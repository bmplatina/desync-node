package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/zalando/go-keyring"
)

const (
	authLoginEndpoint   = "https://api.prodbybitmap.com/auth/login"
	authProfileEndpoint = "https://api.prodbybitmap.com/auth/profile"
	authKeyringService  = "bitmap-disttool"
	authKeyringUser     = "jwt"
	authTokenEnvVar     = "BITMAP_AUTH_TOKEN"
)

var (
	authNow           = time.Now
	authPostJSON      = postAuthJSON
	authGetProfile    = getAuthProfile
	keyringSet        = keyring.Set
	keyringGet        = keyring.Get
	keyringDelete     = keyring.Delete
	authTokenPathFunc = defaultAuthTokenPath
)

type authClaims struct {
	UID             any    `json:"uid"`
	Email           string `json:"email"`
	Username        string `json:"username"`
	IsAdmin         any    `json:"isAdmin"`
	IsDeveloper     any    `json:"isDeveloper"`
	IsTeammate      any    `json:"isTeammate"`
	AvatarURI       string `json:"avatarUri"`
	IsEmailVerified any    `json:"isEmailVerified"`
	Exp             int64  `json:"exp"`
}

type loginRequest struct {
	Email        string `json:"email"`
	Password     string `json:"password"`
	KeepLoggedIn bool   `json:"bKeepLoggedIn"`
}

type loginResponse struct {
	Token string `json:"token"`
}

type profileResponse struct {
	IsDeveloper any `json:"isDeveloper"`
}

type tokenFile struct {
	Token string `json:"token"`
}

func requiresAuthentication(cmd *cobra.Command) bool {
	if cmd == nil {
		return false
	}
	if cmd == cmd.Root() || cmd.Name() == "help" {
		return false
	}
	if cmd.Parent() != nil && cmd.Parent().Name() == "auth" {
		return false
	}
	return true
}

func ensureAuthenticated() error {
	_, err := getValidClaims()
	return err
}

func ensureDeveloperRole(ctx context.Context) error {
	token, err := loadAuthToken()
	if err != nil {
		return err
	}
	claims, err := parseClaims(token)
	if err != nil {
		return err
	}
	if claims.Exp <= 0 {
		return errors.New("token is missing exp claim")
	}
	if authNow().Unix() >= claims.Exp {
		return errors.New("token has expired")
	}
	var profile profileResponse
	if err := authGetProfile(ctx, authProfileEndpoint, token, &profile); err != nil {
		return err
	}
	if !boolish(profile.IsDeveloper) {
		return errors.New("desync tar requires a developer account")
	}
	return nil
}

func getValidClaims() (*authClaims, error) {
	token, err := loadAuthToken()
	if err != nil {
		return nil, err
	}
	claims, err := parseClaims(token)
	if err != nil {
		return nil, err
	}
	if claims.Exp <= 0 {
		return nil, errors.New("token is missing exp claim")
	}
	if authNow().Unix() >= claims.Exp {
		return nil, errors.New("token has expired")
	}
	return claims, nil
}

func parseClaims(token string) (*authClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid JWT payload: %w", err)
	}
	var claims authClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("invalid JWT claims: %w", err)
	}
	return &claims, nil
}

func performLogin(ctx context.Context, email, password string) (string, error) {
	reqBody := loginRequest{
		Email:        email,
		Password:     password,
		KeepLoggedIn: true,
	}
	var rsp loginResponse
	if err := authPostJSON(ctx, authLoginEndpoint, reqBody, &rsp); err != nil {
		return "", err
	}
	if strings.TrimSpace(rsp.Token) == "" {
		return "", errors.New("login response did not include token")
	}
	return rsp.Token, nil
}

func postAuthJSON(ctx context.Context, endpoint string, reqBody any, rspBody any) error {
	b, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	rsp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer rsp.Body.Close()

	body, err := io.ReadAll(rsp.Body)
	if err != nil {
		return err
	}
	if rsp.StatusCode != http.StatusOK {
		return fmt.Errorf("login failed: HTTP %d: %s", rsp.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := json.Unmarshal(body, rspBody); err != nil {
		return err
	}
	return nil
}

func getAuthProfile(ctx context.Context, endpoint, token string, rspBody any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 30 * time.Second}
	rsp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer rsp.Body.Close()

	body, err := io.ReadAll(rsp.Body)
	if err != nil {
		return err
	}
	if rsp.StatusCode != http.StatusOK {
		return fmt.Errorf("profile lookup failed: HTTP %d: %s", rsp.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := json.Unmarshal(body, rspBody); err != nil {
		return err
	}
	return nil
}

func saveAuthToken(token string) error {
	if err := keyringSet(authKeyringService, authKeyringUser, token); err == nil {
		return nil
	}
	return saveAuthTokenFile(token)
}

func loadAuthToken() (string, error) {
	envToken := strings.TrimSpace(os.Getenv(authTokenEnvVar))
	if envToken != "" {
		return envToken, nil
	}

	token, err := keyringGet(authKeyringService, authKeyringUser)
	if err == nil && strings.TrimSpace(token) != "" {
		return token, nil
	}
	if err != nil && !errors.Is(err, keyring.ErrNotFound) {
		// Keep trying fallback storage.
	}
	return loadAuthTokenFile()
}

func deleteAuthToken() error {
	keyringErr := keyringDelete(authKeyringService, authKeyringUser)
	if errors.Is(keyringErr, keyring.ErrNotFound) {
		keyringErr = nil
	}

	fileErr := deleteAuthTokenFile()
	if os.IsNotExist(fileErr) {
		fileErr = nil
	}

	if keyringErr != nil && fileErr != nil {
		return fmt.Errorf("failed to delete token from keychain and fallback file: %v; %v", keyringErr, fileErr)
	}
	if keyringErr != nil {
		return keyringErr
	}
	if fileErr != nil {
		return fileErr
	}
	return nil
}

func defaultAuthTokenPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "desync", "auth.json"), nil
}

func saveAuthTokenFile(token string) error {
	path, err := authTokenPathFunc()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	b, err := json.Marshal(tokenFile{Token: token})
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0600)
}

func loadAuthTokenFile() (string, error) {
	path, err := authTokenPathFunc()
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var tf tokenFile
	if err := json.Unmarshal(b, &tf); err != nil {
		return "", err
	}
	if strings.TrimSpace(tf.Token) == "" {
		return "", errors.New("stored auth token is empty")
	}
	return tf.Token, nil
}

func deleteAuthTokenFile() error {
	path, err := authTokenPathFunc()
	if err != nil {
		return err
	}
	return os.Remove(path)
}

func boolish(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case float64:
		return t == 1
	case int:
		return t == 1
	case int64:
		return t == 1
	case json.Number:
		i, err := t.Int64()
		return err == nil && i == 1
	default:
		return false
	}
}
