package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"github.com/zalando/go-keyring"
)

func TestAuthLoginCommand(t *testing.T) {
	oldPost := authPostJSON
	oldSet := keyringSet
	oldOut := stdout
	t.Cleanup(func() {
		authPostJSON = oldPost
		keyringSet = oldSet
		stdout = oldOut
	})

	var (
		service string
		user    string
		token   string
	)
	authPostJSON = func(ctx context.Context, endpoint string, reqBody any, rspBody any) error {
		require.Equal(t, authLoginEndpoint, endpoint)
		req, ok := reqBody.(loginRequest)
		require.True(t, ok)
		require.Equal(t, "tester@example.com", req.Email)
		require.Equal(t, "super-secret", req.Password)
		require.True(t, req.KeepLoggedIn)
		rsp := rspBody.(*loginResponse)
		rsp.Token = "jwt.token.value"
		return nil
	}
	keyringSet = func(svc, usr, value string) error {
		service, user, token = svc, usr, value
		return nil
	}

	var out strings.Builder
	stdout = &out
	cmd := newAuthLoginCommand(context.Background())
	cmd.SetIn(strings.NewReader("tester@example.com\nsuper-secret\n"))
	_, err := cmd.ExecuteC()
	require.NoError(t, err)
	require.Equal(t, authKeyringService, service)
	require.Equal(t, authKeyringUser, user)
	require.Equal(t, "jwt.token.value", token)
	require.Contains(t, out.String(), "Logging in via Bitmap ID")
	require.Contains(t, out.String(), "Email:")
	require.Contains(t, out.String(), "Password:")
}

func TestRootAuthGuardBlocksUnauthenticatedCommands(t *testing.T) {
	oldGet := keyringGet
	oldPath := authTokenPathFunc
	t.Cleanup(func() {
		keyringGet = oldGet
		authTokenPathFunc = oldPath
	})

	keyringGet = func(service, user string) (string, error) {
		return "", keyring.ErrNotFound
	}
	authTokenPathFunc = func() (string, error) {
		return filepath.Join(t.TempDir(), "auth.json"), nil
	}

	root := newRootCommand()
	root.AddCommand(&cobra.Command{
		Use: "dummy",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	})

	root.SetArgs([]string{"dummy"})
	_, err := root.ExecuteC()
	require.Error(t, err)
	require.Contains(t, err.Error(), "desync auth login")
}

func TestEnsureDeveloperRole(t *testing.T) {
	oldGet := keyringGet
	oldNow := authNow
	oldProfile := authGetProfile
	t.Cleanup(func() {
		keyringGet = oldGet
		authNow = oldNow
		authGetProfile = oldProfile
	})

	now := time.Unix(1_700_000_000, 0)
	authNow = func() time.Time { return now }
	token := testJWT(`{"email":"dev@example.com","isDeveloper":1,"exp":1700003600}`)
	keyringGet = func(service, user string) (string, error) {
		return token, nil
	}
	authGetProfile = func(ctx context.Context, endpoint, bearerToken string, rspBody any) error {
		require.Equal(t, authProfileEndpoint, endpoint)
		require.Equal(t, token, bearerToken)
		profile := rspBody.(*profileResponse)
		profile.IsDeveloper = 1
		return nil
	}

	require.NoError(t, ensureDeveloperRole(context.Background()))
}

func TestEnsureDeveloperRoleDenied(t *testing.T) {
	oldGet := keyringGet
	oldNow := authNow
	oldProfile := authGetProfile
	t.Cleanup(func() {
		keyringGet = oldGet
		authNow = oldNow
		authGetProfile = oldProfile
	})

	now := time.Unix(1_700_000_000, 0)
	authNow = func() time.Time { return now }
	token := testJWT(`{"email":"user@example.com","isDeveloper":0,"exp":1700003600}`)
	keyringGet = func(service, user string) (string, error) {
		return token, nil
	}
	authGetProfile = func(ctx context.Context, endpoint, bearerToken string, rspBody any) error {
		profile := rspBody.(*profileResponse)
		profile.IsDeveloper = 0
		return nil
	}

	err := ensureDeveloperRole(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "developer")
}

func TestSaveAuthTokenFallbackToFile(t *testing.T) {
	oldSet := keyringSet
	oldPath := authTokenPathFunc
	t.Cleanup(func() {
		keyringSet = oldSet
		authTokenPathFunc = oldPath
	})

	tokenPath := filepath.Join(t.TempDir(), "auth.json")
	authTokenPathFunc = func() (string, error) {
		return tokenPath, nil
	}
	keyringSet = func(service, user, value string) error {
		return errors.New("keychain unavailable")
	}

	err := saveAuthToken("fallback-token")
	require.NoError(t, err)

	oldGet := keyringGet
	t.Cleanup(func() {
		keyringGet = oldGet
	})
	keyringGet = func(service, user string) (string, error) {
		return "", keyring.ErrNotFound
	}

	token, err := loadAuthToken()
	require.NoError(t, err)
	require.Equal(t, "fallback-token", token)
}

func testJWT(payload string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	body := base64.RawURLEncoding.EncodeToString([]byte(payload))
	return header + "." + body + "."
}

func TestReadPasswordFromNonTTY(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetIn(strings.NewReader("pw-value\n"))
	pwd, err := readPassword(cmd, bufio.NewReader(cmd.InOrStdin()))
	require.NoError(t, err)
	require.Equal(t, "pw-value", pwd)
}

func TestAuthLogoutCommand(t *testing.T) {
	oldDelete := keyringDelete
	oldPath := authTokenPathFunc
	oldOut := stdout
	t.Cleanup(func() {
		keyringDelete = oldDelete
		authTokenPathFunc = oldPath
		stdout = oldOut
	})

	tokenPath := filepath.Join(t.TempDir(), "auth.json")
	authTokenPathFunc = func() (string, error) {
		return tokenPath, nil
	}
	require.NoError(t, os.WriteFile(tokenPath, []byte(`{"token":"x"}`), 0600))

	keyringDelete = func(service, user string) error {
		require.Equal(t, authKeyringService, service)
		require.Equal(t, authKeyringUser, user)
		return nil
	}

	var out strings.Builder
	stdout = &out
	cmd := newAuthLogoutCommand()
	_, err := cmd.ExecuteC()
	require.NoError(t, err)
	_, statErr := os.Stat(tokenPath)
	require.Error(t, statErr)
	require.True(t, os.IsNotExist(statErr))
	require.Contains(t, out.String(), "Logged out.")
}
