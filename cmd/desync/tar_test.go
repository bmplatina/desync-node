//go:build !windows
// +build !windows

package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTarCommandArchive(t *testing.T) {
	oldGet := keyringGet
	oldNow := authNow
	oldProfile := authGetProfile
	t.Cleanup(func() {
		keyringGet = oldGet
		authNow = oldNow
		authGetProfile = oldProfile
	})
	authNow = func() time.Time { return time.Unix(1_700_000_000, 0) }
	token := testJWT(`{"email":"dev@example.com","isDeveloper":1,"exp":1700003600}`)
	keyringGet = func(service, user string) (string, error) {
		return token, nil
	}
	authGetProfile = func(ctx context.Context, endpoint, bearerToken string, rspBody any) error {
		profile := rspBody.(*profileResponse)
		profile.IsDeveloper = 1
		return nil
	}

	// Create an output dir
	out := t.TempDir()
	archive := filepath.Join(out, "tree.catar")

	// Run "tar" command to build the catar archive
	cmd := newTarCommand(context.Background())
	cmd.SetArgs([]string{archive, "testdata/tree"})
	_, err := cmd.ExecuteC()
	require.NoError(t, err)
}

func TestTarCommandIndex(t *testing.T) {
	oldGet := keyringGet
	oldNow := authNow
	oldProfile := authGetProfile
	t.Cleanup(func() {
		keyringGet = oldGet
		authNow = oldNow
		authGetProfile = oldProfile
	})
	authNow = func() time.Time { return time.Unix(1_700_000_000, 0) }
	token := testJWT(`{"email":"dev@example.com","isDeveloper":1,"exp":1700003600}`)
	keyringGet = func(service, user string) (string, error) {
		return token, nil
	}
	authGetProfile = func(ctx context.Context, endpoint, bearerToken string, rspBody any) error {
		profile := rspBody.(*profileResponse)
		profile.IsDeveloper = 1
		return nil
	}

	// Create an output dir to function as chunk store and to hold the caidx
	out := t.TempDir()
	index := filepath.Join(out, "tree.caidx")

	// Run "tar" command to build a caidx index and store the chunks
	cmd := newTarCommand(context.Background())
	cmd.SetArgs([]string{"-s", out, "-i", index, "testdata/tree"})
	_, err := cmd.ExecuteC()
	require.NoError(t, err)
}
