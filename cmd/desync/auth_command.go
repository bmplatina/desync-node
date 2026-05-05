package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/spf13/cobra"
)

func newAuthCommand(ctx context.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Authentication commands",
	}
	cmd.AddCommand(newAuthLoginCommand(ctx), newAuthLogoutCommand())
	return cmd
}

func newAuthLoginCommand(ctx context.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Login with Bitmap ID",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAuthLogin(ctx, cmd)
		},
		SilenceUsage: true,
	}
	return cmd
}

func runAuthLogin(ctx context.Context, cmd *cobra.Command) error {
	fmt.Fprintln(stdout, "Logging in via Bitmap ID")
	in := cmd.InOrStdin()
	reader := bufio.NewReader(in)

	fmt.Fprint(stdout, "Email: ")
	emailRaw, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	email := strings.TrimSpace(emailRaw)
	if email == "" {
		return errors.New("email is required")
	}

	fmt.Fprint(stdout, "Password: ")
	password, err := readPassword(cmd, reader)
	if err != nil {
		return err
	}
	if password == "" {
		return errors.New("password is required")
	}

	token, err := performLogin(ctx, email, password)
	if err != nil {
		return err
	}
	if err := saveAuthToken(token); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "Login successful.")
	return nil
}

func readPassword(cmd *cobra.Command, reader *bufio.Reader) (string, error) {
	in := cmd.InOrStdin()
	if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		b, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(stdout)
		return strings.TrimSpace(string(b)), err
	}
	passwordRaw, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(passwordRaw), nil
}

func newAuthLogoutCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "logout",
		Short: "Logout from Bitmap ID",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := deleteAuthToken(); err != nil {
				return err
			}
			fmt.Fprintln(stdout, "Logged out.")
			return nil
		},
		SilenceUsage: true,
	}
	return cmd
}
