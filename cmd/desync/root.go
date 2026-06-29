package main

import (
	"errors"

	"github.com/spf13/cobra"
)

func newRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bitmap-disttool",
		Short: "Bitmap Developer Distribution Tool",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if !requiresAuthentication(cmd) {
				return nil
			}
			if err := ensureAuthenticated(); err != nil {
				return errors.New("you are not logged in. Run 'bitmap-disttool auth login'")
			}
			return nil
		},
	}
	cmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default $HOME/.config/desync/config.json)")
	cmd.PersistentFlags().StringVar(&digestAlgorithm, "digest", "sha512-256", "digest algorithm, sha512-256 or sha256")
	cmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "verbose mode")
	return cmd
}
