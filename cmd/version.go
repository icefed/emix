package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/icefed/emix/version"
)

func newCmdVersion() *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "version",
		DisableFlagsInUseLine: true,
		Short:                 "Print the emix version",
		GroupID:               "additional",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintln(os.Stdout, version.Version)
		},
	}
	return cmd
}
