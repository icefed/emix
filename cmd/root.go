package main

import (
	"github.com/spf13/cobra"
)

const (
	rootCmdName = "emix"
)

func newRootCommand() *cobra.Command {
	command := &cobra.Command{
		Use: rootCmdName,
	}
	// subcommand group
	command.AddGroup(&cobra.Group{
		ID:    "general",
		Title: "General Commands:",
	}, &cobra.Group{
		ID:    "additional",
		Title: "Additional Commands:",
	})
	command.SetHelpCommandGroupID("additional")
	command.SetCompletionCommandGroupID("additional")

	cobra.EnableCommandSorting = false

	// Top Level Commands
	command.AddCommand(newCmdDomix())
	command.AddCommand(newCmdDemix())

	// Other Commands
	command.AddCommand(newCmdVersion())

	return command
}
