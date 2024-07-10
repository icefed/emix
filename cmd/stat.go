package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/icefed/emix"
	"github.com/spf13/cobra"
)

type StatOptions struct {
	// read password from stdin if Password is true
	Password       bool
	CredentialFile string

	emixFilePath string
	password     [16]byte
}

func newCmdStat() *cobra.Command {
	o := &StatOptions{}
	cmd := &cobra.Command{
		Use:     "stat <path>",
		Short:   "stat the emix file",
		GroupID: "general",
		Args:    cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cobra.CheckErr(o.Validate(args[0]))
			cobra.CheckErr(o.Run())
		},
	}
	cmd.Flags().SortFlags = false
	cmd.Flags().BoolVarP(&o.Password, "password", "p", false, "Use password to decrypt, max length is 16 bytes. Conflicts with --credential-file.")
	cmd.Flags().StringVar(&o.CredentialFile, "credential-file", "", "Use a credential file as password. Conflicts with --password.")
	return cmd
}

func (o *StatOptions) Validate(emixFilePath string) error {
	info, err := os.Stat(emixFilePath)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("path %s is not a regular file", emixFilePath)
	}
	o.emixFilePath = filepath.Clean(emixFilePath)

	if o.Password && o.CredentialFile != "" {
		return errors.New("can not set both --password and --credential-file")
	}
	if o.Password {
		// input password
		password, err := inputPassword()
		if err != nil {
			return err
		}

		copy(o.password[:], password)
	}
	if o.CredentialFile != "" {
		password, err := emix.GeneratePasswordFromFile(o.CredentialFile)
		if err != nil {
			return err
		}
		copy(o.password[:], password)
	}

	return nil
}

func (o *StatOptions) Run() error {
	f, err := os.Open(o.emixFilePath)
	if err != nil {
		return err
	}
	defer f.Close()

	ok, err := emix.IsEmixFile(f)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("not emix file")
	}

	f.Seek(int64(emix.ZipHeaderLength()), io.SeekStart)

	emixHeader := &emix.EmixHeader{}
	copy(emixHeader.Password[:], o.password[:])
	err = emixHeader.UnmarshalBinaryFromReader(f)
	if err != nil {
		return err
	}

	// print info as table
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.TabIndent)
	fmt.Fprintf(tw, "%11s:\t%s\n", "Name", emixHeader.FileInfo.Name)
	fmt.Fprintf(tw, "%11s:\t%s (%d)\n", "Size", humanize.Bytes(emixHeader.FileInfo.Size), emixHeader.FileInfo.Size)
	fmt.Fprintf(tw, "%11s:\t%s\n", "Mode", fs.FileMode(emixHeader.FileInfo.Mode))
	fmt.Fprintf(tw, "%11s:\t%s\n", "Create Time", time.Unix(0, int64(emixHeader.FileInfo.CreateTime)))
	fmt.Fprintf(tw, "%11s:\t%s\n", "Modify Time", time.Unix(0, int64(emixHeader.FileInfo.ModifyTime)))
	fmt.Fprintf(tw, "%11s:\t%s\n", "SHA256", fmt.Sprintf("%x", emixHeader.FileInfo.FileContentHash))
	tw.Flush()

	return nil
}
