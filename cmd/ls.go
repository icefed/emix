package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/icefed/emix"
	"github.com/spf13/cobra"
)

type LsOptions struct {
	// read password from stdin if Password is true
	Password       bool
	CredentialFile string
	LongFormat     bool

	dir      string
	password [16]byte
}

func newCmdLs() *cobra.Command {
	o := &LsOptions{}
	cmd := &cobra.Command{
		Use:     "ls <path>",
		Short:   "list the emix files of the directory",
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
	cmd.Flags().BoolVarP(&o.LongFormat, "long", "l", false, "Use a long listing format.")
	return cmd
}

func (o *LsOptions) Validate(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("path %s is not a directory", dir)
	}
	o.dir = filepath.Clean(dir)

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

func (o *LsOptions) Run() error {
	files, err := os.ReadDir(o.dir)
	if err != nil {
		return err
	}

	emixFilesInfo := make([]*emix.EmixHeader, 0)
	for _, file := range files {
		if !file.Type().IsRegular() {
			continue
		}

		f, err := os.Open(filepath.Join(o.dir, file.Name()))
		if err != nil {
			return err
		}
		defer f.Close()

		ok, err := emix.IsEmixFile(f)
		if err != nil {
			return fmt.Errorf("check %s error: %v", file.Name(), err)
		}
		if !ok {
			continue
		}

		f.Seek(int64(emix.ZipHeaderLength()), io.SeekStart)

		emixHeader := &emix.EmixHeader{}
		copy(emixHeader.Password[:], o.password[:])
		err = emixHeader.UnmarshalBinaryFromReader(f)
		if err != nil {
			return fmt.Errorf("parse %s emix header error: %v", file.Name(), err)
		}
		emixFilesInfo = append(emixFilesInfo, emixHeader)
	}

	// print emix files
	if len(emixFilesInfo) == 0 {
		return nil
	}
	if o.LongFormat {
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		for _, info := range emixFilesInfo {
			fmt.Fprintf(tw, "%s\t%6s\t%s\t%s\n", fs.FileMode(info.FileInfo.Mode),
				strings.ReplaceAll(humanize.Bytes(uint64(info.FileInfo.Size)), " ", ""),
				time.Unix(0, int64(info.FileInfo.ModifyTime)).Format("Jan _2 15:04 MST 2006"),
				info.FileInfo.Name,
			)
		}
		tw.Flush()
	} else {
		names := make([]string, 0, len(emixFilesInfo))
		for _, info := range emixFilesInfo {
			names = append(names, info.FileInfo.Name)
		}
		fmt.Fprintf(os.Stdout, "%s\n", strings.Join(names, "\n"))
	}
	return nil
}
