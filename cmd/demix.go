package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	ignore "github.com/sabhiram/go-gitignore"
	"github.com/spf13/cobra"

	"github.com/icefed/emix"
)

type DemixOptions struct {
	// read password from stdin if Password is true
	Password       bool
	CredentialFile string
	Output         string
	Excludes       []string
	Silence        bool

	source      string
	sourceIsDir bool

	password      [16]byte
	ignoreMatcher *ignore.GitIgnore
}

func newCmdDemix() *cobra.Command {
	o := &DemixOptions{}
	cmd := &cobra.Command{
		Use:     "demix <path>",
		Short:   "de-mix the files of the path.",
		Long:    ``,
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
	cmd.Flags().StringVarP(&o.Output, "output", "o", "", "Output directory, default is emix_%datetime(format: 2006-01-02 15.04.05).")
	cmd.Flags().StringSliceVarP(&o.Excludes, "excludes", "e", []string{".*"}, "Exclude files matching PATTERN if <path> is directory, gitignore style. default use `.*` to ignore hidden files. Multi patterns can be separated by comma.")
	cmd.Flags().BoolVar(&o.Silence, "silence", false, "Silence all output")
	return cmd
}

func (o *DemixOptions) Validate(source string) error {
	info, err := os.Stat(source)
	if err != nil {
		return err
	}
	o.source = filepath.Clean(source)
	if info.IsDir() {
		o.sourceIsDir = true
	}

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
	// check output
	if o.Output == "" {
		o.Output = fmt.Sprintf("emix_%s", time.Now().Format("2006-01-02 15.04.05"))
	}
	o.Output = filepath.Clean(o.Output)
	outDirStat, err := os.Stat(o.Output)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		// create output directory
		if err = os.MkdirAll(o.Output, 0755); err != nil {
			return fmt.Errorf("create output directory error: %v", err)
		}
	} else if !outDirStat.Mode().IsDir() {
		return fmt.Errorf("output should be a directory")
	}

	// ignore
	if len(o.Excludes) != 0 {
		o.ignoreMatcher = ignore.CompileIgnoreLines(o.Excludes...)
	}
	return nil
}

func (o *DemixOptions) Run() error {
	if o.sourceIsDir {
		return filepath.Walk(o.source, func(path string, info fs.FileInfo, err error) error {
			if err != nil {
				return err
			}
			// check exclude pattern
			if o.ignoreMatcher != nil && o.ignoreMatcher.MatchesPath(path) {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			// skip directory path
			if info.IsDir() {
				return nil
			}
			// nonsupport file type: symlink, device...
			if !info.Mode().IsRegular() {
				return fmt.Errorf("not a regular file: %v", info.Name())
			}
			// output
			outDir := filepath.Join(o.Output, strings.TrimPrefix(filepath.Dir(path), o.source))
			err = os.MkdirAll(outDir, 0755)
			if err != nil {
				return err
			}
			return o.DecryptFile(path, outDir)
		})
	}

	return o.DecryptFile(o.source, o.Output)
}

func (o *DemixOptions) DecryptFile(src string, outDir string) error {
	f, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("Open source file error: %v", err)
	}
	defer f.Close()

	ok, err := emix.IsEmixFile((f))
	if err != nil {
		return err
	}
	if !ok {
		fmt.Fprintf(os.Stderr, fmt.Sprintf("Ignore invalid emix file %s\n", src))
		return nil
	}

	// unmarshal header
	emixHeader := &emix.EmixHeader{
		Password: o.password,
	}
	f.Seek(int64(emix.ZipHeaderLength()), io.SeekStart)
	err = emixHeader.UnmarshalBinaryFromReader(f)
	if err != nil {
		if errors.Is(err, emix.ErrInvalidEmixHeader) {
			fmt.Fprintf(os.Stderr, fmt.Sprintf("Ignore invalid emix file %s\n", src))
			return nil
		}
		return err
	}

	dest := filepath.Join(outDir, emixHeader.FileInfo.Name)
	if !o.Silence {
		fmt.Fprint(os.Stdout, o.source, " -> ", dest, "\n")
	}
	targetFile, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer targetFile.Close()

	// hash file
	hash := sha256.New()
	mf := io.MultiWriter(targetFile, hash)

	// reset file position
	f.Seek(int64(emix.ZipHeaderLength()+emixHeader.EncodedLength()), io.SeekStart)

	// write file content
	if emixHeader.EncryptData {
		cipher, err := emix.NewAESXTS(o.password)
		if err != nil {
			return err
		}
		err = emix.DecryptContent(cipher, f, mf, int64(emixHeader.FileInfo.Size))
		if err != nil {
			return fmt.Errorf("Write decrypted file content error: %v", err)
		}
	} else {
		if _, err := io.Copy(mf, f); err != nil {
			return fmt.Errorf("Write file content error: %v", err)
		}
	}
	fileHash := hash.Sum(nil)

	if !bytes.Equal(emixHeader.FileInfo.FileContentHash[:], fileHash) {
		return fmt.Errorf("File content hash mismatch")
	}
	return nil
}
