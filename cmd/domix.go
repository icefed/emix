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
	"golang.org/x/term"

	"github.com/icefed/emix"
)

type DomixOptions struct {
	// read password from stdin if Password is true
	Password       bool
	CredentialFile string
	EmbedPassword  bool
	// 0: standard, no encryption
	// 1: encrypt file info
	// 2: encrypt file info and content
	MixType  int
	KeepName bool
	Output   string
	Excludes []string
	Silence  bool

	source      string
	sourceIsDir bool

	password      [16]byte
	ignoreMatcher *ignore.GitIgnore
}

func newCmdDomix() *cobra.Command {
	o := &DomixOptions{}
	cmd := &cobra.Command{
		Use:     "domix <path>",
		Short:   "do-mix the files of the path.",
		Long:    ``,
		GroupID: "general",
		Args:    cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cobra.CheckErr(o.Validate(args[0]))
			cobra.CheckErr(o.Run())
		},
	}

	cmd.Flags().SortFlags = false
	cmd.Flags().IntVarP(&o.MixType, "type", "t", 0, "Mix type. 0: standard, 1: encrypt file info, 2: encrypt file info and content.")
	cmd.Flags().BoolVarP(&o.KeepName, "keep-name", "k", false, "Keep original name. Default is false.")
	cmd.Flags().BoolVarP(&o.Password, "password", "p", false, "Use password to encrypt, max length is 16 bytes. Conflicts with --credential-file and --embed-password.")
	cmd.Flags().StringVar(&o.CredentialFile, "credential-file", "", "Use a credential file as password. Conflicts with --password and --embed-password.")
	cmd.Flags().BoolVar(&o.EmbedPassword, "embed-password", false, "Embed password to file header, password will be generated. Conflicts with --password and --credential-file.")
	cmd.Flags().StringVarP(&o.Output, "output", "o", "", "Output directory. Default use emix_%datetime(format: 2006-01-02_15-04-05).")
	cmd.Flags().StringSliceVarP(&o.Excludes, "excludes", "e", []string{".*"}, "Exclude files matching PATTERN if <path> is directory, gitignore style. default use `.*` to ignore hidden files. Multi patterns can be separated by comma.")
	cmd.Flags().BoolVar(&o.Silence, "silence", false, "Silence all output.")
	return cmd
}

func (o *DomixOptions) Validate(source string) error {
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
	if (o.Password || o.CredentialFile != "") && o.EmbedPassword {
		return errors.New("can not set both --password, --credential-file and --embed-password")
	}
	if o.MixType > 2 {
		return errors.New("invalid --type, only support 0, 1, 2, see help for details")
	}
	if o.MixType == 0 {
		if o.Password || o.EmbedPassword || o.CredentialFile != "" {
			return errors.New("invalid --type 0, can not set password or embed-password")
		}
	} else {
		if !o.Password && !o.EmbedPassword && o.CredentialFile == "" {
			return errors.New("invalid --type, need password or embed-password or credential-file")
		}
	}
	if o.Password {
		// input password
		password, err := inputPassword()
		if err != nil {
			return err
		}

		// verify password
		if err = inputPasswordAgain(password); err != nil {
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
	if o.EmbedPassword {
		// no nothing
		// will generate a new password for each file
	}
	// check output
	if o.Output == "" {
		o.Output = fmt.Sprintf("emix_%s", time.Now().Format("2006-01-02_15-04-05"))
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

func (o *DomixOptions) Run() error {
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
			return o.EncryptFile(path, info, outDir)
		})
	}

	info, err := os.Stat(o.source)
	if err != nil {
		return err
	}
	return o.EncryptFile(o.source, info, o.Output)
}

func (o *DomixOptions) EncryptFile(src string, srcInfo os.FileInfo, outDir string) error {
	dest := filepath.Join(outDir, time.Now().Format("2006-01-02_15-04-05.000000")+".zip")
	if o.KeepName {
		dest = filepath.Join(outDir, srcInfo.Name())
	}
	if !o.Silence {
		fmt.Fprint(os.Stdout, o.source, " -> ", dest, "\n")
	}
	efi := &emix.FileInfo{
		Name:       srcInfo.Name(),
		Size:       uint64(srcInfo.Size()),
		Mode:       uint32(srcInfo.Mode()),
		CreateTime: uint64(getFileCreateTime(srcInfo).UnixNano()),
		ModifyTime: uint64(srcInfo.ModTime().UnixNano()),
	}
	// header
	emixHeader := &emix.EmixHeader{
		EmbedPassword: o.EmbedPassword,
		FileInfo:      *efi,
	}
	switch o.MixType {
	case 0:
	case 1:
		emixHeader.EncryptInfo = true
	case 2:
		emixHeader.EncryptData = true
	}
	if len(o.password) > 0 {
		copy(emixHeader.Password[:], o.password[:])
	}

	targetFile, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer targetFile.Close()

	f, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("Open source file error: %v", err)
	}
	defer f.Close()

	// hash source file
	hash := sha256.New()
	// use tee reader
	teef := io.TeeReader(f, hash)

	// set file position to target file data
	targetFile.Seek(int64(emix.ZipHeaderLength()+emixHeader.EncodedLength()), io.SeekStart)

	// write file content first
	if emixHeader.EncryptData {
		cipher, err := emix.NewAESXTS(o.password)
		if err != nil {
			return err
		}
		err = emix.EncryptContent(cipher, teef, targetFile)
		if err != nil {
			return fmt.Errorf("Write encrypted file content error: %v", err)
		}
	} else {
		if _, err := io.Copy(targetFile, teef); err != nil {
			return fmt.Errorf("Write file content error: %v", err)
		}
	}

	// reset file position
	targetFile.Seek(0, io.SeekStart)
	// write zip header
	_, err = targetFile.Write(emix.ZipHeader())
	if err != nil {
		return fmt.Errorf("Write zip header error: %v", err)
	}
	// write emix header
	fileHash := hash.Sum(nil)
	copy(emixHeader.FileInfo.FileContentHash[:], fileHash)
	encodedHeader, err := emixHeader.MarshalBinary()
	if err != nil {
		return fmt.Errorf("Encode emix header error: %v", err)
	}
	_, err = targetFile.Write(encodedHeader)
	if err != nil {
		return fmt.Errorf("Write emix header error: %v", err)
	}

	return nil
}

func inputPassword() ([]byte, error) {
	fmt.Fprint(os.Stderr, "Enter password: ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("Read password error: %v", err)
	}
	if len(password) == 0 || len(password) > 16 {
		return nil, errors.New("password length must be between 1 and 16")
	}
	return password, nil
}

func inputPasswordAgain(password []byte) error {
	fmt.Fprint(os.Stderr, "Enter password again: ")
	passwordAgain, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return fmt.Errorf("Read password error: %v", err)
	}
	if !bytes.Equal(password, passwordAgain) {
		return errors.New("password is not same")
	}
	fmt.Fprintln(os.Stderr, "Please keep your password safe, and don't forget it!")
	return nil
}
