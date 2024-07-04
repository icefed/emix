package emix

import (
	"errors"
	"io"

	"golang.org/x/crypto/xts"
)

const (
	// 4K
	XTSSectorSize = 1024 * 4

	// SectorNumberStart as sector number for AES-XTS
	SectorNumberStart = 1024
)

// EncryptContent encrypt file content using AES-XTS, read data from reader and write cipher data to writer
func EncryptContent(cipher *xts.Cipher, reader io.Reader, writer io.Writer) error {
	plainBuf := make([]byte, XTSSectorSize)
	cipherBuf := make([]byte, XTSSectorSize)
	sectorNumber := uint64(SectorNumberStart)
	for {
		n, err := reader.Read(plainBuf)
		if n > 0 {
			cipher.Encrypt(cipherBuf, plainBuf, sectorNumber)
			_, e := writer.Write(cipherBuf)
			if e != nil {
				return e
			}
			sectorNumber++
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
	}
	return nil
}

// EncryptContent decrypt file content using AES-XTS, read cipher data from reader and write plain data to writer
func DecryptContent(cipher *xts.Cipher, reader io.Reader, writer io.Writer, size int64) error {
	plainBuf := make([]byte, XTSSectorSize)
	cipherBuf := make([]byte, XTSSectorSize)
	sectorNumber := uint64(SectorNumberStart)
	for leftSize := size; leftSize > 0; leftSize = leftSize - XTSSectorSize {
		n, err := reader.Read(cipherBuf)
		if n > 0 && n < XTSSectorSize {
			return ErrInvalidEmixFileContent
		}
		if n == XTSSectorSize {
			cipher.Decrypt(plainBuf, cipherBuf, sectorNumber)
			_, e := writer.Write(plainBuf[:min(XTSSectorSize, leftSize)])
			if e != nil {
				return e
			}
			sectorNumber++
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
	}
	return nil
}
