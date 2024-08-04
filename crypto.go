package emix

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/xts"
)

// use aes-256-gcm
func NewAESGCM(key [16]byte) (cipher.AEAD, error) {
	ekey := HKDF(key[:], nil, []byte("aesgem key"), 32)
	block, err := aes.NewCipher(ekey)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aesgcm, nil
}

func AESGCMEncrypt(plainText []byte, key [16]byte) ([]byte, error) {
	aesgcm, err := NewAESGCM(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	cipherText := aesgcm.Seal(nil, nonce, plainText, nil)
	return append(nonce, cipherText...), nil
}

func AESGCMDecrypt(cipherText []byte, key [16]byte) ([]byte, error) {
	aesgcm, err := NewAESGCM(key)
	if err != nil {
		return nil, err
	}

	nonceSize := aesgcm.NonceSize()
	if len(cipherText) < nonceSize {
		return nil, fmt.Errorf("cipherText too short")
	}
	nonce := cipherText[:nonceSize]
	cipherText = cipherText[nonceSize:]
	return aesgcm.Open(nil, nonce, cipherText, nil)
}

// NewAESXTS returns an xts.Cipher
func NewAESXTS(key [16]byte) (*xts.Cipher, error) {
	hkdfKey := HKDF(key[:], nil, []byte("aesxts key"), 32)
	return xts.NewCipher(aes.NewCipher, hkdfKey)
}

func HKDF(secret []byte, salt []byte, info []byte, length int) []byte {
	hkdfReader := hkdf.New(sha256.New, secret, salt, info)
	out := make([]byte, length)
	hkdfReader.Read(out)
	return out
}

// GeneratePasswordFromFile use a credential file to generate password
// return 16-byte password
func GeneratePasswordFromFile(filePath string) ([]byte, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("Open credential file error: %v", err)
	}
	defer f.Close()

	// hash file
	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return nil, fmt.Errorf("Read credential file error: %v", err)
	}
	fileHash := hash.Sum(nil)

	// use file hash as hkdf secret to generate password
	password := HKDF(fileHash, nil, []byte("credential file"), 16)
	return password, nil
}

// GenerateRandomPassword generate random length-byte password
func GenerateRandomPassword(length int) ([]byte, error) {
	password := make([]byte, length)
	_, err := rand.Read(password)
	if err != nil {
		return nil, fmt.Errorf("Generate password error: %v", err)
	}
	return password, nil
}
