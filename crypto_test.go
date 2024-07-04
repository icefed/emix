package emix

import (
	"bytes"
	"testing"
)

func TestAESGCM(t *testing.T) {
	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	plainText := []byte("hello world")

	cipherText, err := AESGCMEncrypt(plainText, key)
	if err != nil {
		t.Fatal(err)
	}
	plainText2, err := AESGCMDecrypt(cipherText, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plainText, plainText2) {
		t.Fatal("not equal")
	}
}
