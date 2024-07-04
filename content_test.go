package emix

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/xts"
)

func TestContent(t *testing.T) {
	tests := []struct {
		name      string
		plaintext []byte
	}{
		{
			name:      "0",
			plaintext: nil,
		}, {
			name:      "1k",
			plaintext: make([]byte, 1024),
		}, {
			name:      "4k",
			plaintext: make([]byte, 4096),
		}, {
			name:      "12k",
			plaintext: make([]byte, 12*1024),
		}, {
			name:      "13k",
			plaintext: make([]byte, 13*1024),
		}, {
			name:      "13m",
			plaintext: make([]byte, 13*1024*1024),
		},
	}

	password := make([]byte, 32)
	rand.Read(password)
	cipher, err := xts.NewCipher(aes.NewCipher, password)
	assert.Nil(t, err)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cipherbuffer := bytes.NewBuffer(nil)
			err := EncryptContent(cipher, bytes.NewReader(test.plaintext), cipherbuffer)
			assert.Nil(t, err)

			plainbuffer := bytes.NewBuffer(nil)
			err = DecryptContent(cipher, cipherbuffer, plainbuffer, int64(len(test.plaintext)))
			assert.Nil(t, err)
			assert.EqualValues(t, test.plaintext, plainbuffer.Bytes())
		})
	}
}
