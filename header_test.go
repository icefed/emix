package emix

import (
	"crypto/sha256"
	"testing"
	"time"
)

func TestEmixHeader(t *testing.T) {
	now := time.Now().UnixNano()
	info := FileInfo{
		Name:            "test.txt",
		Size:            1024,
		Mode:            0644,
		CreateTime:      uint64(now),
		ModifyTime:      uint64(now),
		FileContentHash: sha256.Sum256([]byte("test")),
	}

	t.Run("general", func(t *testing.T) {
		header := EmixHeader{
			FileInfo: info,
		}
		buf, err := header.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if len(buf) != header.EncodedLength() {
			t.Fatal("EncodedLength not equal")
		}
		var header2 EmixHeader
		if err := header2.UnmarshalBinary(buf); err != nil {
			t.Fatal(err)
		}
		if header2 != header {
			t.Fatal("not equal")
		}
	})

	t.Run("encrypt", func(t *testing.T) {
		header := EmixHeader{
			EncryptInfo:   true,
			EmbedPassword: true,
			Password:      [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			FileInfo:      info,
		}
		buf, err := header.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if len(buf) != header.EncodedLength() {
			t.Fatal("EncodedLength not equal")
		}
		var header2 EmixHeader
		if err := header2.UnmarshalBinary(buf); err != nil {
			t.Fatal(err)
		}
		if header2 != header {
			t.Fatal("not equal")
		}
	})
}

func TestFileInfo(t *testing.T) {
	now := time.Now().UnixNano()
	info := FileInfo{
		Name:            "test.txt",
		Size:            1024,
		Mode:            0644,
		CreateTime:      uint64(now),
		ModifyTime:      uint64(now),
		FileContentHash: sha256.Sum256([]byte("test")),
	}
	buf, err := info.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var info2 FileInfo
	if err := info2.UnmarshalBinary(buf); err != nil {
		t.Fatal(err)
	}
	if info != info2 {
		t.Fatal("not equal")
	}
}
