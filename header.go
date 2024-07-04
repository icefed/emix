package emix

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
)

// emix file structure
// [zip header] [emix header] [file content]

var (
	zipHeaderMagic  = [4]byte{0x50, 0x4b, 0x03, 0x04}
	zipHeaderLength = 64

	emixHeaderMagic              = [4]byte{0x45, 0x4d, 0x49, 0x58} // EMIX
	emixHeaderMixTypeStandard    = [2]byte{0x00, 0x00}
	emixHeaderMixTypeEncryptInfo = [2]byte{0x00, 0x01}
	emixHeaderMixTypeEncryptData = [2]byte{0x00, 0x02}
	// embed password mask use mix type first byte
	emixHeaderEmbedPasswordMask = byte(0x01)

	// [4-byte magic] [16-byte random] [2-byte mix type] [16-byte password]
	// [2-byte file info length] [bytes min file info] [32-byte hash]
	emixHeaderMinLength = 4 + 16 + 2 + 16 + 2 + fileInfoEncodedMinLength + 32
	// [4-byte magic] [16-byte random] [2-byte mix type] [16-byte password]
	// [2-byte file info length] [bytes max encrypted file info] [32-byte hash]
	// encrypted file info add 28 bytes
	emixHeaderMaxLength = 4 + 16 + 2 + 16 + 2 + fileInfoEncodedMaxLength + 28 + 32

	fileNameMinLength = 1
	fileNameMaxLength = 255
	// [2-byte file name length] [file name] [8-byte file size] [4-byte mode]
	// [8-byte create time] [8-byte modify time] [32-byte file content hash]
	fileInfoEncodedMinLength = 2 + fileNameMinLength + 8 + 4 + 8 + 8 + 32
	fileInfoEncodedMaxLength = 2 + fileNameMaxLength + 8 + 4 + 8 + 8 + 32

	/// errors
	ErrNameTooShort           = errors.New("name too short")
	ErrNameTooLong            = errors.New("name too long")
	ErrInvalidEmixHeader      = errors.New("invalid emix header")
	ErrInvalidEmixFileContent = errors.New("invalid emix file content")
	ErrInvalidEncodedFileInfo = errors.New("invalid file info")
)

// ZipHeader return zip header
func ZipHeader() []byte {
	return append(zipHeaderMagic[:], make([]byte, zipHeaderLength-4)...)
}

// ZipHeaderLength return zip header length
func ZipHeaderLength() int {
	return zipHeaderLength
}

type EmixHeader struct {
	EncryptInfo bool
	EncryptData bool
	// EmbedPassword must only use auto generated 16-byte password
	EmbedPassword bool
	Password      [16]byte
	FileInfo      FileInfo

	// raw data
	// magic          [4]byte
	// random         [16]byte
	// mixType        [2]byte
	// password       [16]byte
	// fileInfoLength [2]byte
	// fileInfo       []byte
	// hash           [32]byte
}

func (e *EmixHeader) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 0, emixHeaderMaxLength)
	// add magic
	buf = append(buf, emixHeaderMagic[:]...)
	// add random bytes
	random := make([]byte, 16)
	rand.Read(random)
	buf = append(buf, random...)
	// add mix type
	mixType := [2]byte{}
	if e.EncryptInfo {
		mixType[1] = mixType[1] | emixHeaderMixTypeEncryptInfo[1]
	}
	if e.EncryptData {
		mixType[1] = mixType[1] | emixHeaderMixTypeEncryptData[1]
	}
	if e.EmbedPassword {
		mixType[0] = emixHeaderEmbedPasswordMask
		buf = append(buf, mixType[:]...)
		buf = append(buf, e.Password[:]...)
	} else {
		buf = append(buf, mixType[:]...)
		buf = append(buf, make([]byte, 16)...)
	}

	// marshal fileinfo
	encodedFileInfo, err := e.FileInfo.MarshalBinary()
	if err != nil {
		return nil, err
	}
	// encrypt fileinfo if needed
	if e.EncryptInfo {
		cipherFileInfo, err := AESGCMEncrypt(encodedFileInfo, e.Password)
		if err != nil {
			return nil, err
		}
		encodedFileInfo = cipherFileInfo
	}
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(encodedFileInfo)))
	buf = append(buf, encodedFileInfo...)

	// hash
	hash := sha256.Sum256(buf)
	buf = append(buf, hash[:]...)

	return buf, nil
}

func (e *EmixHeader) UnmarshalBinary(data []byte) error {
	if len(data) < emixHeaderMinLength {
		return ErrInvalidEmixHeader
	}
	return e.UnmarshalBinaryFromReader(bytes.NewReader(data))
}

func (e *EmixHeader) UnmarshalBinaryFromReader(r io.Reader) error {
	buf := make([]byte, emixHeaderMaxLength)
	n, err := io.ReadAtLeast(r, buf, emixHeaderMinLength)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return err
	}
	if n < emixHeaderMinLength {
		return ErrInvalidEmixHeader
	}
	buf = buf[:n]

	// magic
	i := 0
	if !bytes.Equal(buf[i:4], emixHeaderMagic[:]) {
		return ErrInvalidEmixHeader
	}
	// random bytes
	i += 4
	// mix type
	i += 16
	mixType := buf[i : i+2]
	e.EncryptInfo = (mixType[1] & emixHeaderMixTypeEncryptInfo[1]) > 0
	e.EncryptData = (mixType[1] & emixHeaderMixTypeEncryptData[1]) > 0
	e.EmbedPassword = (mixType[0] & emixHeaderEmbedPasswordMask) > 0
	// password
	i += 2
	if e.EmbedPassword {
		copy(e.Password[:], buf[i:i+16])
	}

	// file info
	i += 16
	encodedFileInfoLength := int(binary.BigEndian.Uint16(buf[i : i+2]))
	i += 2
	if len(buf) < i+encodedFileInfoLength+32 {
		return ErrInvalidEmixHeader
	}
	encodedFileInfo := buf[i : i+encodedFileInfoLength]
	if e.EncryptInfo {
		decodedFileInfo, err := AESGCMDecrypt(encodedFileInfo, e.Password)
		if err != nil {
			return err
		}
		encodedFileInfo = decodedFileInfo
	}
	fileInfo := &FileInfo{}
	if err := fileInfo.UnmarshalBinary(encodedFileInfo); err != nil {
		return err
	}
	e.FileInfo = *fileInfo

	// hash
	i += encodedFileInfoLength
	hash := buf[i : i+32]
	headerHash := sha256.Sum256(buf[:i])

	// check hash
	if !bytes.Equal(hash, headerHash[:]) {
		return ErrInvalidEmixHeader
	}
	return nil
}

// EncodedLength return EmixHeader encoded length
func (e *EmixHeader) EncodedLength() int {
	length := 4 + 16 + 2 + 16 + 2 + e.FileInfo.EncodedLength() + 32
	if e.EncryptInfo {
		length += 28
	}
	return length
}

type FileInfo struct {
	Name            string
	Size            uint64
	Mode            uint32
	CreateTime      uint64
	ModifyTime      uint64
	FileContentHash [32]byte

	// raw data
	// nameLength      [2]byte
	// name            []byte
	// size            [8]byte
	// mode            [4]byte
	// createTime      [8]byte
	// modifyTime      [8]byte
	// fileContentHash [32]byte
}

// EncodedLength measure encoded length
func (f *FileInfo) EncodedLength() int {
	return fileInfoEncodedMinLength + len(f.Name) - fileNameMinLength
}

// MarshalBinary serialize FileInfo
// format: namelength + name + size + mode + create time + modify time
// namelength use 2 bytes
func (f *FileInfo) MarshalBinary() ([]byte, error) {
	if len(f.Name) < fileNameMinLength {
		return nil, ErrNameTooShort
	}
	if len(f.Name) > fileNameMaxLength {
		return nil, ErrNameTooLong
	}

	buf := make([]byte, 0, f.EncodedLength())
	// name length
	buf = binary.LittleEndian.AppendUint16(buf, uint16(len(f.Name)))
	buf = append(buf, []byte(f.Name)...)
	buf = binary.LittleEndian.AppendUint64(buf, uint64(f.Size))
	buf = binary.LittleEndian.AppendUint32(buf, f.Mode)
	buf = binary.LittleEndian.AppendUint64(buf, f.CreateTime)
	buf = binary.LittleEndian.AppendUint64(buf, f.ModifyTime)
	buf = append(buf, f.FileContentHash[:]...)
	return buf, nil
}

// UnmarshalBinary deserialize FileInfo
func (f *FileInfo) UnmarshalBinary(data []byte) error {
	if len(data) < fileInfoEncodedMinLength {
		return ErrInvalidEncodedFileInfo
	}

	// name length
	i := 0
	fileNameLength := binary.LittleEndian.Uint16(data[i:2])
	if int(fileNameLength) < fileNameMinLength || int(fileNameLength) > fileNameMaxLength {
		return ErrInvalidEncodedFileInfo
	}
	// name
	i += 2
	f.Name = string(data[i : i+int(fileNameLength)])
	i += int(fileNameLength)
	f.Size = binary.LittleEndian.Uint64(data[i : i+8])
	// mode
	i += 8
	f.Mode = binary.LittleEndian.Uint32(data[i : i+4])
	// create time
	i += 4
	f.CreateTime = binary.LittleEndian.Uint64(data[i : i+8])
	// modify time
	i += 8
	f.ModifyTime = binary.LittleEndian.Uint64(data[i : i+8])
	// file content hash
	i += 8
	copy(f.FileContentHash[:], data[i:i+32])

	return nil
}

// IsEmixFileByData check if the data is emix file
func IsEmixFileByData(data []byte) (bool, error) {
	return IsEmixFile(bytes.NewReader(data))
}

// IsEmixFileByPath check if the path is emix file
func IsEmixFileByPath(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	return IsEmixFile(f)
}

// IsEmixFile check if the file is emix file
func IsEmixFile(r io.Reader) (bool, error) {
	buf := make([]byte, zipHeaderLength+emixHeaderMinLength)
	n, err := io.ReadFull(r, buf)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return false, err
	}
	if n < zipHeaderLength+emixHeaderMinLength {
		return false, nil
	}

	// check zip header
	if !bytes.Equal(buf[:4], zipHeaderMagic[:]) {
		return false, nil
	}
	if !bytes.Equal(buf[4:64], make([]byte, 60)) {
		return false, nil
	}

	// check emix header
	if !bytes.Equal(buf[64:68], emixHeaderMagic[:]) {
		return false, nil
	}

	return true, nil
}
