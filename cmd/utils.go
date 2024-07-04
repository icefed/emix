//go:build !linux && !darwin

package main

import (
	"io/fs"
	"time"
)

func getFileCreateTime(fileinfo fs.FileInfo) time.Time {
	return fileinfo.ModTime()
}
