//go:build darwin

package main

import (
	"io/fs"
	"syscall"
	"time"
)

func getFileCreateTime(fileinfo fs.FileInfo) time.Time {
	if stat, ok := fileinfo.Sys().(*syscall.Stat_t); ok {
		return time.Unix(int64(stat.Ctimespec.Sec), int64(stat.Ctimespec.Nsec))
	}
	return fileinfo.ModTime()
}
