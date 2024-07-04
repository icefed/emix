//go:build linux

package main

import (
	"io/fs"
	"syscall"
	"time"
)

func getFileCreateTime(fileinfo fs.FileInfo) time.Time {
	if stat, ok := fileinfo.Sys().(*syscall.Stat_t); ok {
		return time.Unix(int64(stat.Ctim.Sec), int64(stat.Ctim.Nsec))
	}
	return fileinfo.ModTime()
}
