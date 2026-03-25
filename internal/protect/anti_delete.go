// 文件路径: internal/protect/anti_delete.go
package protect

import (
	"os"
	"syscall"
)

var globalFileHandle syscall.Handle = syscall.InvalidHandle

// LockFile 独占锁定指定路径的文件
func LockFile(targetPath string) error {
	pathPtr, err := syscall.UTF16PtrFromString(targetPath)
	if err != nil {
		return err
	}

	// 允许读取 (FILE_SHARE_READ)，拒绝其他进程写入和删除
	handle, err := syscall.CreateFile(
		pathPtr,
		syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)

	if err != nil {
		return err
	}

	globalFileHandle = handle
	return nil
}

// LockSelfFile 锁定自身
func LockSelfFile() error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	return LockFile(exePath)
}
