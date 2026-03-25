// 文件路径: internal/protect/anti_delete.go
package protect

import (
	"os"
	"sync"
	"syscall"
)

var (
	lockedHandles []syscall.Handle
	lockMu        sync.Mutex
)

// LockFile 独占锁定指定路径的文件
func LockFile(targetPath string) error {
	pathPtr, err := syscall.UTF16PtrFromString(targetPath)
	if err != nil {
		return err
	}

	// 允许读取 (FILE_SHARE_READ)，坚决拒绝其他进程写入和删除
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

	// 🌟 修复：使用切片和互斥锁保存所有句柄，防止多次调用时变量覆盖导致控制权丢失
	lockMu.Lock()
	lockedHandles = append(lockedHandles, handle)
	lockMu.Unlock()

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
