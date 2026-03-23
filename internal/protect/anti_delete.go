// 文件路径: internal/protect/anti_delete.go
package protect

import (
	"os"
	"syscall"
)

// 全局变量保存句柄，防止 Go 语言的垃圾回收器 (GC) 自动关闭文件句柄导致锁失效
var globalFileHandle syscall.Handle = syscall.InvalidHandle

// LockSelfFile 独占锁定自身可执行文件
// 成功返回 nil，失败返回 error
func LockSelfFile() error {
	// 1. 获取当前运行的可执行文件绝对路径
	exePath, err := os.Executable()
	if err != nil {
		return err
	}

	// 2. 将路径转换为 Windows API 需要的 UTF-16 指针
	pathPtr, err := syscall.UTF16PtrFromString(exePath)
	if err != nil {
		return err
	}

	// 3. 调用底层 CreateFile 锁定文件
	// 核心防御点：ShareMode 设置为 0 (FILE_SHARE_NONE)
	// 这意味着拒绝其他任何进程对该文件发起读、写、删除的共享请求
	handle, err := syscall.CreateFile(
		pathPtr,
		syscall.GENERIC_READ, // 仅要求读权限
		0,                    // FILE_SHARE_NONE (绝对独占)
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)

	if err != nil {
		return err
	}

	// 赋值给全局变量，持有至进程生命周期结束
	globalFileHandle = handle
	return nil
}
