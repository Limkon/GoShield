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
	// 🌟 核心修复点：将 ShareMode 改为 FILE_SHARE_READ (值为 1)
	// 这意味着：允许读取(修复 RunPE 自身注入失败的 Bug)
	// 但依然拒绝其他任何进程对该文件发起写、删除的共享请求 (完美保留防删功能)
	handle, err := syscall.CreateFile(
		pathPtr,
		syscall.GENERIC_READ,    // 仅要求读权限
		syscall.FILE_SHARE_READ, // 允许读，拒绝写和删
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
