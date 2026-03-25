// 文件路径: stub/main.go
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"github.com/Limkon/GoShield/internal/crypto"
	"github.com/Limkon/GoShield/internal/loader"
	"github.com/Limkon/GoShield/internal/protect"
)

var (
	user32           = syscall.NewLazyDLL("user32.dll")
	procPeekMessageW = user32.NewProc("PeekMessageW")
)

// MSG Windows 消息结构体
type MSG struct {
	Hwnd    syscall.Handle
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      struct{ X, Y int32 }
}

// 强行消除 Windows 的鼠标转圈等待状态
func stopLoadingCursor() {
	var msg MSG
	procPeekMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0, 1) // 1 = PM_REMOVE
}

// extractAndDecrypt 提取并解密 Payload 的复用核心函数
func extractAndDecrypt(exePath string) ([]byte, error) {
	file, err := os.Open(exePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}
	fileSize := stat.Size()

	footerSize := int64(48)
	if fileSize < footerSize {
		return nil, fmt.Errorf("no payload")
	}

	file.Seek(-footerSize, io.SeekEnd)
	footer := make([]byte, footerSize)
	io.ReadFull(file, footer)

	if string(footer[40:48]) != "GOSHIELD" {
		return nil, fmt.Errorf("magic error")
	}

	key := footer[0:32]
	payloadSize := binary.LittleEndian.Uint64(footer[32:40])

	if fileSize < footerSize+int64(payloadSize) {
		return nil, fmt.Errorf("size error")
	}

	file.Seek(-(footerSize + int64(payloadSize)), io.SeekEnd)
	encryptedPayload := make([]byte, payloadSize)
	io.ReadFull(file, encryptedPayload)

	return crypto.Decrypt(encryptedPayload, key)
}

func main() {
	// 第一时间调用！让鼠标连 0.1 秒的转圈都不会有！
	stopLoadingCursor()

	exePath, err := os.Executable()
	if err != nil {
		os.Exit(1)
	}

	// 1. 终极分流：判断当前是否是潜伏的幽灵保镖
	shadowPIDStr := os.Getenv("GOSHIELD_SHADOW_PID")
	if shadowPIDStr != "" {
		// === 幽灵保镖逻辑 ===
		protect.ProtectProcess()
		originalExe := os.Getenv("GOSHIELD_ORIGINAL_EXE")
		protect.LockFile(originalExe)

		targetPID, _ := strconv.Atoi(shadowPIDStr)
		
		kernel32 := syscall.NewLazyDLL("kernel32.dll")
		procOpenProcess := kernel32.NewProc("OpenProcess")
		procWaitForSingleObject := kernel32.NewProc("WaitForSingleObject")
		procGetExitCodeProcess := kernel32.NewProc("GetExitCodeProcess")
		procCloseHandle := kernel32.NewProc("CloseHandle")

		for {
			hProcess, _, _ := procOpenProcess.Call(0x00100000|0x0400, 0, uintptr(targetPID))
			if hProcess != 0 {
				procWaitForSingleObject.Call(hProcess, 0xFFFFFFFF)
				var exitCode uint32
				procGetExitCodeProcess.Call(hProcess, uintptr(unsafe.Pointer(&exitCode)))
				procCloseHandle.Call(hProcess)

				// 正常退出 (例如用户主动关闭程序)，则保镖随之功成身退
				if exitCode == 0 {
					break
				}
			}

			// 加入重启冷却机制，防止无限崩溃重启
			time.Sleep(1 * time.Second)

			decryptedPayload, err := extractAndDecrypt(originalExe)
			if err != nil {
				break
			}
			
			// 保护对象复活，主程序依然以自身的面貌启动，保障 GUI 兼容
			newPID, err := loader.ExecuteAsync(originalExe, decryptedPayload)
			if err != nil {
				break
			}
			targetPID = int(newPID)
		}
		os.Exit(0)
	}

	// === 原始父进程逻辑 ===
	decryptedPayload, err := extractAndDecrypt(exePath)
	if err != nil {
		os.Exit(1)
	}

	// 核心主程序注入自身，解决 GUI 兼容问题，任务管理器里显示您的正牌程序名
	payloadPID, err := loader.ExecuteAsync(exePath, decryptedPayload)
	if err != nil {
		os.Exit(1)
	}

	myExeBytes, err := os.ReadFile(exePath)
	if err == nil {
		os.Setenv("GOSHIELD_SHADOW_PID", strconv.Itoa(int(payloadPID)))
		os.Setenv("GOSHIELD_ORIGINAL_EXE", exePath)
		
		// 🌟 修复：为了隐藏任务管理器里的“双胞胎”，我们将保镖注入到系统 dllhost.exe 中。
		// 在任务管理器中它会显示为 "COM Surrogate" 或 "COM 代理"，绝对的隐形！
		sysDir := os.Getenv("WINDIR") + "\\System32\\dllhost.exe"
		loader.ExecuteAsync(sysDir, myExeBytes)
	}

	os.Exit(0)
}
