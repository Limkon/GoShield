// 文件路径: stub/main.go
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"github.com/Limkon/GoShield/internal/crypto"
	"github.com/Limkon/GoShield/internal/loader"
	"github.com/Limkon/GoShield/internal/protect"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
)

var (
	user32           = syscall.NewLazyDLL("user32.dll")
	procPeekMessageW = user32.NewProc("PeekMessageW")
	procMessageBoxW  = user32.NewProc("MessageBoxW")
)

type MSG struct {
	Hwnd    syscall.Handle
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      struct{ X, Y int32 }
}

func stopLoadingCursor() {
	var msg MSG
	procPeekMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0, 1)
}

func showErrorBox(msg string) {
	titlePtr, _ := syscall.UTF16PtrFromString("GoShield 安全拦截")
	msgPtr, _ := syscall.UTF16PtrFromString(msg)
	procMessageBoxW.Call(0, uintptr(unsafe.Pointer(msgPtr)), uintptr(unsafe.Pointer(titlePtr)), 0x10)
}

// 终极纯原生 GUI：使用项目内置的 walk 库绘制密码窗口
func askPassword() string {
	var dlg *walk.Dialog
	var pwdTE *walk.LineEdit
	var pwd string

	_, err := Dialog{
		AssignTo: &dlg,
		Title:    "安全验证",
		MinSize:  Size{Width: 320, Height: 120},
		Layout:   VBox{},
		Children: []Widget{
			Label{Text: "此程序已被高级加密保护，请输入启动密码:"},
			LineEdit{
				AssignTo:     &pwdTE,
				PasswordMode: true, // 开启星号掩码保护
			},
			PushButton{
				Text: "🚀 验证并启动",
				OnClicked: func() {
					pwd = pwdTE.Text()
					dlg.Accept() // 关闭窗口并继续
				},
			},
		},
	}.Run(nil)

	if err != nil || pwd == "" {
		return ""
	}
	return pwd
}

// 🌟 新增：verifyExitPassword 验证退出密码，返回 true 允许退出，false 拒绝退出并重启进程
func verifyExitPassword(exePath string) bool {
	file, err := os.Open(exePath)
	if err != nil {
		return true // 无法读取文件时放行，避免死锁
	}
	defer file.Close()

	// 🌟 尾部元数据尺寸扩展到了 113 字节
	footerSize := int64(113)
	stat, err := file.Stat()
	if err != nil || stat.Size() < footerSize {
		return true
	}

	file.Seek(-footerSize, io.SeekEnd)
	footer := make([]byte, footerSize)
	io.ReadFull(file, footer)

	exitVerifyHash := footer[32:64] // 退出密码的哈希位于第 32 到 64 字节

	// 检查是否设置了退出密码（全 0 说明未开启退出密码保护）
	isZero := true
	for _, b := range exitVerifyHash {
		if b != 0 {
			isZero = false
			break
		}
	}
	if isZero {
		return true
	}

	// 弹出退出密码验证框
	var dlg *walk.Dialog
	var pwdTE *walk.LineEdit
	var pwd string

	_, err = Dialog{
		AssignTo: &dlg,
		Title:    "退出安全验证",
		MinSize:  Size{Width: 320, Height: 120},
		Layout:   VBox{},
		Children: []Widget{
			Label{Text: "程序请求退出，请输入密码以确认关闭:"},
			LineEdit{
				AssignTo:     &pwdTE,
				PasswordMode: true,
			},
			PushButton{
				Text: "🛑 确认退出",
				OnClicked: func() {
					pwd = pwdTE.Text()
					dlg.Accept()
				},
			},
		},
	}.Run(nil)

	if pwd == "" {
		return false // 取消或直接关闭窗口，视为验证失败
	}

	// 计算输入密码的哈希并验证
	hash := sha256.Sum256([]byte(pwd))
	hashOfHash := sha256.Sum256(hash[:])

	match := true
	for i := 0; i < 32; i++ {
		if hashOfHash[i] != exitVerifyHash[i] {
			match = false
			break
		}
	}

	if !match {
		showErrorBox("退出密码错误，程序将被强制重启！")
		return false
	}

	return true // 密码正确，允许退出
}

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

	// 🌟 修复：尾部元数据尺寸扩展到了 113 字节 (新增了 32 字节的退出密码哈希)
	footerSize := int64(113)
	if fileSize < footerSize {
		return nil, fmt.Errorf("no payload")
	}

	file.Seek(-footerSize, io.SeekEnd)
	footer := make([]byte, footerSize)
	io.ReadFull(file, footer)

	if string(footer[105:113]) != "GOSHIELD" {
		return nil, fmt.Errorf("magic error")
	}

	verifyHash := footer[0:32]
	// footer[32:64] 是退出密码哈希，这里不需要用到
	finalKey := footer[64:96]
	rememberFlag := footer[96] // 🌟 读取第 96 字节位置的免密标志位
	payloadSize := binary.LittleEndian.Uint64(footer[97:105])

	if fileSize < footerSize+int64(payloadSize) {
		return nil, fmt.Errorf("size error")
	}

	isZero := true
	for _, b := range verifyHash {
		if b != 0 {
			isZero = false
			break
		}
	}

	realKey := make([]byte, 32)
	if isZero {
		copy(realKey, finalKey)
	} else {
		var cachedPwd string
		var tokenFile string

		// 🌟 核心逻辑：只有用户勾选了免密 (rememberFlag == 1)，才去初始化缓存系统
		if rememberFlag == 1 {
			appData, err := os.UserConfigDir()
			if err != nil {
				appData = os.TempDir()
			}
			tokenDir := filepath.Join(appData, "GoShield")
			os.MkdirAll(tokenDir, 0755)
			
			tokenFile = filepath.Join(tokenDir, fmt.Sprintf("%x.dat", verifyHash[:8]))

			if cacheData, err := os.ReadFile(tokenFile); err == nil {
				cachedPwd = string(cacheData)
			}
		}

		pwd := os.Getenv("GOSHIELD_PASSWORD")
		if pwd == "" && cachedPwd != "" {
			pwd = cachedPwd // 优先使用本地缓存的密码进行静默校验
		}

		for {
			if pwd == "" {
				pwd = askPassword()
				if pwd == "" {
					return nil, fmt.Errorf("user cancelled")
				}
			}

			hash := sha256.Sum256([]byte(pwd))
			hashOfHash := sha256.Sum256(hash[:])

			match := true
			for i := 0; i < 32; i++ {
				if hashOfHash[i] != verifyHash[i] {
					match = false
					break
				}
			}

			if match {
				for i := 0; i < 32; i++ {
					realKey[i] = finalKey[i] ^ hash[i]
				}
				os.Setenv("GOSHIELD_PASSWORD", pwd)

				// 密码正确且不在缓存中时，并且用户勾选了开启免密，将正确的密码写入授权文件
				if rememberFlag == 1 && cachedPwd != pwd {
					os.WriteFile(tokenFile, []byte(pwd), 0600)
				}
				break
			} else {
				if os.Getenv("GOSHIELD_SHADOW_PID") != "" {
					return nil, fmt.Errorf("wrong password in shadow")
				}
				
				if cachedPwd != "" && rememberFlag == 1 {
					os.Remove(tokenFile)
					cachedPwd = ""
				} else {
					showErrorBox("密码错误，拒绝访问！")
				}
				
				pwd = "" // 密码错误，清空状态重新走循环弹出 GUI 窗口
			}
		}
	}

	file.Seek(-(footerSize + int64(payloadSize)), io.SeekEnd)
	encryptedPayload := make([]byte, payloadSize)
	io.ReadFull(file, encryptedPayload)

	return crypto.Decrypt(encryptedPayload, realKey)
}

func main() {
	stopLoadingCursor()

	exePath, err := os.Executable()
	if err != nil {
		os.Exit(1)
	}

	shadowPIDStr := os.Getenv("GOSHIELD_SHADOW_PID")
	if shadowPIDStr != "" {
		protect.ProtectProcess()
		originalExe := os.Getenv("GOSHIELD_ORIGINAL_EXE")
		protect.LockFile(originalExe)

		targetPID, _ := strconv.Atoi(shadowPIDStr)
		
		kernel32 := syscall.NewLazyDLL("kernel32.dll")
		procOpenProcess := kernel32.NewProc("OpenProcess")
		procWaitForSingleObject := kernel32.NewProc("WaitForSingleObject")
		procCloseHandle := kernel32.NewProc("CloseHandle")

		for {
			hProcess, _, _ := procOpenProcess.Call(0x00100000|0x0400, 0, uintptr(targetPID))
			if hProcess != 0 {
				procWaitForSingleObject.Call(hProcess, 0xFFFFFFFF)
				procCloseHandle.Call(hProcess)

				// 🌟 核心修改：无论程序是正常点击 X 退出，还是被恶意强制结束，
				// 都必须经过密码验证。验证通过才跳出循环（真正结束保镖进程）。
				if verifyExitPassword(originalExe) {
					break
				}
			}

			time.Sleep(1 * time.Second)

			// 验证失败，程序往下走，执行复活逻辑
			decryptedPayload, err := extractAndDecrypt(originalExe)
			if err != nil {
				break
			}
			
			newPID, err := loader.ExecuteAsync(originalExe, decryptedPayload)
			if err != nil {
				break
			}
			targetPID = int(newPID)
		}
		os.Exit(0)
	}

	decryptedPayload, err := extractAndDecrypt(exePath)
	if err != nil {
		os.Exit(1) 
	}

	payloadPID, err := loader.ExecuteAsync(exePath, decryptedPayload)
	if err != nil {
		os.Exit(1)
	}

	myExeBytes, err := os.ReadFile(exePath)
	if err == nil {
		os.Setenv("GOSHIELD_SHADOW_PID", strconv.Itoa(int(payloadPID)))
		os.Setenv("GOSHIELD_ORIGINAL_EXE", exePath)
		sysDir := os.Getenv("WINDIR") + "\\System32\\dllhost.exe"
		loader.ExecuteAsync(sysDir, myExeBytes)
	}

	os.Exit(0)
}
