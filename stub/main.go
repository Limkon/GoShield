// 文件路径: stub/main.go
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
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
				PasswordMode: true,
			},
			PushButton{
				Text: "🚀 验证并启动",
				OnClicked: func() {
					pwd = pwdTE.Text()
					dlg.Accept()
				},
			},
		},
	}.Run(nil)

	if err != nil || pwd == "" {
		return ""
	}
	return pwd
}

// 🌟 修复：不再通过 os.Open 读取文件，而是通过环境变量获取哈希，避免与 LockFile 发生读写死锁冲突
func verifyExitPassword() bool {
	hashHex := os.Getenv("GOSHIELD_EXIT_HASH")
	if hashHex == "" {
		return true // 无密码要求
	}

	exitVerifyHash, err := hex.DecodeString(hashHex)
	if err != nil || len(exitVerifyHash) != 32 {
		return true
	}

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

	if pwd == "" || err != nil {
		return false
	}

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

	return true
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
	exitVerifyHash := footer[32:64]
	finalKey := footer[64:96]
	rememberFlag := footer[96]
	payloadSize := binary.LittleEndian.Uint64(footer[97:105])

	if fileSize < footerSize+int64(payloadSize) {
		return nil, fmt.Errorf("size error")
	}

	// 🌟 将退出密码验证器存入环境变量，供后续保镖和退出 UI 校验使用
	isExitZero := true
	for _, b := range exitVerifyHash {
		if b != 0 {
			isExitZero = false
			break
		}
	}
	if !isExitZero {
		os.Setenv("GOSHIELD_EXIT_HASH", hex.EncodeToString(exitVerifyHash))
	} else {
		os.Setenv("GOSHIELD_EXIT_HASH", "")
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
			pwd = cachedPwd 
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
				
				pwd = "" 
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

	// 🌟 新增拦截层：如果环境变量被设置，说明这是保镖唤起的专用 UI 进程
	if os.Getenv("GOSHIELD_SHOW_EXIT_UI") == "1" {
		if verifyExitPassword() {
			os.Exit(0)
		}
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
			} else {
				// 防御：进程可能被强制秒退或 PID 异常，必须 Sleep 阻断无限循环空转
				time.Sleep(1 * time.Second)
			}

			// 🌟 核心修复：通过安全唤起外部带清单（Manifest）的原程序来绘制 UI 拦截窗口
			exitUIPassed := false
			hashHex := os.Getenv("GOSHIELD_EXIT_HASH")
			if hashHex == "" {
				exitUIPassed = true // 无退出密码拦截
			} else {
				cmd := exec.Command(originalExe)
				cmd.Env = append(os.Environ(), "GOSHIELD_SHOW_EXIT_UI=1")
				err := cmd.Run() // 阻塞等待用户输入
				if err == nil {
					exitUIPassed = true // 退出码为 0 代表验证成功
				}
			}

			if exitUIPassed {
				break
			}

			// 验证失败或点击取消，程序直接复活
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
