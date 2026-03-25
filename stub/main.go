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
	user32                    = syscall.NewLazyDLL("user32.dll")
	procPeekMessageW          = user32.NewProc("PeekMessageW")
	procMessageBoxW           = user32.NewProc("MessageBoxW")
	procSystemParametersInfoW = user32.NewProc("SystemParametersInfoW")
	procSetWindowPos          = user32.NewProc("SetWindowPos")
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
	// 0x40010 = MB_TOPMOST (强制最上层) | MB_ICONHAND (错误红叉图标)
	procMessageBoxW.Call(0, uintptr(unsafe.Pointer(msgPtr)), uintptr(unsafe.Pointer(titlePtr)), 0x40010)
}

// 🌟 核心重构：抛弃 Dialog，使用完全听话的 MainWindow
func askPassword() string {
	var mw *walk.MainWindow
	var pwdTE *walk.LineEdit
	var pwd string

	err := MainWindow{
		AssignTo: &mw,
		Title:    "安全验证",
		MinSize:  Size{Width: 320, Height: 120},
		Size:     Size{Width: 320, Height: 120}, // 直接写死固定尺寸
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
					mw.Close() // 关闭 MainWindow 即可结束运行循环
				},
			},
		},
	}.Create()

	if err != nil {
		return ""
	}

	// 1. 物理计算：获取屏幕除去任务栏的真实面积
	var rect struct{ Left, Top, Right, Bottom int32 }
	procSystemParametersInfoW.Call(0x0030, 0, uintptr(unsafe.Pointer(&rect)), 0)

	// 计算绝对坐标 (唯一合法路径：屏幕右边界 - 窗口宽 - 边距)
	x := int(rect.Right) - 320 - 15
	y := int(rect.Bottom) - 120 - 15

	// 2. 赋予坐标：MainWindow 会完美遵守
	mw.SetBounds(walk.Rectangle{X: x, Y: y, Width: 320, Height: 120})
	
	// 3. 强行置顶：HWND_TOPMOST (-1)
	procSetWindowPos.Call(uintptr(mw.Handle()), ^uintptr(0), uintptr(x), uintptr(y), 0, 0, 0x0041)

	mw.Run()
	return pwd
}

func verifyExitPassword() bool {
	hashHex := os.Getenv("GOSHIELD_EXIT_HASH")
	if hashHex == "" {
		return true
	}

	exitVerifyHash, err := hex.DecodeString(hashHex)
	if err != nil || len(exitVerifyHash) != 32 {
		return true
	}

	var mw *walk.MainWindow
	var pwdTE *walk.LineEdit
	var pwd string

	err = MainWindow{
		AssignTo: &mw,
		Title:    "退出安全验证",
		MinSize:  Size{Width: 320, Height: 120},
		Size:     Size{Width: 320, Height: 120},
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
					mw.Close()
				},
			},
		},
	}.Create()

	if err != nil {
		return false
	}

	// 1. 物理计算：获取屏幕可用区域
	var rect struct{ Left, Top, Right, Bottom int32 }
	procSystemParametersInfoW.Call(0x0030, 0, uintptr(unsafe.Pointer(&rect)), 0)

	x := int(rect.Right) - 320 - 15
	y := int(rect.Bottom) - 120 - 15

	// 2. 精准定位与置顶
	mw.SetBounds(walk.Rectangle{X: x, Y: y, Width: 320, Height: 120})
	procSetWindowPos.Call(uintptr(mw.Handle()), ^uintptr(0), uintptr(x), uintptr(y), 0, 0, 0x0041)

	mw.Run()

	if pwd == "" {
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
		showErrorBox("密码错误")
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
					showErrorBox("密码错误")
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

		const accessRight = 0x00100000 | 0x0400

		for {
			hProcess, _, _ := procOpenProcess.Call(uintptr(accessRight), 0, uintptr(targetPID))
			if hProcess != 0 {
				procWaitForSingleObject.Call(hProcess, 0xFFFFFFFF)
				procCloseHandle.Call(hProcess)
			} else {
				time.Sleep(500 * time.Millisecond)
			}

			exitUIPassed := false
			hashHex := os.Getenv("GOSHIELD_EXIT_HASH")
			if hashHex == "" {
				exitUIPassed = true 
			} else {
				cmd := exec.Command(originalExe)
				cmd.Env = append(os.Environ(), "GOSHIELD_SHOW_EXIT_UI=1")
				err := cmd.Run() 
				if err == nil {
					exitUIPassed = true 
				}
			}

			if exitUIPassed {
				break 
			}

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
