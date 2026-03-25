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
	kernel32                      = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess               = kernel32.NewProc("OpenProcess")
	procCloseHandle               = kernel32.NewProc("CloseHandle")
	procTerminateProcess          = kernel32.NewProc("TerminateProcess")
	procGetCurrentThreadId        = kernel32.NewProc("GetCurrentThreadId")

	user32                        = syscall.NewLazyDLL("user32.dll")
	procPeekMessageW              = user32.NewProc("PeekMessageW")
	procMessageBoxW               = user32.NewProc("MessageBoxW")
	procSystemParametersInfoW     = user32.NewProc("SystemParametersInfoW")
	procSetWindowPos              = user32.NewProc("SetWindowPos")
	procEnumWindows               = user32.NewProc("EnumWindows")
	procGetWindowThreadProcessId  = user32.NewProc("GetWindowThreadProcessId")
	procSetWinEventHook           = user32.NewProc("SetWinEventHook")
	procUnhookWinEvent            = user32.NewProc("UnhookWinEvent")
	procMsgWaitForMultipleObjects = user32.NewProc("MsgWaitForMultipleObjects")
	procPostThreadMessageW        = user32.NewProc("PostThreadMessageW")
	procTranslateMessage          = user32.NewProc("TranslateMessage")
	procDispatchMessageW          = user32.NewProc("DispatchMessageW")
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
	procMessageBoxW.Call(0, uintptr(unsafe.Pointer(msgPtr)), uintptr(unsafe.Pointer(titlePtr)), 0x40010)
}

// 探测内存中是否还存在目标进程的任何窗口对象
func hasAnyWindow(pid uint32) bool {
	var found bool
	cb := syscall.NewCallback(func(hwnd syscall.Handle, lParam uintptr) uintptr {
		var wpid uint32
		procGetWindowThreadProcessId.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&wpid)))
		if wpid == pid {
			found = true
			return 0 // 找到哪怕一个窗口，立刻停止枚举
		}
		return 1
	})
	procEnumWindows.Call(cb, 0)
	return found
}

// 保持使用上一版完美的 MainWindow，确保精准定位右下角且绝对置顶
func askPassword() string {
	var mw *walk.MainWindow
	var pwdTE *walk.LineEdit
	var pwd string

	err := MainWindow{
		AssignTo: &mw,
		Title:    "安全验证",
		MinSize:  Size{Width: 320, Height: 120},
		Size:     Size{Width: 320, Height: 120},
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
					mw.Close()
				},
			},
		},
	}.Create()

	if err != nil {
		return ""
	}

	var rect struct{ Left, Top, Right, Bottom int32 }
	procSystemParametersInfoW.Call(0x0030, 0, uintptr(unsafe.Pointer(&rect)), 0)

	x := int(rect.Right) - 320 - 15
	y := int(rect.Bottom) - 120 - 15

	mw.SetBounds(walk.Rectangle{X: x, Y: y, Width: 320, Height: 120})
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

	var rect struct{ Left, Top, Right, Bottom int32 }
	procSystemParametersInfoW.Call(0x0030, 0, uintptr(unsafe.Pointer(&rect)), 0)

	x := int(rect.Right) - 320 - 15
	y := int(rect.Bottom) - 120 - 15

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
		const accessRight = 0x00100000 | 0x0400 | 0x0001 // SYNCHRONIZE | QUERY | TERMINATE

		// 🌟 核心破局点：给予主程序 1.5 秒的“初始化无敌护盾时间”
		// 彻底跳过启动时疯狂创建、销毁临时探测窗口的时期，杜绝“刚启动就拦截”的误报。
		time.Sleep(1500 * time.Millisecond)

		tidPtr, _, _ := procGetCurrentThreadId.Call()
		mainThreadId := uint32(tidPtr)

		winEventCb := syscall.NewCallback(func(hWinEventHook syscall.Handle, event uint32, hwnd syscall.Handle, idObject int32, idChild int32, idEventThread uint32, dwmsEventTime uint32) uintptr {
			if idObject == 0 { // 确认是窗口事件 (OBJID_WINDOW)
				procPostThreadMessageW.Call(uintptr(mainThreadId), 0x8000, 0, 0)
			}
			return 0
		})

		for {
			hProcess, _, _ := procOpenProcess.Call(uintptr(accessRight), 0, uintptr(targetPID))
			if hProcess != 0 {
				// 挂载 0x8001 (EVENT_OBJECT_DESTROY 销毁事件)
				hook, _, _ := procSetWinEventHook.Call(0x8001, 0x8001, 0, winEventCb, uintptr(targetPID), 0, 0)

				for {
					// 0 消耗深度挂起，绝不浪费 1 滴 CPU
					res, _, _ := procMsgWaitForMultipleObjects.Call(1, uintptr(unsafe.Pointer(&hProcess)), 0, 0xFFFFFFFF, 0x04BF)
					if res == 0 {
						break // 进程物理死亡
					}

					var msg MSG
					for {
						hasMsg, _, _ := procPeekMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0, 1)
						if hasMsg == 0 {
							break
						}
						procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
						procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
					}

					// 唤醒后：探测内存中是否还存在该进程的任意窗口对象
					if !hasAnyWindow(uint32(targetPID)) {
						// 🌟 突破口：没有任何窗口了！说明用户按下了托盘退出！瞬间破局！
						break
					}
				}

				if hook != 0 {
					procUnhookWinEvent.Call(hook)
				}

				// 🌟 物理斩杀：既然目标已经决定退出并销毁了所有窗口，
				// 不等它磨蹭清理内存垃圾，保镖直接补刀砍断进程，将几秒的延迟压缩到 0！
				procTerminateProcess.Call(hProcess, 0)
				procCloseHandle.Call(hProcess)
			} else {
				time.Sleep(500 * time.Millisecond)
			}

			// 瞬间弹出 UI
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

			// 拦截失败/密码错误：原地复活
			decryptedPayload, err := extractAndDecrypt(originalExe)
			if err != nil {
				break
			}

			newPID, err := loader.ExecuteAsync(originalExe, decryptedPayload)
			if err != nil {
				break
			}
			targetPID = int(newPID)
			
			// 复活后也要给 1.5 秒护盾，防止陷入死循环
			time.Sleep(1500 * time.Millisecond)
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
