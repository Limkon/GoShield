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
	procEnumWindows               = user32.NewProc("EnumWindows")
	procGetWindowThreadProcessId  = user32.NewProc("GetWindowThreadProcessId")
	procIsWindowVisible           = user32.NewProc("IsWindowVisible")
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
	procMessageBoxW.Call(0, uintptr(unsafe.Pointer(msgPtr)), uintptr(unsafe.Pointer(titlePtr)), 0x10)
}

func hasVisibleWindow(pid uint32) bool {
	var found bool
	cb := syscall.NewCallback(func(hwnd syscall.Handle, lParam uintptr) uintptr {
		var wpid uint32
		procGetWindowThreadProcessId.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&wpid)))
		if wpid == pid {
			vis, _, _ := procIsWindowVisible.Call(uintptr(hwnd))
			if vis != 0 {
				found = true
				return 0 
			}
		}
		return 1 
	})
	procEnumWindows.Call(cb, 0)
	return found
}

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

func verifyExitPassword() bool {
	hashHex := os.Getenv("GOSHIELD_EXIT_HASH")
	if hashHex == "" {
		return true 
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
		
		const accessRight = 0x00100000 | 0x0400 | 0x0001
		
		// 🌟 获取当前保镖主线程 ID，用于接收事件唤醒信号
		tidPtr, _, _ := procGetCurrentThreadId.Call()
		mainThreadId := uint32(tidPtr)

		// 🌟 注册原生的钩子回调函数（0 CPU 占用，全靠系统硬件事件触发）
		winEventCb := syscall.NewCallback(func(hWinEventHook syscall.Handle, event uint32, hwnd syscall.Handle, idObject int32, idChild int32, idEventThread uint32, dwmsEventTime uint32) uintptr {
			if idObject == 0 { // 确认是窗口事件 (OBJID_WINDOW)
				// 发送自定义唤醒信号 (WM_APP = 0x8000) 到我们的主线程，打断无限挂起状态
				procPostThreadMessageW.Call(uintptr(mainThreadId), 0x8000, 0, 0)
			}
			return 0
		})

		for {
			hProcess, _, _ := procOpenProcess.Call(uintptr(accessRight), 0, uintptr(targetPID))
			if hProcess != 0 {
				windowAppeared := false

				// 🌟 极限操作：监控目标 PID 的 0x8001(销毁) 到 0x8003(隐藏) 的事件
				// 这里利用了操作系统的底层无感事件订阅
				hook, _, _ := procSetWinEventHook.Call(
					0x8001, 0x8003, 
					0, winEventCb, uintptr(targetPID), 0, 0) // WINEVENT_OUTOFCONTEXT

				for {
					// 🌟 绝对 0 轮询：阻塞当前线程直到 hProcess 死亡，或者收到刚才我们设定的唤醒事件 (QS_ALLEVENTS = 0x04BF)
					// 这期间线程处于内核态深度休眠，完全不消耗 CPU 资源。
					res, _, _ := procMsgWaitForMultipleObjects.Call(1, uintptr(unsafe.Pointer(&hProcess)), 0, 0xFFFFFFFF, 0x04BF)
					if res == 0 {
						break // 进程被强制物理销毁，结束监控
					}

					// 清理系统通过事件驱动发送给我们的队列消息，否则会阻塞下次唤醒
					var msg MSG
					for {
						hasMsg, _, _ := procPeekMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0, 1) // PM_REMOVE
						if hasMsg == 0 {
							break
						}
						procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
						procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
					}

					// 唤醒后，仅执行这一次状态校验
					hasVis := hasVisibleWindow(uint32(targetPID))
					if hasVis {
						windowAppeared = true
					} else if windowAppeared {
						// 一旦发现曾经出现的窗口消失了，说明目标正在退出！瞬间打破死锁！
						break
					}
				}

				if hook != 0 {
					procUnhookWinEvent.Call(hook)
				}
			} else {
				time.Sleep(500 * time.Millisecond) // 防止异常防空转兜底
			}

			// 拦截时刻：安全唤起外部带清单（Manifest）的原程序绘制 UI 拦截窗口
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

			if hProcess != 0 {
				// 战术斩杀：毫不留情地切断依然在后台磨叽的主进程残留线程，杜绝文件抢占
				procTerminateProcess.Call(hProcess, 0)
				procCloseHandle.Call(hProcess)
			}

			if exitUIPassed {
				break 
			}

			// 密码错误：执行瞬发复活逻辑
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
