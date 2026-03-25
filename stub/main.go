// 文件路径: stub/main.go
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/Limkon/GoShield/internal/crypto"
	"github.com/Limkon/GoShield/internal/loader"
	"github.com/Limkon/GoShield/internal/protect"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"github.com/microsoft/go-winio"
)

var (
	kernel32                  = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess           = kernel32.NewProc("OpenProcess")
	procWaitForSingleObject   = kernel32.NewProc("WaitForSingleObject")
	procCloseHandle           = kernel32.NewProc("CloseHandle")

	user32                    = syscall.NewLazyDLL("user32.dll")
	procPeekMessageW          = user32.NewProc("PeekMessageW")
	procMessageBoxW           = user32.NewProc("MessageBoxW")
	procSystemParametersInfoW = user32.NewProc("SystemParametersInfoW")
	procSetWindowPos          = user32.NewProc("SetWindowPos")
)

// 🌟 全局状态控制：用于区分是合法退出，还是被强制他杀
var (
	authorizedExit      bool
	authorizedExitMutex sync.Mutex
)

// 定义唯一的命名管道通讯地址
const authPipeName = `\\.\pipe\GoShieldAuthPipe`

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
		return true // 如果没有设置退出密码，直接放行
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

	// 初始化退出密码环境（供后续的 UI 拦截使用）
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

	// 🌟 幽灵保镖模式：执行防护、建立通讯管道并监控生死
	shadowPIDStr := os.Getenv("GOSHIELD_SHADOW_PID")
	if shadowPIDStr != "" {
		protect.ProtectProcess()
		originalExe := os.Getenv("GOSHIELD_ORIGINAL_EXE")
		protect.LockFile(originalExe)

		targetPID, _ := strconv.Atoi(shadowPIDStr)

		// 1. 启动管道服务端，独立于主线程运行
		listener, err := winio.ListenPipe(authPipeName, nil)
		if err == nil {
			go func() {
				for {
					conn, err := listener.Accept()
					if err != nil {
						continue
					}

					reader := bufio.NewReader(conn)
					msg, _ := reader.ReadString('\n')

					// 收到主程序的“离职申请”
					if msg == "TRY_EXIT\n" {
						// 瞬间弹出保镖进程内部已经预热好的密码框
						if verifyExitPassword() {
							// 密码正确，修改放行状态位，并给主程序发放准行许可
							authorizedExitMutex.Lock()
							authorizedExit = true
							authorizedExitMutex.Unlock()

							conn.Write([]byte("ALLOW\n"))
						} else {
							// 密码错误，直接驳回，托盘程序甚至不会感知到闪烁
							conn.Write([]byte("REJECT\n"))
						}
					}
					conn.Close()
				}
			}()
		}

		// 2. 监控线程：死等物理进程状态
		const accessRight = 0x00100000 | 0x0400 // SYNCHRONIZE | QUERY_INFORMATION
		for {
			hProcess, _, _ := procOpenProcess.Call(uintptr(accessRight), 0, uintptr(targetPID))
			if hProcess != 0 {
				procWaitForSingleObject.Call(hProcess, 0xFFFFFFFF)
				procCloseHandle.Call(hProcess)
			} else {
				time.Sleep(500 * time.Millisecond)
			}

			// 进程确认物理死亡。判断它是因为拿到了“审批许可”才退出的，还是被外力强杀的？
			authorizedExitMutex.Lock()
			isAuth := authorizedExit
			authorizedExitMutex.Unlock()

			if isAuth {
				// 走正规流程退出，保镖圆满完成任务，功成身退
				os.Exit(0)
			}

			// 🌟 未经授权的进程死亡（防杀防御触发！）
			decryptedPayload, err := extractAndDecrypt(originalExe)
			if err != nil {
				break
			}

			newPID, err := loader.ExecuteAsync(originalExe, decryptedPayload)
			if err != nil {
				break
			}
			targetPID = int(newPID) // 更新为新生成的 PID，继续进行下一轮监控防线
		}
		os.Exit(0)
	}

	// ---------------- 第一阶段：正常启动与注入加载 ----------------
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
