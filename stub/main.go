package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"github.com/Limkon/GoShield/internal/crypto"
	"github.com/Limkon/GoShield/internal/loader"
	"github.com/Limkon/GoShield/internal/protect"
	"github.com/microsoft/go-winio" // 需要 go get github.com/microsoft/go-winio

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
)

var (
	user32                    = syscall.NewLazyDLL("user32.dll")
	procMessageBoxW           = user32.NewProc("MessageBoxW")
	procSystemParametersInfoW = user32.NewProc("SystemParametersInfoW")
	procSetWindowPos          = user32.NewProc("SetWindowPos")
)

const pipeName = `\\.\pipe\GoShieldAuthPipe`

func showErrorBox(msg string) {
	titlePtr, _ := syscall.UTF16PtrFromString("安全验证")
	msgPtr, _ := syscall.UTF16PtrFromString(msg)
	procMessageBoxW.Call(0, uintptr(unsafe.Pointer(msgPtr)), uintptr(unsafe.Pointer(titlePtr)), 0x40010)
}

// 弹出验证 UI
func verifyExitPassword(hashHex string) bool {
	if hashHex == "" { return true }
	exitVerifyHash, _ := hex.DecodeString(hashHex)

	var mw *walk.MainWindow
	var pwdTE *walk.LineEdit
	var confirmed bool
	var pwd string

	MainWindow{
		AssignTo: &mw,
		Title:    "退出验证",
		MinSize:  Size{Width: 300, Height: 120},
		Layout:   VBox{},
		Children: []Widget{
			Label{Text: "请输入退出密码："},
			LineEdit{AssignTo: &pwdTE, PasswordMode: true},
			PushButton{
				Text: "确认退出",
				OnClicked: func() {
					pwd = pwdTE.Text()
					mw.Close()
					confirmed = true
				},
			},
		},
	}.Create()

	// 定位到右下角
	var rect struct{ Left, Top, Right, Bottom int32 }
	procSystemParametersInfoW.Call(0x0030, 0, uintptr(unsafe.Pointer(&rect)), 0)
	x, y := int(rect.Right)-320, int(rect.Bottom)-140
	mw.SetBounds(walk.Rectangle{X: x, Y: y, Width: 300, Height: 120})
	procSetWindowPos.Call(uintptr(mw.Handle()), ^uintptr(0), uintptr(x), uintptr(y), 0, 0, 0x0041)

	mw.Run()
	if !confirmed { return false }

	h1 := sha256.Sum256([]byte(pwd))
	h2 := sha256.Sum256(h1[:])
	if hex.EncodeToString(h2[:]) == hashHex {
		return true
	}
	showErrorBox("密码错误，拒绝退出")
	return false
}

func main() {
	exePath, _ := os.Executable()

	// ---------------- 影子保镖模式 ----------------
	if os.Getenv("GOSHIELD_SHADOW_PID") != "" {
		protect.ProtectProcess()
		targetPID, _ := strconv.Atoi(os.Getenv("GOSHIELD_SHADOW_PID"))
		exitHash := os.Getenv("GOSHIELD_EXIT_HASH")

		// 启动命名管道监听
		l, err := winio.ListenPipe(pipeName, nil)
		if err != nil { os.Exit(1) }

		go func() {
			for {
				conn, err := l.Accept()
				if err != nil { continue }
				
				reader := bufio.NewReader(conn)
				msg, _ := reader.ReadString('\n')
				
				if msg == "TRY_EXIT\n" {
					if verifyExitPassword(exitHash) {
						fmt.Fprintln(conn, "ALLOW")
						time.Sleep(100 * time.Millisecond)
						os.Exit(0) // 保镖也完成任务退出
					} else {
						fmt.Fprintln(conn, "REJECT")
					}
				}
				conn.Close()
			}
		}()

		// 监控进程是否被强杀（防爆）
		hProc, _ := syscall.OpenProcess(0x00100000, false, uint32(targetPID))
		syscall.WaitForSingleObject(hProc, syscall.INFINITE)
		os.Exit(0)
	}

	// ---------------- 正常启动逻辑 ----------------
	// 1. 解密 Payload (代码同之前，略)
    // 2. 启动主程序获取 PID
    // 3. 启动 dllhost.exe 作为保镖，传入环境变量：
    //    GOSHIELD_SHADOW_PID = 主程序PID
    //    GOSHIELD_EXIT_HASH = 退出密码Hash
}
