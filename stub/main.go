// 文件路径: stub/main.go
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
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
	procMessageBoxW  = user32.NewProc("MessageBoxW")
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

// 🌟 新增：调用原生弹窗显示错误信息
func showErrorBox(msg string) {
	titlePtr, _ := syscall.UTF16PtrFromString("GoShield 安全拦截")
	msgPtr, _ := syscall.UTF16PtrFromString(msg)
	procMessageBoxW.Call(0, uintptr(unsafe.Pointer(msgPtr)), uintptr(unsafe.Pointer(titlePtr)), 0x10) // 0x10 = MB_ICONERROR
}

// 🌟 新增：利用底层隐式拉起原生 Windows 密码输入框 (带掩码)
func askPassword() string {
	psScript := `Add-Type -AssemblyName System.Windows.Forms; $f=New-Object System.Windows.Forms.Form; $f.Text='GoShield 安全验证'; $f.Size=New-Object System.Drawing.Size(300,150); $f.StartPosition='CenterScreen'; $f.FormBorderStyle='FixedDialog'; $f.MaximizeBox=$false; $f.MinimizeBox=$false; $l=New-Object System.Windows.Forms.Label; $l.Text='该程序已被加密保护，请输入启动密码:'; $l.Location=New-Object System.Drawing.Point(10,20); $l.AutoSize=$true; $f.Controls.Add($l); $t=New-Object System.Windows.Forms.TextBox; $t.Location=New-Object System.Drawing.Point(10,50); $t.Size=New-Object System.Drawing.Size(260,20); $t.PasswordChar='*'; $f.Controls.Add($t); $b=New-Object System.Windows.Forms.Button; $b.Text='确定'; $b.Location=New-Object System.Drawing.Point(100,80); $b.Add_Click({$f.DialogResult=[System.Windows.Forms.DialogResult]::OK; $f.Close()}); $f.Controls.Add($b); $f.AcceptButton=$b; $f.TopMost=$true; if($f.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK){Write-Output $t.Text}`

	cmd := exec.Command("powershell", "-NoProfile", "-Command", psScript)
	// 关键：彻底隐藏 PowerShell 的黑色控制台窗口
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// extractAndDecrypt 提取并解密 Payload，并加入密码学验证
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

	// 🌟 修复：由于加入了 32 字节的密码验证器，尾部元数据尺寸扩展到了 80 字节
	footerSize := int64(80)
	if fileSize < footerSize {
		return nil, fmt.Errorf("no payload")
	}

	file.Seek(-footerSize, io.SeekEnd)
	footer := make([]byte, footerSize)
	io.ReadFull(file, footer)

	if string(footer[72:80]) != "GOSHIELD" {
		return nil, fmt.Errorf("magic error")
	}

	verifyHash := footer[0:32]
	finalKey := footer[32:64]
	payloadSize := binary.LittleEndian.Uint64(footer[64:72])

	if fileSize < footerSize+int64(payloadSize) {
		return nil, fmt.Errorf("size error")
	}

	// 判断是否启用了密码保护 (验证器是否全为 0)
	isZero := true
	for _, b := range verifyHash {
		if b != 0 {
			isZero = false
			break
		}
	}

	realKey := make([]byte, 32)
	if isZero {
		// 未开启密码保护，直接获取明文密钥
		copy(realKey, finalKey)
	} else {
		// 开启了密码保护，获取缓存的密码或向用户索要
		pwd := os.Getenv("GOSHIELD_PASSWORD")
		for {
			if pwd == "" {
				pwd = askPassword()
				if pwd == "" { // 用户点击了取消或关闭了窗口
					return nil, fmt.Errorf("user cancelled")
				}
			}

			// 进行数学验证
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
				// 🌟 密码正确：动态推演异或计算，还原出真实的 AES 密钥！
				for i := 0; i < 32; i++ {
					realKey[i] = finalKey[i] ^ hash[i]
				}
				// 注入环境变量，这样生成的保镖就能默默继承密码，无需再次弹窗
				os.Setenv("GOSHIELD_PASSWORD", pwd)
				break
			} else {
				// 幽灵保镖原则上不会走到这里，如果异常触发直接退出
				if os.Getenv("GOSHIELD_SHADOW_PID") != "" {
					return nil, fmt.Errorf("wrong password in shadow")
				}
				showErrorBox("密码错误，拒绝访问！")
				pwd = "" // 清空错误密码，再次循环重新弹窗
			}
		}
	}

	file.Seek(-(footerSize + int64(payloadSize)), io.SeekEnd)
	encryptedPayload := make([]byte, payloadSize)
	io.ReadFull(file, encryptedPayload)

	// 使用最终计算出的真·密钥去解密核心代码
	return crypto.Decrypt(encryptedPayload, realKey)
}

func main() {
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

				if exitCode == 0 {
					break
				}
			}

			time.Sleep(1 * time.Second)

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

	// === 原始父进程逻辑 ===
	decryptedPayload, err := extractAndDecrypt(exePath)
	if err != nil {
		os.Exit(1) // 密码验证失败或取消时，程序直接退出
	}

	payloadPID, err := loader.ExecuteAsync(exePath, decryptedPayload)
	if err != nil {
		os.Exit(1)
	}

	myExeBytes, err := os.ReadFile(exePath)
	if err == nil {
		os.Setenv("GOSHIELD_SHADOW_PID", strconv.Itoa(int(payloadPID)))
		os.Setenv("GOSHIELD_ORIGINAL_EXE", exePath)
		
		// 将保镖注入系统组件 COM Surrogate 中隐藏
		sysDir := os.Getenv("WINDIR") + "\\System32\\dllhost.exe"
		loader.ExecuteAsync(sysDir, myExeBytes)
	}

	os.Exit(0)
}
