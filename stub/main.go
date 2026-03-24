// 文件路径: stub/main.go
package main

import (
	"encoding/binary"
	"io"
	"os"

	"github.com/Limkon/GoShield/internal/crypto"
	"github.com/Limkon/GoShield/internal/loader"
	"github.com/Limkon/GoShield/internal/protect"
)

func main() {
	// 1. 先从自身读取附加数据
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

	// 3. 🌟 启动双进程不死守护 (注意：这必须放在确认文件未被篡改之后执行，防止坏文件死循环)
	// 如果当前是影子进程，它会在 StartWatchdog 内部阻塞并自动退出，不会继续执行后面的 RunPE 逻辑
	protect.StartWatchdog()

	// 4. 解密真实程序的 Payload
	decryptedPayload, err := crypto.Decrypt(encryptedPayload, key)
	if err != nil {
		protect.NotifyNormalExit() // 哪怕出错也要和平解除影子，避免死循环复活
		os.Exit(1) 
	}

	// 5. 执行内存加载 (RunPE)
	err = loader.Execute(exePath, decryptedPayload)
	if err != nil {
		protect.NotifyNormalExit()
		os.Exit(1)
	}

	// 6. 真实程序已退出，触发安全信号通知影子进程一起和平关闭！
	protect.NotifyNormalExit()
}
