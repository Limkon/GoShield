// 文件路径: internal/compiler/generator.go
package compiler

import (
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Limkon/GoShield/internal/crypto" // 🌟 新增：引入 crypto 包进行流式调用
)

// 使用 go:embed 将预编译的外壳程序嵌入到加壳机中
// 注意：在 GitHub Actions 构建或本地构建加壳机前，需先编译 stub 产出此文件
//go:embed stub_base.exe
var stubBase []byte

// 🌟 新增：countingWriter 用于在流式写入过程中精准统计写入的字节数
type countingWriter struct {
	w io.Writer
	n uint64
}

func (cw *countingWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	cw.n += uint64(n)
	return n, err
}

// BuildProtectedExe 核心构建调度 (流式加密版)
// 🌟 修复：移除 encryptedData []byte 参数，摒弃内存驻留模式
func BuildProtectedExe(originalExe string, key []byte, startupPwd string, exitPwd string, rememberPwd bool, outputExe string) error {
	// 校验 stubBase 是否合法
	if len(stubBase) < 1024 {
		return errors.New("内置外壳 (stub_base.exe) 无效或损坏，请重新编译项目！")
	}

	// 避免使用系统 %TEMP% 目录触发 EDR 拦截
	outDir := filepath.Dir(outputExe)
	tmpFile, err := os.CreateTemp(outDir, "goshield_stub_*.exe")
	if err != nil {
		return fmt.Errorf("无法创建临时外壳文件: %v", err)
	}
	tmpExe := tmpFile.Name()
	
	// 写入基础外壳数据
	if _, err := tmpFile.Write(stubBase); err != nil {
		tmpFile.Close()
		os.Remove(tmpExe)
		return fmt.Errorf("释放临时外壳失败: %v", err)
	}
	
	tmpFile.Close() 
	defer os.Remove(tmpExe)

	// 2. 自动化注入图标
	CloneIcon(originalExe, tmpExe)

	// 3. 重新读取注入图标后的新外壳数据
	newStubBase, err := os.ReadFile(tmpExe)
	if err != nil {
		return fmt.Errorf("读取注入图标后的外壳失败: %v", err)
	}

	// 4. 创建并准备写入最终输出文件
	file, err := os.OpenFile(outputExe, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("无法创建输出文件: %v", err)
	}
	defer file.Close()

	// 5. 写入带原程序图标的外壳 (Stub Base)
	if _, err := file.Write(newStubBase); err != nil {
		return fmt.Errorf("写入外壳基础数据失败: %v", err)
	}

	// 6. 🌟 核心修改：执行流式加密并直接落盘 (Zero-Copy 概念)
	origFile, err := os.Open(originalExe)
	if err != nil {
		return fmt.Errorf("无法打开原始程序进行加密: %v", err)
	}
	defer origFile.Close()

	// 使用 countingWriter 包装 file 句柄，拦截并统计流经的字节数
	cw := &countingWriter{w: file}
	if err := crypto.EncryptStream(origFile, cw, key); err != nil {
		return fmt.Errorf("流式加密处理失败: %v", err)
	}
	// 获取精准的密文总长度
	payloadSize := cw.n 

	// 7. 处理启动密码高级防御逻辑
	var verifyHash []byte
	var finalKey []byte

	if startupPwd == "" {
		verifyHash = make([]byte, 32)
		finalKey = key
	} else {
		hash := sha256.Sum256([]byte(startupPwd))
		hashOfHash := sha256.Sum256(hash[:])
		verifyHash = hashOfHash[:]

		finalKey = make([]byte, 32)
		for i := 0; i < 32; i++ {
			finalKey[i] = key[i] ^ hash[i]
		}
	}

	// 8. 处理退出密码逻辑
	var exitVerifyHash []byte
	if exitPwd == "" {
		exitVerifyHash = make([]byte, 32)
	} else {
		hash := sha256.Sum256([]byte(exitPwd))
		hashOfHash := sha256.Sum256(hash[:])
		exitVerifyHash = hashOfHash[:]
	}

	// 9. 依次写入尾部元数据
	if _, err := file.Write(verifyHash); err != nil {
		return fmt.Errorf("写入启动密码验证器失败: %v", err)
	}

	if _, err := file.Write(exitVerifyHash); err != nil {
		return fmt.Errorf("写入退出密码验证器失败: %v", err)
	}

	if len(finalKey) != 32 {
		return fmt.Errorf("密钥长度错误: 期望 32 字节，实际 %d 字节", len(finalKey))
	}
	if _, err := file.Write(finalKey); err != nil {
		return fmt.Errorf("写入加密密钥失败: %v", err)
	}

	remByte := []byte{0}
	if rememberPwd {
		remByte[0] = 1
	}
	if _, err := file.Write(remByte); err != nil {
		return fmt.Errorf("写入免密标志位失败: %v", err)
	}

	// 🌟 写入刚才通过 countingWriter 精准获取的动态 Payload 长度
	sizeBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(sizeBuf, payloadSize)
	if _, err := file.Write(sizeBuf); err != nil {
		return fmt.Errorf("写入长度元数据失败: %v", err)
	}

	magic := []byte("GOSHIELD")
	if _, err := file.Write(magic); err != nil {
		return fmt.Errorf("写入特征码失败: %v", err)
	}

	return file.Sync()
}
