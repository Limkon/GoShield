// 文件路径: internal/crypto/aesgcm.go
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// GenerateRandomKey 生成 32 字节 (256-bit) 的 AES 密钥
func GenerateRandomKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// Encrypt 使用 AES-GCM 加密数据
func Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesgcm.NonceSize()
	
	// 🌟 修复/优化：预分配精确的容量，避免 Seal 内部二次分配大内存，极大降低 OOM 风险和 GC 压力
	ciphertext := make([]byte, nonceSize, nonceSize+len(plaintext)+aesgcm.Overhead())
	
	// 填充随机 Nonce
	if _, err := io.ReadFull(rand.Reader, ciphertext[:nonceSize]); err != nil {
		return nil, err
	}

	// 结果直接安全追加到预分配的 ciphertext 容量内
	ciphertext = aesgcm.Seal(ciphertext, ciphertext[:nonceSize], plaintext, nil)
	return ciphertext, nil
}

// Decrypt 使用 AES-GCM 解密数据
func Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesgcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:nonceSize]
	actualCiphertext := ciphertext[nonceSize:]

	// 🌟 修复/优化：利用底层重叠复用内存，进行原地解密 (In-place Decryption)
	// 解密时不再申请等大的明文内存空间，大幅降低解密和加载期的内存峰值
	plaintext, err := aesgcm.Open(actualCiphertext[:0], nonce, actualCiphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
