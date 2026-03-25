// 文件路径: internal/compiler/icon.go
package compiler

import (
	"sync"
	"syscall"
	"unsafe"
)

var (
	kernel32                 = syscall.NewLazyDLL("kernel32.dll")
	procLoadLibraryExW       = kernel32.NewProc("LoadLibraryExW")
	procFreeLibrary          = kernel32.NewProc("FreeLibrary")
	procEnumResourceNamesW   = kernel32.NewProc("EnumResourceNamesW")
	procFindResourceW        = kernel32.NewProc("FindResourceW")
	procLoadResource         = kernel32.NewProc("LoadResource")
	procLockResource         = kernel32.NewProc("LockResource")
	procSizeofResource       = kernel32.NewProc("SizeofResource")
	procBeginUpdateResourceW = kernel32.NewProc("BeginUpdateResourceW")
	procUpdateResourceW      = kernel32.NewProc("UpdateResourceW")
	procEndUpdateResourceW   = kernel32.NewProc("EndUpdateResourceW")
)

const (
	LOAD_LIBRARY_AS_DATAFILE = 0x00000002
	RT_ICON                  = 3
	RT_GROUP_ICON            = 14
)

// 🌟 修复：提取为全局回调和状态变量，避免局部 syscall.NewCallback 导致的内存泄漏和超限 Panic
var (
	iconMu          sync.Mutex
	tempGroupIconId uintptr
	tempIconIds     []uintptr

	cbGroup = syscall.NewCallback(func(h, typ, name, param uintptr) uintptr {
		tempGroupIconId = name
		return 0 // 找到第一个组图标就停止遍历
	})

	cbIcon = syscall.NewCallback(func(h, typ, name, param uintptr) uintptr {
		tempIconIds = append(tempIconIds, name)
		return 1 // 继续遍历所有子图标
	})
)

// CloneIcon 利用 Windows 原生 API 从原程序提取图标并注入到临时外壳
func CloneIcon(srcPath, dstPath string) {
	// 🌟 修复：加锁保证并发安全，并重置全局状态
	iconMu.Lock()
	defer iconMu.Unlock()
	
	tempGroupIconId = 0
	tempIconIds = nil

	srcPtr, err := syscall.UTF16PtrFromString(srcPath)
	if err != nil {
		return
	}

	hModule, _, _ := procLoadLibraryExW.Call(uintptr(unsafe.Pointer(srcPtr)), 0, LOAD_LIBRARY_AS_DATAFILE)
	if hModule == 0 {
		return
	}
	defer procFreeLibrary.Call(hModule)

	// 1. 获取原程序的组图标 ID
	procEnumResourceNamesW.Call(hModule, uintptr(RT_GROUP_ICON), cbGroup, 0)

	if tempGroupIconId == 0 {
		return // 原程序如果没有图标则直接跳过
	}

	// 2. 获取所有的子图标数据 ID
	procEnumResourceNamesW.Call(hModule, uintptr(RT_ICON), cbIcon, 0)

	// 3. 开启对目标程序的资源写入句柄
	dstPtr, err := syscall.UTF16PtrFromString(dstPath)
	if err != nil {
		return
	}
	hUpdate, _, _ := procBeginUpdateResourceW.Call(uintptr(unsafe.Pointer(dstPtr)), 0)
	if hUpdate == 0 {
		return
	}

	// 4. 将提取出的图标组与子图标资源精确克隆进去
	copyRes(hModule, hUpdate, RT_GROUP_ICON, tempGroupIconId)
	for _, id := range tempIconIds {
		copyRes(hModule, hUpdate, RT_ICON, id)
	}

	// 5. 提交并保存更改 (参数为 0 代表保存修改)
	procEndUpdateResourceW.Call(hUpdate, 0)
}

func copyRes(hModule, hUpdate, resType, resId uintptr) {
	hRes, _, _ := procFindResourceW.Call(hModule, resId, resType)
	if hRes == 0 {
		return
	}
	hLoad, _, _ := procLoadResource.Call(hModule, hRes)
	if hLoad == 0 {
		return
	}
	ptr, _, _ := procLockResource.Call(hLoad)
	size, _, _ := procSizeofResource.Call(hModule, hRes)

	if ptr != 0 && size != 0 {
		// 🌟 修复：语言 ID 替换为 0 (LANG_NEUTRAL)，彻底解决中文系统或中立资源引起的白图标、乱码失效问题
		procUpdateResourceW.Call(hUpdate, resType, resId, 0, ptr, size)
	}
}
