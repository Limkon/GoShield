// 文件路径: internal/compiler/icon.go
package compiler

import (
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

// CloneIcon 利用 Windows 原生 API 从原程序提取图标并注入到临时外壳
func CloneIcon(srcPath, dstPath string) {
	srcPtr, _ := syscall.UTF16PtrFromString(srcPath)
	hModule, _, _ := procLoadLibraryExW.Call(uintptr(unsafe.Pointer(srcPtr)), 0, LOAD_LIBRARY_AS_DATAFILE)
	if hModule == 0 {
		return
	}
	defer procFreeLibrary.Call(hModule)

	// 1. 获取原程序的组图标 ID
	var groupIconId uintptr
	cbGroup := syscall.NewCallback(func(h, typ, name, param uintptr) uintptr {
		groupIconId = name
		return 0 // 找到第一个组图标就停止遍历
	})
	procEnumResourceNamesW.Call(hModule, uintptr(RT_GROUP_ICON), cbGroup, 0)

	if groupIconId == 0 {
		return // 原程序如果没有图标则直接跳过
	}

	// 2. 获取所有的子图标数据 ID
	var iconIds []uintptr
	cbIcon := syscall.NewCallback(func(h, typ, name, param uintptr) uintptr {
		iconIds = append(iconIds, name)
		return 1 // 继续遍历所有子图标
	})
	procEnumResourceNamesW.Call(hModule, uintptr(RT_ICON), cbIcon, 0)

	// 3. 开启对目标程序的资源写入句柄
	dstPtr, _ := syscall.UTF16PtrFromString(dstPath)
	hUpdate, _, _ := procBeginUpdateResourceW.Call(uintptr(unsafe.Pointer(dstPtr)), 0)
	if hUpdate == 0 {
		return
	}

	// 4. 将提取出的图标组与子图标资源精确克隆进去
	copyRes(hModule, hUpdate, RT_GROUP_ICON, groupIconId)
	for _, id := range iconIds {
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
		// 1033 为通用英语语言 ID，防止部分系统乱码读取失败
		procUpdateResourceW.Call(hUpdate, resType, resId, 1033, ptr, size)
	}
}
