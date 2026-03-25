// 文件路径: cmd/builder/main.go
package main

import (
	"fmt"
	"os"

	"github.com/Limkon/GoShield/internal/compiler"
	"github.com/Limkon/GoShield/internal/crypto"
	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative" // 引入声明式 UI 语法
)

// appendLog 线程安全地向文本框中追加日志
func appendLog(logTE *walk.TextEdit, msg string) {
	logTE.Synchronize(func() {
		logTE.AppendText(msg + "\r\n")
	})
}

func main() {
	var mw *walk.MainWindow
	var inTE, outTE, pwdTE *walk.LineEdit // 🌟 新增：密码输入框变量
	var logTE *walk.TextEdit
	var pb *walk.ProgressBar
	var runBtn *walk.PushButton

	err := MainWindow{
		AssignTo: &mw,
		Title:    "GoShield - 终极 EXE 保护加壳系统",
		MinSize:  Size{Width: 550, Height: 450}, // 稍微增高一点以适应新行
		Layout:   VBox{},
		Children: []Widget{
			GroupBox{
				Title:  "目标文件配置",
				Layout: Grid{Columns: 3},
				Children: []Widget{
					Label{Text: "原始程序:"},
					LineEdit{AssignTo: &inTE, ReadOnly: true},
					PushButton{
						Text: "浏览...",
						OnClicked: func() {
							dlg := new(walk.FileDialog)
							dlg.Filter = "可执行文件 (*.exe)|*.exe|所有文件 (*.*)|*.*"
							dlg.Title = "选择需要加壳保护的 EXE"
							if ok, _ := dlg.ShowOpen(mw); ok {
								inTE.SetText(dlg.FilePath)
								outTE.SetText(dlg.FilePath[:len(dlg.FilePath)-4] + "_protected.exe")
							}
						},
					},

					Label{Text: "输出路径:"},
					LineEdit{AssignTo: &outTE},
					PushButton{
						Text: "浏览...",
						OnClicked: func() {
							dlg := new(walk.FileDialog)
							dlg.Filter = "可执行文件 (*.exe)|*.exe"
							dlg.Title = "保存保护后的 EXE"
							if ok, _ := dlg.ShowSave(mw); ok {
								outTE.SetText(dlg.FilePath)
							}
						},
					},

					// 🌟 新增：密码输入行
					Label{Text: "启动密码:"},
					LineEdit{AssignTo: &pwdTE, PasswordMode: true}, // PasswordMode 隐藏输入字符
					Label{Text: "(可选，留空则无密码保护)"},
				},
			},
			Label{Text: "加壳与混淆进度:"},
			ProgressBar{
				AssignTo: &pb,
				MinValue: 0,
				MaxValue: 100,
			},
			TextEdit{
				AssignTo: &logTE,
				ReadOnly: true,
				VScroll:  true,
			},
			PushButton{
				AssignTo: &runBtn,
				Text:     "⚡ 开始加壳保护",
				OnClicked: func() {
					inFile := inTE.Text()
					outFile := outTE.Text()
					password := pwdTE.Text() // 🌟 获取用户填写的密码

					if inFile == "" || outFile == "" {
						walk.MsgBox(mw, "错误", "请先选择输入和输出文件路径！", walk.MsgBoxIconError)
						return
					}

					fileInfo, err := os.Stat(inFile)
					if err != nil {
						walk.MsgBox(mw, "错误", "无法读取输入文件状态！", walk.MsgBoxIconError)
						return
					}
					if fileInfo.Size() > 500*1024*1024 { // 限制最大 500MB
						walk.MsgBox(mw, "警告", "目标文件过大（超过 500MB），一次性载入内存可能导致崩溃，请重新选择！", walk.MsgBoxIconWarning)
						return
					}

					// 禁用按钮并重置状态 (在主线程执行，安全)
					runBtn.SetEnabled(false)
					logTE.SetText("")
					pb.SetValue(0)

					// 开启后台协程处理加壳逻辑，防止阻塞 UI 线程
					go func() {
						defer mw.Synchronize(func() { runBtn.SetEnabled(true) })

						appendLog(logTE, "[*] 读取原始可执行文件...")
						mw.Synchronize(func() { pb.SetValue(10) })
						plaintext, err := os.ReadFile(inFile)
						if err != nil {
							appendLog(logTE, fmt.Sprintf("[-] 失败: %v", err))
							mw.Synchronize(func() { pb.SetValue(0) }) // 发生错误重置进度
							return
						}

						appendLog(logTE, "[*] 动态生成 256-bit AES 混淆密钥...")
						mw.Synchronize(func() { pb.SetValue(30) })
						key, err := crypto.GenerateRandomKey()
						if err != nil {
							appendLog(logTE, fmt.Sprintf("[-] 失败: %v", err))
							mw.Synchronize(func() { pb.SetValue(0) })
							return
						}

						appendLog(logTE, "[*] 执行 AES-GCM 高级加密引擎...")
						mw.Synchronize(func() { pb.SetValue(50) })
						ciphertext, err := crypto.Encrypt(plaintext, key)
						if err != nil {
							appendLog(logTE, fmt.Sprintf("[-] 失败: %v", err))
							mw.Synchronize(func() { pb.SetValue(0) })
							return
						}

						appendLog(logTE, "[*] 正在执行无损图标注入与预编译壳拼接...")
						mw.Synchronize(func() { pb.SetValue(70) })
						
						// 🌟 核心修改点：传入 password 参数
						err = compiler.BuildProtectedExe(inFile, ciphertext, key, password, outFile)
						if err != nil {
							appendLog(logTE, fmt.Sprintf("[-] 编译失败: %v", err))
							mw.Synchronize(func() { pb.SetValue(0) })
							return
						}

						mw.Synchronize(func() { pb.SetValue(100) })
						appendLog(logTE, fmt.Sprintf("[+] 加壳成功！\r\n[+] 带壳程序已安全保存至: %s", outFile))
						
						mw.Synchronize(func() {
							walk.MsgBox(mw, "成功", "程序加壳与底层保护植入完成！\n原程序图标已完美继承，您可以测试运行了。", walk.MsgBoxIconInformation)
						})
					}()
				},
			},
		},
	}.Create()

	if err != nil {
		os.Exit(1)
	}

	// 启动 UI 消息循环
	mw.Run()
}
