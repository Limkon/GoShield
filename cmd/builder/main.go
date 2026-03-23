// 文件路径: cmd/builder/main.go
package main

import (
	"fmt"
	"os"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative" // 引入声明式 UI 语法
	"github.com/Limkon/GoShield/internal/compiler"
	"github.com/Limkon/GoShield/internal/crypto"
)

// appendLog 线程安全地向文本框中追加日志
func appendLog(logTE *walk.TextEdit, msg string) {
	logTE.Synchronize(func() {
		logTE.AppendText(msg + "\r\n")
	})
}

func main() {
	var mw *walk.MainWindow
	var inTE, outTE *walk.LineEdit
	var logTE *walk.TextEdit
	var pb *walk.ProgressBar
	var runBtn *walk.PushButton

	err := MainWindow{
		AssignTo: &mw,
		Title:    "GoShield - 终极 EXE 保护加壳系统",
		// 🌟 修改点：删除了 Icon: "app.ico", 这一行
		MinSize:  Size{Width: 550, Height: 400},
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

					if inFile == "" || outFile == "" {
						walk.MsgBox(mw, "错误", "请先选择输入和输出文件路径！", walk.MsgBoxIconError)
						return
					}

					// 禁用按钮并重置状态
					runBtn.SetEnabled(false)
					logTE.SetText("")
					pb.SetValue(0)

					// 开启后台协程处理加壳逻辑，防止阻塞 UI 线程
					go func() {
						defer mw.Synchronize(func() { runBtn.SetEnabled(true) })

						appendLog(logTE, "[*] 读取原始可执行文件...")
						mw.Synchronize(func() { pb.SetValue(20) })
						plaintext, err := os.ReadFile(inFile)
						if err != nil {
							appendLog(logTE, fmt.Sprintf("[-] 失败: %v", err))
							return
						}

						appendLog(logTE, "[*] 动态生成 256-bit AES 混淆密钥...")
						mw.Synchronize(func() { pb.SetValue(40) })
						key, err := crypto.GenerateRandomKey()
						if err != nil {
							appendLog(logTE, fmt.Sprintf("[-] 失败: %v", err))
							return
						}

						appendLog(logTE, "[*] 执行 AES-GCM 高级加密引擎...")
						mw.Synchronize(func() { pb.SetValue(60) })
						ciphertext, err := crypto.Encrypt(plaintext, key)
						if err != nil {
							appendLog(logTE, fmt.Sprintf("[-] 失败: %v", err))
							return
						}

						appendLog(logTE, "[*] 正在执行 Overlay 注入并拼装预编译防御壳 (极速)...")
						mw.Synchronize(func() { pb.SetValue(80) })
						
						err = compiler.BuildProtectedExe(ciphertext, key, outFile)
						if err != nil {
							appendLog(logTE, fmt.Sprintf("[-] 编译失败: %v", err))
							return
						}

						mw.Synchronize(func() { pb.SetValue(100) })
						appendLog(logTE, fmt.Sprintf("[+] 加壳成功！\r\n[+] 带壳程序已安全保存至: %s", outFile))
						
						mw.Synchronize(func() {
							walk.MsgBox(mw, "成功", "程序加壳与底层保护植入完成！\n您现在可以测试运行了。", walk.MsgBoxIconInformation)
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
