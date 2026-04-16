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
	var inTE, outTE, pwdTE, confirmPwdTE *walk.LineEdit
	var exitPwdTE, confirmExitPwdTE *walk.LineEdit
	var rememberCB *walk.CheckBox
	var logTE *walk.TextEdit
	var pb *walk.ProgressBar
	var runBtn *walk.PushButton

	err := MainWindow{
		AssignTo: &mw,
		Title:    "GoShield - 流式加密版", // 🌟 彰显底层架构升级
		MinSize:  Size{Width: 300, Height: 380},
		Size:     Size{Width: 600, Height: 380},
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

					Label{Text: "启动密码:"},
					LineEdit{AssignTo: &pwdTE, PasswordMode: true},
					CheckBox{
						AssignTo: &rememberCB, 
						Text: "免密缓存",
						Checked: true, 
					},

					Label{Text: "确认启动:"},
					LineEdit{AssignTo: &confirmPwdTE, PasswordMode: true},
					Label{Text: "(留空则无启动密码)"},

					Label{Text: "程序锁密码:"},
					LineEdit{AssignTo: &exitPwdTE, PasswordMode: true},
					Label{Text: "拦截所有外部结束/退出操作"},

					Label{Text: "确认程序锁:"},
					LineEdit{AssignTo: &confirmExitPwdTE, PasswordMode: true},
					Label{Text: "(留空则无程序锁)"},
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
					password := pwdTE.Text()
					confirmPassword := confirmPwdTE.Text()
					exitPassword := exitPwdTE.Text()
					confirmExitPassword := confirmExitPwdTE.Text()
					rememberPwd := rememberCB.Checked()

					if inFile == "" || outFile == "" {
						walk.MsgBox(mw, "错误", "请先选择输入和输出文件路径！", walk.MsgBoxIconError)
						return
					}

					if password != confirmPassword {
						walk.MsgBox(mw, "错误", "两次输入的启动密码不一致，请重新输入！", walk.MsgBoxIconError)
						pwdTE.SetText("")
						confirmPwdTE.SetText("")
						return
					}

					if exitPassword != confirmExitPassword {
						walk.MsgBox(mw, "错误", "两次输入的程序锁密码不一致，请重新输入！", walk.MsgBoxIconError)
						exitPwdTE.SetText("")
						confirmExitPwdTE.SetText("")
						return
					}

					_, err := os.Stat(inFile)
					if err != nil {
						walk.MsgBox(mw, "错误", "无法读取输入文件状态！", walk.MsgBoxIconError)
						return
					}
					
					// 🌟 核心优化：删除了 fileInfo.Size() > 500MB 的拦截！
					// 得益于流式加密，现在可以无限制处理任何大小的文件。

					runBtn.SetEnabled(false)
					logTE.SetText("")
					pb.SetValue(0)

					go func() {
						defer mw.Synchronize(func() { runBtn.SetEnabled(true) })

						appendLog(logTE, "[*] 动态生成 256-bit AES 混淆密钥...")
						mw.Synchronize(func() { pb.SetValue(20) })
						key, err := crypto.GenerateRandomKey()
						if err != nil {
							appendLog(logTE, fmt.Sprintf("[-] 失败: %v", err))
							mw.Synchronize(func() { pb.SetValue(0) })
							return
						}

						// 🌟 核心优化：删除了读入整个文件到内存和全量加密的步骤
						appendLog(logTE, "[*] 正在执行无损图标注入与流式 AES-GCM 核心加密引擎...")
						mw.Synchronize(func() { pb.SetValue(50) })
						
						// 将原始文件路径直接丢给底层，进行边读、边加密、边写的 Zero-Copy 操作
						err = compiler.BuildProtectedExe(inFile, key, password, exitPassword, rememberPwd, outFile)
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

	mw.Run()
}
