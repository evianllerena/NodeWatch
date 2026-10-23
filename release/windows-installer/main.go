//go:build windows

// NodeWatch Setup: installs NodeWatch for the current Windows account (no administrator rights).
//
// Rebuilt from source (v0.10.49) to behave like the shipped v0.10.42 installer, whose behaviour was recorded on a
// clean Windows machine (.github/workflows/installer-parity.yml): the same wizard pages and texts, the same silent
// switch (/S), the same "already installed — open it now?" question, the same files, shortcuts and Settings › Apps
// entry, and an uninstaller ("Uninstall NodeWatch.exe /uninstall [/S]"). The payload (NodeWatch/NodeWatch.exe and
// NodeWatch/_internal/**) is embedded at build time by tools/build_release.py.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

const (
	appName     = "NodeWatch"
	publisher   = "BWN"
	appVersion  = "0.10.42" // stamped by tools/build_release.py
	tagline     = "Network Operations Portal"
	uninstaller = "Uninstall NodeWatch.exe"
)

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	gdi32    = syscall.NewLazyDLL("gdi32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")
	ole32    = syscall.NewLazyDLL("ole32.dll")

	procMessageBoxW          = user32.NewProc("MessageBoxW")
	procRegisterClassExW     = user32.NewProc("RegisterClassExW")
	procCreateWindowExW      = user32.NewProc("CreateWindowExW")
	procDefWindowProcW       = user32.NewProc("DefWindowProcW")
	procGetMessageW          = user32.NewProc("GetMessageW")
	procTranslateMessage     = user32.NewProc("TranslateMessage")
	procDispatchMessageW     = user32.NewProc("DispatchMessageW")
	procIsDialogMessageW     = user32.NewProc("IsDialogMessageW")
	procPostQuitMessage      = user32.NewProc("PostQuitMessage")
	procPostMessageW         = user32.NewProc("PostMessageW")
	procSendMessageW         = user32.NewProc("SendMessageW")
	procShowWindow           = user32.NewProc("ShowWindow")
	procUpdateWindow         = user32.NewProc("UpdateWindow")
	procDestroyWindow        = user32.NewProc("DestroyWindow")
	procEnableWindow         = user32.NewProc("EnableWindow")
	procSetWindowTextW       = user32.NewProc("SetWindowTextW")
	procGetWindowTextW       = user32.NewProc("GetWindowTextW")
	procGetWindowTextLengthW = user32.NewProc("GetWindowTextLengthW")
	procGetSystemMetrics     = user32.NewProc("GetSystemMetrics")
	procLoadCursorW          = user32.NewProc("LoadCursorW")
	procLoadIconW            = user32.NewProc("LoadIconW")
	procGetSysColorBrush     = user32.NewProc("GetSysColorBrush")
	procSetFocus             = user32.NewProc("SetFocus")
	procGetModuleHandleW     = kernel32.NewProc("GetModuleHandleW")
	procCreateFontW          = gdi32.NewProc("CreateFontW")
	procSHBrowseForFolderW   = shell32.NewProc("SHBrowseForFolderW")
	procSHGetPathFromIDListW = shell32.NewProc("SHGetPathFromIDListW")
	procCoTaskMemFree        = ole32.NewProc("CoTaskMemFree")
	procCoInitializeEx       = ole32.NewProc("CoInitializeEx")
)

const (
	wsOverlapped  = 0x00000000
	wsCaption     = 0x00C00000
	wsSysMenu     = 0x00080000
	wsMinimizeBox = 0x00020000
	wsChild       = 0x40000000
	wsVisible     = 0x10000000
	wsTabStop     = 0x00010000
	wsBorder      = 0x00800000
	wsExClientEdg = 0x00000200
	bsPushButton  = 0x0
	bsDefPushBtn  = 0x1
	bsAutoCheck   = 0x3
	esAutoHScroll = 0x80
	wmDestroy     = 0x0002
	wmClose       = 0x0010
	wmCommand     = 0x0111
	wmSetFont     = 0x0030
	wmApp         = 0x8000
	bmGetCheck    = 0x00F0
	bmSetCheck    = 0x00F1
	mbOK          = 0x0
	mbYesNo       = 0x4
	mbIconError   = 0x10
	mbIconQuest   = 0x20
	mbIconWarn    = 0x30
	mbIconInfo    = 0x40
	idYes         = 6
)

// Control ids.
const (
	idBack = 100 + iota
	idNext
	idCancel
	idBrowse
	idDesktop
	idStartNow
)

type point struct{ X, Y int32 }

type msg struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
}

type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   uintptr
	Icon       uintptr
	Cursor     uintptr
	Background uintptr
	MenuName   *uint16
	ClassName  *uint16
	IconSm     uintptr
}

func utf16(s string) *uint16 { p, _ := syscall.UTF16PtrFromString(s); return p }

func messageBox(owner uintptr, title, text string, flags uintptr) uintptr {
	r, _, _ := procMessageBoxW.Call(owner, uintptr(unsafe.Pointer(utf16(text))), uintptr(unsafe.Pointer(utf16(title))), flags)
	return r
}

func setText(h uintptr, s string) { procSetWindowTextW.Call(h, uintptr(unsafe.Pointer(utf16(s)))) }

func getText(h uintptr) string {
	n, _, _ := procGetWindowTextLengthW.Call(h)
	buf := make([]uint16, n+1)
	procGetWindowTextW.Call(h, uintptr(unsafe.Pointer(&buf[0])), n+1)
	return syscall.UTF16ToString(buf)
}

func main() {
	args := os.Args[1:]
	has := func(flag string) bool {
		for _, a := range args {
			if strings.EqualFold(a, flag) {
				return true
			}
		}
		return false
	}
	silent := has("/S")
	switch {
	case has("/uninstall"):
		os.Exit(runUninstall(silent))
	case silent:
		os.Exit(runSilentInstall())
	default:
		runInteractive()
	}
}

func title() string { return fmt.Sprintf("%s %s Setup", appName, appVersion) }

// ---------------------------------------------------------------------------------------------- the wizard

type wizard struct {
	hwnd     uintptr
	font     uintptr
	bold     uintptr
	big      uintptr
	page     int // 0 welcome, 1 location, 2 installing, 3 done
	controls []uintptr
	back     uintptr
	next     uintptr
	cancel   uintptr
	dirEdit  uintptr
	desktop  uintptr
	startNow uintptr
	status   uintptr
	dir      string
	finalDir string
	err      error
	mu       sync.Mutex
}

var wiz = &wizard{}

func runInteractive() {
	runtime.LockOSThread()
	if loc := installedLocation(); loc != "" && installedValue("DisplayVersion") == appVersion && looksLikeNodeWatch(loc) {
		text := fmt.Sprintf("%s %s is already installed.\n\nOpen it now?\n\n(Choose No to install it again.)", appName, appVersion)
		if messageBox(0, appName, text, mbYesNo|mbIconQuest) == idYes {
			_ = startDetached(filepath.Join(loc, "NodeWatch.exe"), loc)
			return
		}
	}
	wiz.dir = defaultInstallDir()
	procCoInitializeEx.Call(0, 0x2) // apartment threaded, for the folder picker
	wiz.run()
}

func (w *wizard) run() {
	inst, _, _ := procGetModuleHandleW.Call(0)
	cursor, _, _ := procLoadCursorW.Call(0, 32512)
	icon, _, _ := procLoadIconW.Call(inst, 1) // the resource icon (go-winres puts the app icon first)
	brush, _, _ := procGetSysColorBrush.Call(15)
	wc := wndClassEx{
		WndProc: syscall.NewCallback(wndProc), Instance: inst, Cursor: cursor, Icon: icon, IconSm: icon,
		Background: brush, ClassName: utf16("NodeWatchSetup"),
	}
	wc.Size = uint32(unsafe.Sizeof(wc))
	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	w.font = makeFont(-12, 400)
	w.bold = makeFont(-16, 700)
	w.big = makeFont(-22, 700)
	width, height := uintptr(560), uintptr(400)
	sw, _, _ := procGetSystemMetrics.Call(0)
	sh, _, _ := procGetSystemMetrics.Call(1)
	w.hwnd, _, _ = procCreateWindowExW.Call(0, uintptr(unsafe.Pointer(utf16("NodeWatchSetup"))),
		uintptr(unsafe.Pointer(utf16(title()))), wsOverlapped|wsCaption|wsSysMenu|wsMinimizeBox,
		(sw-width)/2, (sh-height)/2, width, height, 0, 0, inst, 0)
	// The product panel on the left and the buttons stay on every page.
	w.label(18, 30, 150, 120, fmt.Sprintf("%s\n%s\n\nVersion %s", appName, tagline, appVersion), w.bold, true)
	w.back = w.button(idBack, 250, 320, 85, 28, "< Back", false)
	w.next = w.button(idNext, 340, 320, 85, 28, "Next >", true)
	w.cancel = w.button(idCancel, 440, 320, 85, 28, "Cancel", false)
	w.showPage(0)
	procShowWindow.Call(w.hwnd, 5)
	procUpdateWindow.Call(w.hwnd)
	var m msg
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		if d, _, _ := procIsDialogMessageW.Call(w.hwnd, uintptr(unsafe.Pointer(&m))); d != 0 {
			continue
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}

func makeFont(height int32, weight int32) uintptr {
	f, _, _ := procCreateFontW.Call(uintptr(height), 0, 0, 0, uintptr(weight), 0, 0, 0, 1, 0, 0, 5, 0,
		uintptr(unsafe.Pointer(utf16("Segoe UI"))))
	return f
}

func (w *wizard) create(class, text string, style uintptr, x, y, cx, cy int, id int, font uintptr, exStyle uintptr) uintptr {
	h, _, _ := procCreateWindowExW.Call(exStyle, uintptr(unsafe.Pointer(utf16(class))), uintptr(unsafe.Pointer(utf16(text))),
		wsChild|wsVisible|style, uintptr(x), uintptr(y), uintptr(cx), uintptr(cy), w.hwnd, uintptr(id), 0, 0)
	if font == 0 {
		font = w.font
	}
	procSendMessageW.Call(h, wmSetFont, font, 1)
	return h
}

func (w *wizard) label(x, y, cx, cy int, text string, font uintptr, keep bool) uintptr {
	h := w.create("STATIC", text, 0, x, y, cx, cy, 0, font, 0)
	if !keep {
		w.controls = append(w.controls, h)
	}
	return h
}

func (w *wizard) button(id, x, y, cx, cy int, text string, def bool) uintptr {
	style := uintptr(bsPushButton | wsTabStop)
	if def {
		style = bsDefPushBtn | wsTabStop
	}
	return w.create("BUTTON", text, style, x, y, cx, cy, id, 0, 0)
}

func (w *wizard) clearPage() {
	for _, h := range w.controls {
		procDestroyWindow.Call(h)
	}
	w.controls = nil
}

func (w *wizard) pageControl(h uintptr) uintptr { w.controls = append(w.controls, h); return h }

func show(h uintptr, on bool) {
	if on {
		procShowWindow.Call(h, 5)
	} else {
		procShowWindow.Call(h, 0)
	}
}

func enable(h uintptr, on bool) {
	v := uintptr(0)
	if on {
		v = 1
	}
	procEnableWindow.Call(h, v)
}

func (w *wizard) showPage(p int) {
	w.clearPage()
	w.page = p
	x := 190
	switch p {
	case 0:
		w.label(x, 30, 340, 30, "Welcome to NodeWatch", w.big, false)
		text := fmt.Sprintf("This installs %s %s for your Windows account.\n\nNo administrator rights and no internet connection are needed, and nothing else has to be installed first.", appName, appVersion)
		if loc := installedLocation(); loc != "" && looksLikeNodeWatch(loc) {
			text += fmt.Sprintf("\n\nNodeWatch is already installed in\n%s\nIt will be updated; your settings and backups are kept.", loc)
		}
		text += "\n\nClick Next to continue."
		w.label(x, 75, 340, 220, text, 0, false)
		show(w.back, false)
		setText(w.next, "Next >")
		enable(w.next, true)
		show(w.cancel, true)
	case 1:
		w.label(x, 30, 340, 30, "Choose install location", w.big, false)
		w.label(x, 75, 340, 20, "Install NodeWatch in this folder:", 0, false)
		w.dirEdit = w.pageControl(w.create("EDIT", w.dir, esAutoHScroll|wsTabStop, x, 98, 255, 24, 0, 0, wsExClientEdg))
		w.pageControl(w.button(idBrowse, x+262, 97, 80, 26, "Browse…", false))
		w.desktop = w.pageControl(w.create("BUTTON", "Create a desktop shortcut", bsAutoCheck|wsTabStop, x, 132, 300, 22, idDesktop, 0, 0))
		procSendMessageW.Call(w.desktop, bmSetCheck, 1, 0)
		w.label(x, 165, 340, 140, fmt.Sprintf("Space needed: about %d MB.\n\nNodeWatch makes this folder private to your account (and administrators), so nobody else on this PC can change its files.\n\nYour settings, backups and logs are kept separately in your profile and survive updates.", spaceNeededMB()), 0, false)
		show(w.back, true)
		enable(w.back, true)
		setText(w.next, "Install")
		enable(w.next, true)
	case 2:
		w.label(x, 30, 340, 30, "Installing NodeWatch", w.big, false)
		w.status = w.label(x, 80, 340, 60, "Preparing…", 0, false)
		enable(w.back, false)
		enable(w.next, false)
		enable(w.cancel, false)
	case 3:
		w.label(x, 30, 340, 30, "NodeWatch is ready", w.big, false)
		w.label(x, 75, 340, 120, fmt.Sprintf("NodeWatch was installed in:\n%s\n\nStart it any time from the Start menu or the desktop shortcut. To remove it later, use Settings › Apps.", w.finalDir), 0, false)
		w.startNow = w.pageControl(w.create("BUTTON", "Start NodeWatch now", bsAutoCheck|wsTabStop, x, 205, 300, 22, idStartNow, 0, 0))
		procSendMessageW.Call(w.startNow, bmSetCheck, 1, 0)
		show(w.back, false)
		show(w.cancel, false)
		setText(w.next, "Finish")
		enable(w.next, true)
	}
	procSetFocus.Call(w.next)
}

func (w *wizard) setStatus(s string) { setText(w.status, s) }

func wndProc(hwnd uintptr, message uint32, wParam, lParam uintptr) uintptr {
	w := wiz
	switch message {
	case wmCommand:
		switch int(wParam & 0xFFFF) {
		case idCancel:
			w.askCancel()
		case idBack:
			if w.page == 1 {
				w.dir = getText(w.dirEdit)
				w.showPage(0)
			}
		case idBrowse:
			if dir := browseFolder(hwnd); dir != "" {
				setText(w.dirEdit, filepath.Join(dir, appName))
			}
		case idNext:
			switch w.page {
			case 0:
				w.showPage(1)
			case 1:
				w.dir = strings.TrimSpace(getText(w.dirEdit))
				desktop := checked(w.desktop)
				dir, ok := w.confirmDir(w.dir)
				if !ok {
					return 0
				}
				w.finalDir = dir
				w.showPage(2)
				go w.installInBackground(dir, desktop)
			case 3:
				if checked(w.startNow) {
					_ = startDetached(filepath.Join(w.finalDir, "NodeWatch.exe"), w.finalDir)
				}
				procDestroyWindow.Call(hwnd)
			}
		}
		return 0
	case wmApp: // install finished (wParam 1 = ok)
		if wParam == 1 {
			w.showPage(3)
		} else {
			messageBox(hwnd, title(), fmt.Sprintf("NodeWatch could not be installed:\n\n%v", w.err), mbOK|mbIconError)
			w.showPage(1)
		}
		return 0
	case wmClose:
		if w.page == 2 {
			return 0 // installing: wait for it to finish
		}
		if w.page == 3 {
			procDestroyWindow.Call(hwnd)
			return 0
		}
		w.askCancel()
		return 0
	case wmDestroy:
		procPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, uintptr(message), wParam, lParam)
	return r
}

func checked(h uintptr) bool { r, _, _ := procSendMessageW.Call(h, bmGetCheck, 0, 0); return r == 1 }

func (w *wizard) askCancel() {
	if messageBox(w.hwnd, title(), "Cancel NodeWatch setup? Nothing has been installed yet.", mbYesNo|mbIconQuest) == idYes {
		procDestroyWindow.Call(w.hwnd)
	}
}

func (w *wizard) confirmDir(dir string) (string, bool) {
	final, notice, err := resolveInstallDir(dir)
	if err != nil {
		messageBox(w.hwnd, title(), err.Error(), mbOK|mbIconWarn)
		return "", false
	}
	if notice != "" && messageBox(w.hwnd, title(), notice+"\n\nContinue?", mbYesNo|mbIconQuest) != idYes {
		return "", false
	}
	return final, true
}

func (w *wizard) installInBackground(dir string, desktop bool) {
	err := install(dir, desktop, func(s string) { w.setStatus(s) })
	w.err = err
	ok := uintptr(0)
	if err == nil {
		ok = 1
	}
	procPostMessageW.Call(w.hwnd, wmApp, ok, 0)
}

type browseInfo struct {
	Owner       uintptr
	Root        uintptr
	DisplayName *uint16
	Title       *uint16
	Flags       uint32
	Callback    uintptr
	LParam      uintptr
	Image       int32
}

func browseFolder(owner uintptr) string {
	name := make([]uint16, 260)
	bi := browseInfo{Owner: owner, DisplayName: &name[0],
		Title: utf16("Choose the folder to install NodeWatch in. A \"NodeWatch\" folder is created inside it."),
		Flags: 0x0001 | 0x0040} // BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE
	pidl, _, _ := procSHBrowseForFolderW.Call(uintptr(unsafe.Pointer(&bi)))
	if pidl == 0 {
		return ""
	}
	defer procCoTaskMemFree.Call(pidl)
	path := make([]uint16, 1024)
	if r, _, _ := procSHGetPathFromIDListW.Call(pidl, uintptr(unsafe.Pointer(&path[0]))); r == 0 {
		return ""
	}
	return syscall.UTF16ToString(path)
}
