//go:build windows

package main

import (
	"archive/zip"
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// The payload: NodeWatch/NodeWatch.exe and NodeWatch/_internal/** (written by tools/build_release.py).
//
//go:embed payload.zip
var payload []byte

const uninstallKey = `Software\Microsoft\Windows\CurrentVersion\Uninstall\NodeWatch`

var (
	advapi32                  = syscall.NewLazyDLL(systemPath("advapi32.dll"))
	procRegCreateKeyExW       = advapi32.NewProc("RegCreateKeyExW")
	procRegOpenKeyExW         = advapi32.NewProc("RegOpenKeyExW")
	procRegSetValueExW        = advapi32.NewProc("RegSetValueExW")
	procRegQueryValueExW      = advapi32.NewProc("RegQueryValueExW")
	procRegDeleteKeyW         = advapi32.NewProc("RegDeleteKeyW")
	procRegCloseKey           = advapi32.NewProc("RegCloseKey")
	procGetVolumeInformationW = kernel32.NewProc("GetVolumeInformationW")
)

const hkeyCurrentUser = uintptr(0x80000001)

func systemDir() string {
	buf := make([]uint16, 260)
	n, _, _ := kernel32.NewProc("GetSystemDirectoryW").Call(uintptr(unsafe.Pointer(&buf[0])), 260)
	if n == 0 {
		return `C:\Windows\System32`
	}
	return syscall.UTF16ToString(buf[:n])
}

func systemPath(name string) string { return filepath.Join(systemDir(), name) }

// ---------------------------------------------------------------------------------------------- registry

func regSet(values map[string]any) error {
	var key syscall.Handle
	if r, _, _ := procRegCreateKeyExW.Call(hkeyCurrentUser, uintptr(unsafe.Pointer(utf16(uninstallKey))), 0, 0, 0,
		0xF003F, 0, uintptr(unsafe.Pointer(&key)), 0); r != 0 {
		return fmt.Errorf("registry: %w", syscall.Errno(r))
	}
	defer procRegCloseKey.Call(uintptr(key))
	for name, value := range values {
		var r uintptr
		switch v := value.(type) {
		case string:
			data, _ := syscall.UTF16FromString(v)
			r, _, _ = procRegSetValueExW.Call(uintptr(key), uintptr(unsafe.Pointer(utf16(name))), 0, 1,
				uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)*2))
		case uint32:
			r, _, _ = procRegSetValueExW.Call(uintptr(key), uintptr(unsafe.Pointer(utf16(name))), 0, 4,
				uintptr(unsafe.Pointer(&v)), 4)
		}
		if r != 0 {
			return fmt.Errorf("registry value %s: %w", name, syscall.Errno(r))
		}
	}
	return nil
}

// installedValue reads a string value of the Settings › Apps entry ("" when there is none).
func installedValue(name string) string {
	var key syscall.Handle
	if r, _, _ := procRegOpenKeyExW.Call(hkeyCurrentUser, uintptr(unsafe.Pointer(utf16(uninstallKey))), 0, 0x20019,
		uintptr(unsafe.Pointer(&key))); r != 0 {
		return ""
	}
	defer procRegCloseKey.Call(uintptr(key))
	var typ, size uint32
	if r, _, _ := procRegQueryValueExW.Call(uintptr(key), uintptr(unsafe.Pointer(utf16(name))), 0,
		uintptr(unsafe.Pointer(&typ)), 0, uintptr(unsafe.Pointer(&size))); r != 0 || typ != 1 || size < 2 {
		return ""
	}
	buf := make([]uint16, size/2+1)
	if r, _, _ := procRegQueryValueExW.Call(uintptr(key), uintptr(unsafe.Pointer(utf16(name))), 0,
		uintptr(unsafe.Pointer(&typ)), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size))); r != 0 {
		return ""
	}
	return syscall.UTF16ToString(buf)
}

func installedLocation() string { return installedValue("InstallLocation") }

func unregisterUninstall() {
	procRegDeleteKeyW.Call(hkeyCurrentUser, uintptr(unsafe.Pointer(utf16(uninstallKey))))
}

func registerUninstall(dir string) error {
	uninst := filepath.Join(dir, uninstaller)
	return regSet(map[string]any{
		"DisplayName":          appName,
		"DisplayVersion":       appVersion,
		"Publisher":            publisher,
		"InstallLocation":      dir,
		"DisplayIcon":          uninst + ",0",
		"UninstallString":      `"` + uninst + `" /uninstall`,
		"QuietUninstallString": `"` + uninst + `" /uninstall /S`,
		"InstallDate":          time.Now().Format("20060102"),
		"NoModify":             uint32(1),
		"NoRepair":             uint32(1),
		"EstimatedSize":        uint32(payloadBytes() / 1024),
	})
}

// ---------------------------------------------------------------------------------------------- folders

func defaultInstallDir() string {
	if loc := installedLocation(); loc != "" && looksLikeNodeWatch(loc) {
		return loc
	}
	return filepath.Join(os.Getenv("LOCALAPPDATA"), "Programs", appName)
}

func dataDir() string { return filepath.Join(os.Getenv("LOCALAPPDATA"), appName) }

func looksLikeNodeWatch(dir string) bool {
	if st, err := os.Stat(filepath.Join(dir, "NodeWatch.exe")); err != nil || st.IsDir() {
		return false
	}
	st, err := os.Stat(filepath.Join(dir, "_internal", "integrity.json"))
	return err == nil && !st.IsDir()
}

func isEmptyDir(dir string) bool {
	entries, err := os.ReadDir(dir)
	return err == nil && len(entries) == 0
}

func within(child, parent string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func fileSystem(dir string) string {
	root := filepath.VolumeName(dir) + `\`
	name := make([]uint16, 64)
	r, _, _ := procGetVolumeInformationW.Call(uintptr(unsafe.Pointer(utf16(root))), 0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&name[0])), 64)
	if r == 0 {
		return ""
	}
	return syscall.UTF16ToString(name)
}

// resolveInstallDir checks a chosen folder. It returns the folder to use, and a notice when that is a subfolder.
func resolveInstallDir(dir string) (string, string, error) {
	dir = strings.TrimSpace(strings.Trim(dir, `"`))
	if dir == "" || !filepath.IsAbs(dir) || filepath.VolumeName(dir) == "" {
		return "", "", errors.New(`Enter a full folder path, for example C:\Users\you\AppData\Local\Programs\NodeWatch.`)
	}
	dir = filepath.Clean(dir)
	if strings.HasPrefix(dir, `\\`) {
		return "", "", errors.New("NodeWatch cannot be installed on a network share. Choose a folder on this PC.")
	}
	if dir == filepath.VolumeName(dir)+`\` {
		return "", "", errors.New(`Choose a folder, not a whole drive (for example add \NodeWatch to the path).`)
	}
	if fs := strings.ToUpper(fileSystem(dir)); strings.HasPrefix(fs, "FAT") || fs == "EXFAT" {
		return "", "", errors.New("This drive (FAT32/exFAT, for example a USB stick) cannot keep NodeWatch's files private, so NodeWatch would refuse to run from it. Choose a folder on your computer's main drive.")
	}
	if data := dataDir(); strings.EqualFold(dir, data) || within(dir, data) {
		return "", "", fmt.Errorf("%s\nThis is where NodeWatch keeps your settings and backups. Choose a different folder, for example %s", dir, filepath.Join(os.Getenv("LOCALAPPDATA"), "Programs", appName))
	}
	if self, err := os.Executable(); err == nil && within(self, dir) && !strings.EqualFold(filepath.Base(self), uninstaller) {
		return "", "", fmt.Errorf("setup is running from inside %s. Move this file (for example to Downloads) and run it again", dir)
	}
	st, err := os.Stat(dir)
	switch {
	case err != nil:
		return dir, "", nil
	case !st.IsDir():
		return "", "", fmt.Errorf("%s already contains other files. Choose an empty folder", dir)
	case isEmptyDir(dir) || looksLikeNodeWatch(dir):
		return dir, "", nil
	}
	sub := filepath.Join(dir, appName)
	if st, err := os.Stat(sub); err == nil && (!st.IsDir() || (!isEmptyDir(sub) && !looksLikeNodeWatch(sub))) {
		return "", "", fmt.Errorf("%s already contains other files. Choose an empty folder", sub)
	}
	return sub, fmt.Sprintf("%s already contains other files, so NodeWatch will be installed in its own subfolder:\n%s", dir, sub), nil
}

// ---------------------------------------------------------------------------------------------- payload

func payloadReader() (*zip.Reader, error) { return zip.NewReader(bytes.NewReader(payload), int64(len(payload))) }

func payloadBytes() uint64 {
	zr, err := payloadReader()
	if err != nil {
		return 0
	}
	var total uint64
	for _, f := range zr.File {
		total += f.UncompressedSize64
	}
	return total
}

func spaceNeededMB() uint64 { return (payloadBytes() + (1<<20 - 1)) >> 20 }

func extract(dest string) error {
	zr, err := payloadReader()
	if err != nil {
		return fmt.Errorf("the setup file is damaged: %w", err)
	}
	const prefix = "NodeWatch/"
	for _, f := range zr.File {
		if !strings.HasPrefix(f.Name, prefix) || strings.HasSuffix(f.Name, "/") {
			continue
		}
		rel := filepath.FromSlash(strings.TrimPrefix(f.Name, prefix))
		target := filepath.Join(dest, rel)
		if !within(target, dest) {
			return fmt.Errorf("the setup file is damaged (%s)", f.Name)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		src, err := f.Open()
		if err != nil {
			return fmt.Errorf("the setup file is damaged: %w", err)
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
		if err != nil {
			src.Close()
			return err
		}
		_, err = io.Copy(out, src)
		src.Close()
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return fmt.Errorf("copy %s: %w", rel, err)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------------------------- helpers

func powershell(script string, env ...string) error {
	cmd := exec.Command(filepath.Join(systemDir(), `WindowsPowerShell\v1.0\powershell.exe`),
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	cmd.Env = append(os.Environ(), env...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func startDetached(exe, dir string) error {
	cmd := exec.Command(exe)
	cmd.Dir = dir
	return cmd.Start()
}

// processesIn lists running programs started from inside dir (NodeWatch, its backend and its window).
func processesIn(dir string) []string {
	cmd := exec.Command(filepath.Join(systemDir(), `WindowsPowerShell\v1.0\powershell.exe`),
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
		`Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and $_.ProcessId -ne [int]$env:NW_SELF -and $_.ExecutablePath.StartsWith($env:NW_DIR + '\', 'OrdinalIgnoreCase') } | ForEach-Object { "$($_.ProcessId) $($_.Name)" }`)
	cmd.Env = append(os.Environ(), "NW_DIR="+dir, fmt.Sprintf("NW_SELF=%d", os.Getpid()))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	out, _ := cmd.Output()
	var rows []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			rows = append(rows, line)
		}
	}
	return rows
}

func stopProcessesIn(dir string) error {
	if len(processesIn(dir)) == 0 {
		return nil
	}
	_ = powershell(`Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($env:NW_DIR + '\', 'OrdinalIgnoreCase') } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }`, "NW_DIR="+dir)
	for i := 0; i < 20; i++ {
		if len(processesIn(dir)) == 0 {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("NodeWatch is still running: %s", strings.Join(processesIn(dir), ", "))
}

// makePrivate gives the folder to the current user, administrators and SYSTEM only (no inherited access).
func makePrivate(dir string) error {
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return fmt.Errorf("could not set folder permissions: %v", err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return fmt.Errorf("could not set folder permissions: %v", err)
	}
	sid, err := user.User.Sid.String()
	if err != nil {
		return fmt.Errorf("could not set folder permissions: %v", err)
	}
	// Set on the empty staging folder before anything is copied in, so every file inherits it.
	cmd := exec.Command(filepath.Join(systemDir(), "icacls.exe"), dir, "/inheritance:r", "/grant:r",
		"*"+sid+":(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F", "/C", "/Q")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("could not set folder permissions: %v %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func startMenuShortcut() string {
	return filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs`, appName+".lnk")
}

const shortcutScript = `$w = New-Object -ComObject WScript.Shell
$target = Join-Path $env:NW_DIR 'NodeWatch.exe'
$targets = @($env:NW_LNK)
if ($env:NW_DESKTOP -eq '1') { $targets += Join-Path ([Environment]::GetFolderPath('Desktop')) 'NodeWatch.lnk' }
foreach ($l in $targets) {
  $s = $w.CreateShortcut($l)
  $s.TargetPath = $target
  $s.WorkingDirectory = $env:NW_DIR
  $s.IconLocation = "$target,0"
  $s.Description = 'NodeWatch Network Operations Portal'
  $s.Save()
}`

const removeShortcutScript = `$w = New-Object -ComObject WScript.Shell
$target = Join-Path $env:NW_DIR 'NodeWatch.exe'
foreach ($l in @($env:NW_LNK, (Join-Path ([Environment]::GetFolderPath('Desktop')) 'NodeWatch.lnk'))) {
  if (Test-Path -LiteralPath $l) {
    if ($w.CreateShortcut($l).TargetPath -ieq $target) { Remove-Item -LiteralPath $l -Force -ErrorAction SilentlyContinue }
  }
}`

// ---------------------------------------------------------------------------------------------- install

func randomSuffix() string { return fmt.Sprintf("%x", time.Now().UnixNano()&0xFFFFFFF) }

func install(dir string, desktop bool, status func(string)) error {
	if status == nil {
		status = func(string) {}
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return err
	}
	suffix := randomSuffix()
	staging := dir + ".new-" + suffix
	_ = os.RemoveAll(staging)
	if err := os.Mkdir(staging, 0o755); err != nil {
		return err
	}
	status("Making the folder private…")
	if err := makePrivate(staging); err != nil {
		_ = os.RemoveAll(staging)
		return err
	}
	status("Copying files…")
	if err := extract(staging); err != nil {
		_ = os.RemoveAll(staging)
		return err
	}
	if err := copyFile(self, filepath.Join(staging, uninstaller)); err != nil {
		_ = os.RemoveAll(staging)
		return fmt.Errorf("add the uninstaller: %w", err)
	}
	if len(processesIn(dir)) > 0 {
		status("Closing the running NodeWatch…")
		if err := stopProcessesIn(dir); err != nil {
			_ = os.RemoveAll(staging)
			return err
		}
	}
	old := ""
	if _, err := os.Stat(dir); err == nil {
		old = dir + ".old-" + suffix
		if err := os.Rename(dir, old); err != nil {
			_ = os.RemoveAll(staging)
			return fmt.Errorf("the previous NodeWatch is still in use (%v). Close NodeWatch (and any window open on its folder) and try again", err)
		}
	}
	if err := os.Rename(staging, dir); err != nil {
		if old != "" {
			_ = os.Rename(old, dir)
		}
		_ = os.RemoveAll(staging)
		return err
	}
	status("Adding the uninstaller…")
	if err := registerUninstall(dir); err != nil {
		return err
	}
	status("Creating shortcuts…")
	flag := "0"
	if desktop {
		flag = "1"
	}
	if err := powershell(shortcutScript, "NW_DIR="+dir, "NW_LNK="+startMenuShortcut(), "NW_DESKTOP="+flag); err != nil {
		return fmt.Errorf("create shortcuts: %w", err)
	}
	if old != "" {
		_ = os.RemoveAll(old)
	}
	status("Done.")
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func runSilentInstall() int {
	dir, _, err := resolveInstallDir(defaultInstallDir())
	if err == nil {
		err = install(dir, true, nil)
	}
	if err != nil {
		_ = os.WriteFile(filepath.Join(os.TempDir(), "NodeWatch-setup.log"),
			[]byte(time.Now().Format(time.RFC3339)+" "+err.Error()+"\r\n"), 0o644)
		return 1
	}
	return 0
}

// ---------------------------------------------------------------------------------------------- uninstall

func runUninstall(silent bool) int {
	self, err := os.Executable()
	if err != nil {
		return 1
	}
	dir := filepath.Dir(self)
	say := func(text string, flags uintptr) {
		if !silent {
			messageBox(0, appName, text, flags)
		}
	}
	if !looksLikeNodeWatch(dir) {
		say(fmt.Sprintf("%s does not look like a NodeWatch folder; nothing was removed.", dir), mbOK|mbIconError)
		return 1
	}
	if len(processesIn(dir)) > 0 {
		say(`Close NodeWatch, then run "Uninstall NodeWatch.exe" in that folder again.`, mbOK|mbIconWarn)
		return 1
	}
	deleteData := false
	if !silent {
		deleteData = messageBox(0, appName, "Also delete your NodeWatch settings, saved configuration backups and logs?\n\nChoose No to keep them for a later reinstall. Saved passwords and API tokens stay in Windows Credential Manager either way.", mbYesNo|mbIconQuest) == idYes
	}
	_ = powershell(removeShortcutScript, "NW_DIR="+dir, "NW_LNK="+startMenuShortcut())
	if strings.EqualFold(filepath.Clean(installedLocation()), filepath.Clean(dir)) {
		unregisterUninstall()
	}
	_ = os.RemoveAll(filepath.Join(dir, "_internal"))
	_ = os.Remove(filepath.Join(dir, "NodeWatch.exe"))
	if deleteData {
		_ = os.RemoveAll(dataDir())
	}
	// This program cannot delete itself while it runs: a hidden command removes it and the empty folder after it exits.
	shell := filepath.Join(systemDir(), "cmd.exe")
	cmd := exec.Command(shell)
	cmd.Dir = os.TempDir()
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000,
		CmdLine: `"` + shell + `" /c "ping -n 3 127.0.0.1 > nul & del /f /q "` + self + `" & rmdir "` + dir + `""`}
	_ = cmd.Start()
	return 0
}
