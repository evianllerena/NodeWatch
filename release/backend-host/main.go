//go:build windows

// Command NodeWatchBackend runs the bundled CPython interpreter inside this
// process, so the NodeWatch backend shows in Task Manager as
// "NodeWatchBackend.exe" instead of "python.exe" (no version resource is
// embedded, so Task Manager shows the file name).
//
// Layout (python-build-standalone, staged by tools/stage_runtime.py):
//
//	_internal\runtime\NodeWatchBackend.exe   <- this program
//	_internal\runtime\python\python312.dll   <- loaded with LoadLibraryExW
//	_internal\runtime\python\Lib\, DLLs\     <- PYTHONHOME
//
// It behaves like python.exe: every argument is handed to Py_Main unchanged,
// and the exit code is Python's. The native launcher starts it with
// CREATE_NO_WINDOW, PYTHONHOME=<runtime\python> and
// PYTHONPATH=<venv>\Lib\site-packages;<_internal>, and falls back to the venv
// python.exe if this host is missing, cannot start, or exits before the
// launcher handshake.
//
// Build (no cgo; console subsystem):
//
//	cd release/backend_host
//	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o ../../runtime/NodeWatchBackend.exe main.go
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	pythonDirName = "python"
	pythonDLLName = "python312.dll"

	loadWithAlteredSearchPath = 0x00000008
	semFailCriticalErrors     = 0x0001
	semNoOpenFileErrorBox     = 0x8000

	// Exit codes used before Python starts (Python itself uses 0, 1, 2 and 120).
	exitHostSetupFailed = 121
)

var (
	kernel32             = syscall.NewLazyDLL("kernel32.dll")
	procLoadLibraryExW   = kernel32.NewProc("LoadLibraryExW")
	procSetDllDirectoryW = kernel32.NewProc("SetDllDirectoryW")
	procAddDllDirectory  = kernel32.NewProc("AddDllDirectory")
	procSetErrorMode     = kernel32.NewProc("SetErrorMode")
	keepAlive            [][]uint16 // UTF-16 buffers handed to CPython; must outlive Py_Main
	keepAliveArgv        []*uint16
)

func init() {
	// Py_Main runs on the main OS thread (the largest stack, like python.exe).
	runtime.LockOSThread()
}

func main() {
	os.Exit(run())
}

func fail(format string, args ...any) int {
	fmt.Fprintf(os.Stderr, "NodeWatchBackend: "+format+"\n", args...)
	return exitHostSetupFailed
}

func utf16Ptr(s string) (*uint16, error) {
	buf, err := syscall.UTF16FromString(s)
	if err != nil {
		return nil, err
	}
	keepAlive = append(keepAlive, buf)
	return &buf[0], nil
}

func run() int {
	exe, err := os.Executable()
	if err != nil {
		return fail("cannot locate own executable: %v", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	home := filepath.Join(filepath.Dir(exe), pythonDirName)
	dllPath := filepath.Join(home, pythonDLLName)
	if st, err := os.Stat(dllPath); err != nil || st.IsDir() {
		return fail("bundled interpreter not found: %s", dllPath)
	}

	// No "missing DLL" message boxes from a hidden background process.
	if procSetErrorMode.Find() == nil {
		procSetErrorMode.Call(semFailCriticalErrors | semNoOpenFileErrorBox)
	}

	// CPython reads these during initialisation. The launcher passes the same
	// values in the child environment; setting them here as well keeps a
	// manually started host consistent.
	_ = os.Setenv("PYTHONHOME", home)
	if os.Getenv("PYTHONNOUSERSITE") == "" {
		_ = os.Setenv("PYTHONNOUSERSITE", "1")
	}

	// Let python312.dll's dependencies (vcruntime140*.dll next to it) and the
	// extension modules' DLLs resolve from the bundled folder, not from this
	// executable's folder.
	homePtr, err := utf16Ptr(home)
	if err != nil {
		return fail("invalid interpreter path: %v", err)
	}
	if procSetDllDirectoryW.Find() == nil {
		procSetDllDirectoryW.Call(uintptr(unsafe.Pointer(homePtr)))
	}
	if procAddDllDirectory.Find() == nil {
		procAddDllDirectory.Call(uintptr(unsafe.Pointer(homePtr)))
	}

	dllPtr, err := utf16Ptr(dllPath)
	if err != nil {
		return fail("invalid interpreter path: %v", err)
	}
	h, _, callErr := procLoadLibraryExW.Call(uintptr(unsafe.Pointer(dllPtr)), 0, loadWithAlteredSearchPath)
	var dll *syscall.DLL
	if h != 0 {
		dll = &syscall.DLL{Name: dllPath, Handle: syscall.Handle(h)}
	} else {
		// Plain LoadLibrary as a second attempt (the DLL directory is set above).
		d, err := syscall.LoadDLL(dllPath)
		if err != nil {
			return fail("cannot load %s: %v / %v", dllPath, callErr, err)
		}
		dll = d
	}

	pyMain, err := dll.FindProc("Py_Main")
	if err != nil {
		return fail("Py_Main not exported by %s: %v", dllPath, err)
	}
	// Deprecated since 3.11 but still honoured by 3.12; harmless when PYTHONHOME
	// already says the same thing. Optional: absent in future versions.
	if setHome, err := dll.FindProc("Py_SetPythonHome"); err == nil {
		setHome.Call(uintptr(unsafe.Pointer(homePtr)))
	}

	// argv exactly as received (Go splits the command line with the same rules
	// as the MSVC runtime that python.exe uses).
	args := os.Args
	if len(args) == 0 {
		args = []string{exe}
	}
	keepAliveArgv = make([]*uint16, 0, len(args)+1)
	for _, a := range args {
		p, err := utf16Ptr(a)
		if err != nil {
			return fail("argument contains NUL: %q", a)
		}
		keepAliveArgv = append(keepAliveArgv, p)
	}
	keepAliveArgv = append(keepAliveArgv, nil) // argv[argc] == NULL, as in C

	rc, _, _ := pyMain.Call(uintptr(len(args)), uintptr(unsafe.Pointer(&keepAliveArgv[0])))
	runtime.KeepAlive(keepAlive)
	runtime.KeepAlive(keepAliveArgv)
	return int(int32(rc))
}
