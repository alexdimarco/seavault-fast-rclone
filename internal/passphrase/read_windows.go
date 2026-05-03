//go:build windows

package passphrase

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

const enableEchoInput = 0x0004

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procGetStdHandle   = kernel32.NewProc("GetStdHandle")
	procGetConsoleMode = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode = kernel32.NewProc("SetConsoleMode")
)

func Read(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	handle, _, _ := procGetStdHandle.Call(uintptr(^uint32(10) + 1)) // STD_INPUT_HANDLE
	var oldMode uint32
	ok := false
	if handle != 0 && handle != uintptr(syscall.InvalidHandle) {
		ret, _, _ := procGetConsoleMode.Call(handle, uintptr(unsafe.Pointer(&oldMode)))
		if ret != 0 {
			newMode := oldMode &^ enableEchoInput
			procSetConsoleMode.Call(handle, uintptr(newMode))
			ok = true
		}
	}
	defer func() {
		if ok {
			procSetConsoleMode.Call(handle, uintptr(oldMode))
		}
		fmt.Fprintln(os.Stderr)
	}()
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return "", err
	}
	password := strings.TrimRight(line, "\r\n")
	if password == "" {
		return "", fmt.Errorf("password must not be empty")
	}
	return password, nil
}
