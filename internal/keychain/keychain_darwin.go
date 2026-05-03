//go:build darwin

package keychain

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

func Get(account string) (string, error) {
	out, err := exec.Command("security", "find-generic-password", "-s", Service, "-a", account, "-w").Output()
	if err != nil {
		return "", fmt.Errorf("macOS Keychain lookup failed: %w", err)
	}
	return strings.TrimRight(string(out), "\r\n"), nil
}

func Set(account, secret string) error {
	cmd := exec.Command("security", "add-generic-password", "-U", "-s", Service, "-a", account, "-w", secret)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("macOS Keychain store failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func Delete(account string) error {
	cmd := exec.Command("security", "delete-generic-password", "-s", Service, "-a", account)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("macOS Keychain delete failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}
