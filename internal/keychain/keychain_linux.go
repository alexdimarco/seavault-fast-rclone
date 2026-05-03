//go:build linux

package keychain

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

func Get(account string) (string, error) {
	out, err := exec.Command("secret-tool", "lookup", "service", Service, "vault-id", account).Output()
	if err != nil {
		return "", fmt.Errorf("Secret Service lookup failed; install libsecret-tools or use SEAVAULT_PASSWORD: %w", err)
	}
	secret := strings.TrimRight(string(out), "\r\n")
	if secret == "" {
		return "", fmt.Errorf("Secret Service returned an empty password")
	}
	return secret, nil
}

func Set(account, secret string) error {
	cmd := exec.Command("secret-tool", "store", "--label", "SeaVault "+account, "service", Service, "vault-id", account)
	cmd.Stdin = strings.NewReader(secret)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("Secret Service store failed; install libsecret-tools and unlock a desktop keyring: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func Delete(account string) error {
	cmd := exec.Command("secret-tool", "clear", "service", Service, "vault-id", account)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("Secret Service delete failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}
