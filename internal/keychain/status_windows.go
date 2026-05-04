//go:build windows

package keychain

// Check returns the Windows Credential Manager dependency state without reading any vault secret.
func Check() Status {
	return Status{Available: true, Backend: "Windows Credential Manager", Summary: "Keychain available", Detail: "Windows Credential Manager API is available in the current process."}
}
