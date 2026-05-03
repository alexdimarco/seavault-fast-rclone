package rsyncput

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/example/seavault-fast/internal/userpath"
	"github.com/example/seavault-fast/internal/vault"
)

const (
	MethodAuto   = "auto"
	MethodRsync  = "rsync"
	MethodNative = "native"
)

type Options struct {
	Method      string
	RsyncBinary string
	KeepStaging bool
}

type Result struct {
	Method      string            `json:"method"`
	RsyncBinary string            `json:"rsyncBinary,omitempty"`
	RsyncOutput string            `json:"rsyncOutput,omitempty"`
	Results     []vault.PutResult `json:"results"`
}

type Status struct {
	Available bool   `json:"available"`
	Binary    string `json:"binary,omitempty"`
	Version   string `json:"version,omitempty"`
	Error     string `json:"error,omitempty"`
}

func Inspect(ctx context.Context, binary string) Status {
	bin, err := resolveBinary(binary)
	if err != nil {
		return Status{Available: false, Error: err.Error()}
	}
	out, err := exec.CommandContext(ctx, bin, "--version").CombinedOutput()
	if err != nil {
		return Status{Available: false, Binary: bin, Error: strings.TrimSpace(string(out))}
	}
	return Status{Available: true, Binary: bin, Version: firstLine(string(out))}
}

func PutPath(ctx context.Context, v *vault.Vault, sourcePath string, virtualPath string, opts Options) (Result, error) {
	method := strings.ToLower(strings.TrimSpace(opts.Method))
	if method == "" {
		method = MethodAuto
	}
	switch method {
	case MethodNative:
		results, err := v.PutPath(sourcePath, virtualPath)
		return Result{Method: MethodNative, Results: results}, err
	case MethodRsync:
		return putViaRsync(ctx, v, sourcePath, virtualPath, opts)
	case MethodAuto:
		if _, err := resolveBinary(opts.RsyncBinary); err != nil {
			results, putErr := v.PutPath(sourcePath, virtualPath)
			return Result{Method: MethodNative, Results: results}, putErr
		}
		return putViaRsync(ctx, v, sourcePath, virtualPath, opts)
	default:
		return Result{}, fmt.Errorf("unsupported put method %q; use auto, rsync, or native", opts.Method)
	}
}

func putViaRsync(ctx context.Context, v *vault.Vault, sourcePath string, virtualPath string, opts Options) (Result, error) {
	bin, err := resolveBinary(opts.RsyncBinary)
	if err != nil {
		return Result{}, err
	}
	src, err := userpath.Abs(sourcePath)
	if err != nil {
		return Result{}, err
	}
	info, err := os.Stat(src)
	if err != nil {
		return Result{}, err
	}
	if err := rejectMetadataSource(v.Root, src); err != nil {
		return Result{}, err
	}
	tmp, err := os.MkdirTemp("", "seavault-rsync-put-*")
	if err != nil {
		return Result{}, err
	}
	if !opts.KeepStaging {
		defer os.RemoveAll(tmp)
	}

	args := []string{
		"-a",
		"--exclude", vault.MetadataDirName + "/",
		"--exclude", ".git/",
		src,
		tmp + string(os.PathSeparator),
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	outBytes, err := cmd.CombinedOutput()
	out := strings.TrimSpace(string(outBytes))
	if err != nil {
		return Result{Method: MethodRsync, RsyncBinary: bin, RsyncOutput: out}, fmt.Errorf("rsync staging failed: %w: %s", err, out)
	}

	staged := filepath.Join(tmp, filepath.Base(src))
	if _, err := os.Stat(staged); err != nil {
		// Some rsync builds treat a file destination differently. This keeps the
		// failure explicit rather than falling back to native ingest after a partial
		// staging run.
		kind := "file"
		if info.IsDir() {
			kind = "directory"
		}
		return Result{Method: MethodRsync, RsyncBinary: bin, RsyncOutput: out}, fmt.Errorf("rsync staged %s was not found at %s", kind, staged)
	}
	results, err := v.PutPath(staged, virtualPath)
	return Result{Method: MethodRsync, RsyncBinary: bin, RsyncOutput: out, Results: results}, err
}

func resolveBinary(binary string) (string, error) {
	binary = strings.TrimSpace(binary)
	if binary == "" {
		binary = "rsync"
	}
	if strings.ContainsAny(binary, `/\\`) {
		abs, err := userpath.Abs(binary)
		if err != nil {
			return "", err
		}
		if st, err := os.Stat(abs); err != nil {
			return "", err
		} else if st.IsDir() {
			return "", fmt.Errorf("rsync binary path %q is a directory", abs)
		}
		return abs, nil
	}
	p, err := exec.LookPath(binary)
	if err != nil {
		return "", fmt.Errorf("rsync was not found; install rsync or use --method native")
	}
	return p, nil
}

func rejectMetadataSource(vaultRoot, src string) error {
	root, err := userpath.Abs(vaultRoot)
	if err != nil {
		return err
	}
	meta := filepath.Join(root, vault.MetadataDirName)
	rootRel, err := filepath.Rel(meta, src)
	if err == nil && rootRel != ".." && !strings.HasPrefix(rootRel, ".."+string(os.PathSeparator)) {
		return errors.New("refusing to put files from inside the encrypted .seavault metadata directory")
	}
	return nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		return s[:i]
	}
	return s
}
