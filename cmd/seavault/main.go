package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/example/seavault-fast/internal/appconfig"
	"github.com/example/seavault-fast/internal/importer"
	"github.com/example/seavault-fast/internal/keychain"
	"github.com/example/seavault-fast/internal/localdav"
	"github.com/example/seavault-fast/internal/passphrase"
	"github.com/example/seavault-fast/internal/processguard"
	"github.com/example/seavault-fast/internal/profile"
	"github.com/example/seavault-fast/internal/rclonebin"
	"github.com/example/seavault-fast/internal/remotes"
	"github.com/example/seavault-fast/internal/rsyncbin"
	"github.com/example/seavault-fast/internal/rsyncput"
	"github.com/example/seavault-fast/internal/sshkeys"
	"github.com/example/seavault-fast/internal/transport"
	localtransport "github.com/example/seavault-fast/internal/transport/local"
	rclonetransport "github.com/example/seavault-fast/internal/transport/rclone"
	"github.com/example/seavault-fast/internal/userpath"
	"github.com/example/seavault-fast/internal/vault"
	"github.com/example/seavault-fast/internal/vaultmove"
	"github.com/example/seavault-fast/internal/webui"
)

const version = "0.14.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(os.Args[2:])
	case "put":
		err = cmdPut(os.Args[2:])
	case "get":
		err = cmdGet(os.Args[2:])
	case "export":
		err = cmdExport(os.Args[2:])
	case "list":
		err = cmdList(os.Args[2:])
	case "remove", "rm":
		err = cmdRemove(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "gc":
		err = cmdGC(os.Args[2:])
	case "stats":
		err = cmdStats(os.Args[2:])
	case "serve":
		err = cmdServe(os.Args[2:])
	case "gui":
		err = cmdGUI(os.Args[2:])
	case "app-config", "config":
		err = cmdAppConfig(os.Args[2:])
	case "profile":
		err = cmdProfile(os.Args[2:])
	case "move":
		err = cmdMove(os.Args[2:])
	case "keychain":
		err = cmdKeychain(os.Args[2:])
	case "rclone":
		err = cmdRclone(os.Args[2:])
	case "rsync":
		err = cmdRsync(os.Args[2:])
	case "remote":
		err = cmdRemote(os.Args[2:])
	case "ssh-key":
		err = cmdSSHKey(os.Args[2:])
	case "version":
		fmt.Println(version)
		return
	default:
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	min := fs.Int("min", 2*1024*1024, "minimum chunk size in bytes")
	avg := fs.Int("avg", 8*1024*1024, "target average chunk size in bytes")
	max := fs.Int("max", 16*1024*1024, "maximum chunk size in bytes")
	kdf := fs.String("kdf", "argon2id", "key derivation function: argon2id, scrypt, or pbkdf2")
	argonTime := fs.Int("argon2-time", vault.DefaultArgon2Time, "Argon2id time cost")
	argonMemory := fs.Int("argon2-memory", vault.DefaultArgon2Memory, "Argon2id memory cost in KiB")
	argonParallelism := fs.Int("argon2-parallelism", vault.DefaultArgon2Threads, "Argon2id parallelism")
	scryptN := fs.Int("scrypt-n", vault.DefaultScryptN, "scrypt N parameter")
	scryptR := fs.Int("scrypt-r", vault.DefaultScryptR, "scrypt r parameter")
	scryptP := fs.Int("scrypt-p", vault.DefaultScryptP, "scrypt p parameter")
	pbkdf2Iter := fs.Int("pbkdf2-iterations", vault.DefaultKDFIterations, "PBKDF2 iterations for legacy mode")
	savePassword := fs.Bool("save-password", false, "store the vault password in the OS keychain after initialization")
	profileName := fs.String("profile", "", "optional local profile name for this vault path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: seavault init [flags] VAULT_DIR")
	}
	vaultPath, err := userpath.Abs(fs.Arg(0))
	if err != nil {
		return err
	}
	if err := userpath.ValidateCreatableVaultPath(vaultPath); err != nil {
		return err
	}
	password, err := readPasswordPrompt("New vault password: ")
	if err != nil {
		return err
	}
	params := vault.ChunkParams{MinSize: *min, AvgSize: *avg, MaxSize: *max}
	var kdfCfg vault.KDFConfig
	switch strings.ToLower(strings.TrimSpace(*kdf)) {
	case "", "argon2id", "argon2-id":
		kdfCfg = vault.KDFConfig{Algorithm: "ARGON2ID", Time: *argonTime, MemoryKiB: *argonMemory, Parallelism: *argonParallelism}
	case "scrypt":
		kdfCfg = vault.KDFConfig{Algorithm: "SCRYPT", ScryptN: *scryptN, ScryptR: *scryptR, ScryptP: *scryptP}
	case "pbkdf2", "pbkdf2-hmac-sha256":
		kdfCfg = vault.KDFConfig{Algorithm: "PBKDF2-HMAC-SHA256", Iterations: *pbkdf2Iter}
	default:
		return fmt.Errorf("unsupported KDF %q", *kdf)
	}
	if err := vault.CreateWithOptions(vaultPath, password, vault.CreateOptions{Chunk: params, KDF: kdfCfg}); err != nil {
		return err
	}
	if *profileName != "" {
		if _, err := profile.Add(*profileName, vaultPath); err != nil {
			return err
		}
	}
	if *savePassword {
		cfg, err := vault.ReadConfig(vaultPath)
		if err != nil {
			return err
		}
		if err := keychain.Set(cfg.VaultID, password); err != nil {
			return err
		}
	}
	fmt.Printf("initialized vault at %s\n", filepath.Join(vaultPath, vault.MetadataDirName))
	return nil
}

func cmdPut(args []string) error {
	fs := flag.NewFlagSet("put", flag.ExitOnError)
	noKeychain := fs.Bool("no-keychain", false, "do not try the OS keychain")
	method := fs.String("method", "auto", "put method: auto, native, managed-rsync, system-rsync, or rsync; auto prefers managed rsync, then system rsync, then native")
	rsyncBinary := fs.String("rsync", "", "system rsync binary path or name; ignored by managed-rsync")
	large := fs.Bool("large", false, "stream a large local file or folder through a bounded-memory import path")
	dryRun := fs.Bool("dry-run", false, "scan and report what a large import would process without writing to the vault")
	skipExisting := fs.Bool("skip-existing", true, "large import skips existing destination files with matching size")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 2 || fs.NArg() > 3 {
		return fmt.Errorf("usage: seavault put [--no-keychain] [--large] [--dry-run] [--method auto|native|managed-rsync|system-rsync|rsync] [--rsync PATH] VAULT_DIR_OR_PROFILE SOURCE_PATH [VIRTUAL_PATH]")
	}
	vaultPath, err := resolveVaultArg(fs.Arg(0))
	if err != nil {
		return err
	}
	password, err := readPasswordForVault(vaultPath, !*noKeychain)
	if err != nil {
		return err
	}
	v, err := vault.Open(vaultPath, password)
	if err != nil {
		return err
	}
	virtual := ""
	if fs.NArg() == 3 {
		virtual = fs.Arg(2)
	}
	if *large || *dryRun {
		progress := importer.ImportPath(context.Background(), v, fs.Arg(1), importer.Options{VirtualPath: virtual, DryRun: *dryRun, Method: *method, RsyncBinary: *rsyncBinary, SkipExisting: *skipExisting}, nil)
		data, _ := json.MarshalIndent(progress, "", "  ")
		fmt.Println(string(data))
		if progress.Status == "failed" || progress.Status == "cancelled" {
			return fmt.Errorf(progress.LastError)
		}
		return nil
	}
	res, err := rsyncput.PutPath(context.Background(), v, fs.Arg(1), virtual, rsyncput.Options{Method: *method, RsyncBinary: *rsyncBinary})
	if err != nil {
		return err
	}
	fmt.Printf("put method: %s\n", res.Method)
	if res.Method == rsyncput.MethodRsync && res.RsyncBinary != "" {
		fmt.Printf("rsync binary: %s\n", res.RsyncBinary)
	}
	for _, r := range res.Results {
		fmt.Printf("put %-50s %10d bytes %4d chunks %4d new\n", r.Path, r.Size, r.ChunkCount, r.NewChunkCount)
	}
	return nil
}
func cmdGet(args []string) error {
	fs := flag.NewFlagSet("get", flag.ExitOnError)
	noKeychain := fs.Bool("no-keychain", false, "do not try the OS keychain")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 3 {
		return fmt.Errorf("usage: seavault get [--no-keychain] VAULT_DIR_OR_PROFILE VIRTUAL_PATH DEST_PATH")
	}
	vaultPath, err := resolveVaultArg(fs.Arg(0))
	if err != nil {
		return err
	}
	password, err := readPasswordForVault(vaultPath, !*noKeychain)
	if err != nil {
		return err
	}
	v, err := vault.Open(vaultPath, password)
	if err != nil {
		return err
	}
	if err := v.GetPath(fs.Arg(1), fs.Arg(2)); err != nil {
		return err
	}
	fmt.Printf("restored %s to %s\n", fs.Arg(1), fs.Arg(2))
	return nil
}

func cmdExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	noKeychain := fs.Bool("no-keychain", false, "do not try the OS keychain")
	overwrite := fs.String("overwrite", vault.OverwriteFail, "overwrite policy: fail, skip, or replace")
	zipOut := fs.Bool("zip", false, "export to a ZIP archive")
	dryRun := fs.Bool("dry-run", false, "count files and planned destinations without writing plaintext output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 3 {
		return fmt.Errorf("usage: seavault export [--overwrite fail|skip|replace] [--zip] [--dry-run] VAULT_DIR_OR_PROFILE VIRTUAL_PATH DEST_LOCAL_FOLDER_OR_ZIP")
	}
	vaultPath, err := resolveVaultArg(fs.Arg(0))
	if err != nil {
		return err
	}
	password, err := readPasswordForVault(vaultPath, !*noKeychain)
	if err != nil {
		return err
	}
	v, err := vault.Open(vaultPath, password)
	if err != nil {
		return err
	}
	dest, err := userpath.Abs(fs.Arg(2))
	if err != nil {
		return err
	}
	res, err := v.ExportPath(context.Background(), fs.Arg(1), dest, vault.ExportOptions{Overwrite: *overwrite, Zip: *zipOut, DryRun: *dryRun})
	if err != nil {
		return err
	}
	if *dryRun {
		fmt.Printf("dry run: %d file(s), %d bytes, destination %s\n", res.Files, res.Bytes, res.DestPath)
	} else {
		fmt.Printf("exported %d file(s), skipped %d, %d bytes to %s\n", res.Exported, res.Skipped, res.Bytes, res.DestPath)
	}
	return nil
}

func cmdList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	noKeychain := fs.Bool("no-keychain", false, "do not try the OS keychain")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: seavault list [--no-keychain] VAULT_DIR_OR_PROFILE")
	}
	vaultPath, err := resolveVaultArg(fs.Arg(0))
	if err != nil {
		return err
	}
	password, err := readPasswordForVault(vaultPath, !*noKeychain)
	if err != nil {
		return err
	}
	v, err := vault.Open(vaultPath, password)
	if err != nil {
		return err
	}
	paths, err := v.List()
	if err != nil {
		return err
	}
	for _, p := range paths {
		fmt.Println(p)
	}
	return nil
}

func cmdRemove(args []string) error {
	fs := flag.NewFlagSet("remove", flag.ExitOnError)
	noKeychain := fs.Bool("no-keychain", false, "do not try the OS keychain")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("usage: seavault remove [--no-keychain] VAULT_DIR_OR_PROFILE VIRTUAL_PATH")
	}
	vaultPath, err := resolveVaultArg(fs.Arg(0))
	if err != nil {
		return err
	}
	password, err := readPasswordForVault(vaultPath, !*noKeychain)
	if err != nil {
		return err
	}
	v, err := vault.Open(vaultPath, password)
	if err != nil {
		return err
	}
	if err := v.Remove(fs.Arg(1)); err != nil {
		return err
	}
	fmt.Println("removed", fs.Arg(1))
	return nil
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	noKeychain := fs.Bool("no-keychain", false, "do not try the OS keychain")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: seavault verify [--no-keychain] VAULT_DIR_OR_PROFILE")
	}
	vaultPath, err := resolveVaultArg(fs.Arg(0))
	if err != nil {
		return err
	}
	password, err := readPasswordForVault(vaultPath, !*noKeychain)
	if err != nil {
		return err
	}
	v, err := vault.Open(vaultPath, password)
	if err != nil {
		return err
	}
	report, err := v.VerifyReport()
	if err != nil {
		return err
	}
	printVerifyReport(report)
	if !report.OK {
		return &vault.VerifyError{Report: report}
	}
	return nil
}

func printVerifyReport(report vault.VerifyReport) {
	status := "FAILED"
	if report.OK {
		status = "PASSED"
	}
	fmt.Printf("vault verification %s\n", status)
	fmt.Printf("files checked: %d\n", report.FilesChecked)
	fmt.Printf("chunks checked: %d\n", report.ChunksChecked)
	fmt.Printf("referenced bytes checked: %d\n", report.BytesChecked)
	if len(report.Issues) == 0 {
		return
	}
	fmt.Printf("issues: %d (missing chunks: %d, corrupt chunks: %d, other errors: %d)\n", len(report.Issues), report.MissingChunks, report.CorruptChunks, report.OtherErrors)
	for i, issue := range report.Issues {
		fmt.Printf("\nissue %d:\n", i+1)
		fmt.Printf("  kind: %s\n", issue.Kind)
		if issue.Path != "" {
			fmt.Printf("  file: %s\n", issue.Path)
		}
		if issue.ChunkID != "" {
			fmt.Printf("  chunk: %s\n", issue.ChunkID)
		}
		if issue.ChunkPath != "" {
			fmt.Printf("  chunk path: %s\n", issue.ChunkPath)
		}
		fmt.Printf("  error: %s\n", issue.Error)
	}
}

func cmdGC(args []string) error {
	fs := flag.NewFlagSet("gc", flag.ExitOnError)
	noKeychain := fs.Bool("no-keychain", false, "do not try the OS keychain")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: seavault gc [--no-keychain] VAULT_DIR_OR_PROFILE")
	}
	vaultPath, err := resolveVaultArg(fs.Arg(0))
	if err != nil {
		return err
	}
	password, err := readPasswordForVault(vaultPath, !*noKeychain)
	if err != nil {
		return err
	}
	v, err := vault.Open(vaultPath, password)
	if err != nil {
		return err
	}
	removed, err := v.GarbageCollect()
	if err != nil {
		return err
	}
	fmt.Printf("removed %d unreferenced chunks\n", removed)
	return nil
}

func cmdStats(args []string) error {
	fs := flag.NewFlagSet("stats", flag.ExitOnError)
	noKeychain := fs.Bool("no-keychain", false, "do not try the OS keychain")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: seavault stats [--no-keychain] VAULT_DIR_OR_PROFILE")
	}
	vaultPath, err := resolveVaultArg(fs.Arg(0))
	if err != nil {
		return err
	}
	password, err := readPasswordForVault(vaultPath, !*noKeychain)
	if err != nil {
		return err
	}
	v, err := vault.Open(vaultPath, password)
	if err != nil {
		return err
	}
	s, err := v.Stats()
	if err != nil {
		return err
	}
	fmt.Printf("files: %d\nreferenced chunks: %d\nstored chunk objects: %d\nreferenced MiB: %.2f\n", s.Files, s.Referenced, s.Objects, s.ReferencedMB)
	return nil
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:8765", "local address for the WebDAV-compatible endpoint")
	noKeychain := fs.Bool("no-keychain", false, "do not try the OS keychain")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: seavault serve [--addr 127.0.0.1:8765] [--no-keychain] VAULT_DIR_OR_PROFILE")
	}
	vaultPath, err := resolveVaultArg(fs.Arg(0))
	if err != nil {
		return err
	}
	password, err := readPasswordForVault(vaultPath, !*noKeychain)
	if err != nil {
		return err
	}
	v, err := vault.Open(vaultPath, password)
	if err != nil {
		return err
	}
	fmt.Printf("serving local WebDAV-compatible vault at http://%s/\n", *addr)
	fmt.Println("bind is local by default; do not expose this listener on an untrusted network")
	return http.ListenAndServe(*addr, localdav.New(v))
}

const guiAuthAccount = "seavault-gui-http-auth"

func cmdAppConfig(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: seavault app-config path|reset|reset-gui-login")
	}
	switch args[0] {
	case "path":
		p, err := appconfig.Path()
		if err != nil {
			return err
		}
		fmt.Println(p)
		return nil
	case "reset", "reset-config":
		return resetLocalAppConfiguration(true)
	case "reset-gui-login", "clear-gui-login", "reset-password":
		return resetLocalAppConfiguration(false)
	default:
		return fmt.Errorf("usage: seavault app-config path|reset|reset-gui-login")
	}
}

func resetLocalAppConfiguration(resetAll bool) error {
	if resetAll {
		p, err := appconfig.Path()
		if err != nil {
			return err
		}
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
		_ = keychain.Delete(guiAuthAccount)
		fmt.Printf("reset SeaVault local app configuration at %s\n", p)
		fmt.Println("vault data, saved vault locations, vault passwords, SSH keys, and remotes were not deleted")
		return nil
	}
	cfg, err := appconfig.Load()
	if err != nil {
		return err
	}
	cfg.GUI.Username = ""
	cfg.GUI.PasswordConfigured = false
	cfg.GUI.PasswordHash = ""
	if err := appconfig.Save(cfg); err != nil {
		return err
	}
	_ = keychain.Delete(guiAuthAccount)
	p, _ := appconfig.Path()
	fmt.Printf("reset SeaVault GUI login in %s\n", p)
	fmt.Println("restart SeaVault or reload the GUI; browser sessions are invalidated when the server restarts")
	return nil
}

func cmdGUI(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "reset", "reset-config":
			return resetLocalAppConfiguration(true)
		case "reset-login", "reset-password", "clear-login":
			return resetLocalAppConfiguration(false)
		case "config-path":
			p, err := appconfig.Path()
			if err != nil {
				return err
			}
			fmt.Println(p)
			return nil
		}
	}
	fs := flag.NewFlagSet("gui", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:8787", "local address for the browser GUI")
	noOpen := fs.Bool("no-open", false, "do not open the browser automatically")
	exitOnBrowserClose := fs.Bool("exit-on-browser-close", true, "best-effort: stop the GUI after the browser page stops sending heartbeats; set --exit-on-browser-close=false to keep the server running")
	if err := fs.Parse(args); err != nil {
		return err
	}
	initial := ""
	if fs.NArg() > 1 {
		return fmt.Errorf("usage: seavault gui [--addr 127.0.0.1:8787] [--no-open] [VAULT_DIR_OR_PROFILE]")
	}
	if fs.NArg() == 1 {
		initial = fs.Arg(0)
	}
	if err := processguard.TerminateExistingSeaVaultProcesses(); err != nil {
		return err
	}
	cfg, err := appconfig.Load()
	if err != nil {
		return err
	}
	if strings.EqualFold(cfg.GUI.Protocol, "https") {
		host := *addr
		if h, _, splitErr := net.SplitHostPort(*addr); splitErr == nil {
			host = h
		}
		cfg, err = appconfig.EnsureSelfSignedCertificate(cfg, host)
		if err != nil {
			return err
		}
		if saveErr := appconfig.Save(cfg); saveErr != nil {
			return saveErr
		}
	}
	s, err := webui.NewWithConfig(initial, cfg)
	if err != nil {
		return err
	}
	scheme := "http"
	if strings.EqualFold(cfg.GUI.Protocol, "https") {
		scheme = "https"
	}
	url := scheme + "://" + *addr + "/"
	fmt.Printf("serving local GUI at %s\n", url)
	fmt.Println("bind is local by default; do not expose this listener on an untrusted network")
	if *exitOnBrowserClose {
		s.EnableBrowserCloseShutdown(10 * time.Second)
		fmt.Println("exit-on-browser-close enabled; the GUI will stop shortly after the browser page closes")
	}
	if !*noOpen {
		_ = openBrowser(url)
	}
	srv := &http.Server{Addr: *addr, Handler: s}
	serveErr := make(chan error, 1)
	go func() {
		if scheme == "https" {
			serveErr <- srv.ListenAndServeTLS(cfg.GUI.CertFile, cfg.GUI.KeyFile)
			return
		}
		serveErr <- srv.ListenAndServe()
	}()
	select {
	case err := <-serveErr:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	case <-s.ShutdownNotify():
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		err := <-serveErr
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

func cmdMove(args []string) error {
	fs := flag.NewFlagSet("move", flag.ExitOnError)
	profileName := fs.String("profile", "", "saved vault name to update after moving")
	replace := fs.Bool("replace", false, "replace an existing destination directory")
	updateRemotes := fs.Bool("update-remotes", true, "update remote profiles that point at the old vault path")
	updateMatching := fs.Bool("update-matching-profiles", true, "update saved vault locations that point at the old vault path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("usage: seavault move [--profile NAME] [--replace] [--update-remotes=true] SOURCE_VAULT_DIR_OR_PROFILE DEST_VAULT_DIR")
	}
	sourceArg := fs.Arg(0)
	destArg := fs.Arg(1)
	sourcePath, err := resolveVaultArg(sourceArg)
	if err != nil {
		return err
	}
	if *profileName == "" {
		if e, ok, err := profile.Resolve(sourceArg); err != nil {
			return err
		} else if ok {
			*profileName = e.Name
		}
	}
	res, err := vaultmove.Move(sourcePath, destArg, vaultmove.Options{ProfileName: *profileName, Replace: *replace, UpdateMatchingProfiles: *updateMatching, UpdateRemoteProfiles: *updateRemotes})
	if err != nil {
		return err
	}
	fmt.Printf("moved vault from %s to %s\n", res.SourcePath, res.DestinationPath)
	if res.UpdatedProfiles > 0 || res.UpdatedRemotes > 0 {
		fmt.Printf("updated %d saved vault location(s) and %d remote profile(s)\n", res.UpdatedProfiles, res.UpdatedRemotes)
	}
	for _, warning := range res.Warnings {
		fmt.Fprintln(os.Stderr, "warning:", warning)
	}
	return nil
}

func cmdProfile(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: seavault profile add [--save-password] NAME VAULT_DIR | save [--save-password] NAME VAULT_DIR | move [--replace] [--update-remotes=true] NAME NEW_VAULT_DIR | list [--status] | remove NAME")
	}
	switch args[0] {
	case "add", "save":
		fs := flag.NewFlagSet("profile "+args[0], flag.ExitOnError)
		savePassword := fs.Bool("save-password", false, "verify and store this vault password in the OS keychain")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 2 {
			return fmt.Errorf("usage: seavault profile %s [--save-password] NAME VAULT_DIR", args[0])
		}
		entry, err := profile.Add(fs.Arg(0), fs.Arg(1))
		if err != nil {
			return err
		}
		if *savePassword {
			cfg, err := vault.ReadConfig(entry.VaultPath)
			if err != nil {
				return err
			}
			password, err := readPasswordPrompt("Vault password to store in OS keychain: ")
			if err != nil {
				return err
			}
			if _, err := vault.Open(entry.VaultPath, password); err != nil {
				return fmt.Errorf("profile saved, but password did not open vault: %w", err)
			}
			if err := keychain.Set(cfg.VaultID, password); err != nil {
				return err
			}
			fmt.Printf("profile %s -> %s (password saved in OS keychain)\n", entry.Name, entry.VaultPath)
			return nil
		}
		fmt.Printf("profile %s -> %s\n", entry.Name, entry.VaultPath)
		return nil
	case "move":
		fs := flag.NewFlagSet("profile move", flag.ExitOnError)
		replace := fs.Bool("replace", false, "replace an existing destination directory")
		updateRemotes := fs.Bool("update-remotes", true, "update remote profiles that point at the old vault path")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 2 {
			return fmt.Errorf("usage: seavault profile move [--replace] [--update-remotes=true] NAME NEW_VAULT_DIR")
		}
		res, err := vaultmove.MoveProfile(fs.Arg(0), fs.Arg(1), vaultmove.Options{Replace: *replace, UpdateRemoteProfiles: *updateRemotes})
		if err != nil {
			return err
		}
		fmt.Printf("moved saved vault %s from %s to %s\n", fs.Arg(0), res.SourcePath, res.DestinationPath)
		if res.UpdatedProfiles > 0 || res.UpdatedRemotes > 0 {
			fmt.Printf("updated %d saved vault location(s) and %d remote profile(s)\n", res.UpdatedProfiles, res.UpdatedRemotes)
		}
		for _, warning := range res.Warnings {
			fmt.Fprintln(os.Stderr, "warning:", warning)
		}
		return nil
	case "list":
		fs := flag.NewFlagSet("profile list", flag.ExitOnError)
		withStatus := fs.Bool("status", false, "include vault existence and keychain status")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return fmt.Errorf("usage: seavault profile list [--status]")
		}
		entries, err := profile.Entries()
		if err != nil {
			return err
		}
		for _, e := range entries {
			if !*withStatus {
				fmt.Printf("%s\t%s\n", e.Name, e.VaultPath)
				continue
			}
			status, keychainStatus := "missing", "no keychain entry"
			if cfg, err := vault.ReadConfig(e.VaultPath); err == nil {
				status = "vault exists"
				if cfg.VaultID != "" {
					if p, err := keychain.Get(cfg.VaultID); err == nil && p != "" {
						keychainStatus = "keychain saved"
					}
				}
			}
			fmt.Printf("%s\t%s\t%s\t%s\n", e.Name, e.VaultPath, status, keychainStatus)
		}
		return nil
	case "remove", "rm":
		if len(args) != 2 {
			return fmt.Errorf("usage: seavault profile remove NAME")
		}
		return profile.Remove(args[1])
	default:
		return fmt.Errorf("unknown profile command %q", args[0])
	}
}

func cmdKeychain(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: seavault keychain store VAULT_DIR_OR_PROFILE | status VAULT_DIR_OR_PROFILE | delete VAULT_DIR_OR_PROFILE")
	}
	switch args[0] {
	case "store":
		if len(args) != 2 {
			return fmt.Errorf("usage: seavault keychain store VAULT_DIR_OR_PROFILE")
		}
		vaultPath, err := resolveVaultArg(args[1])
		if err != nil {
			return err
		}
		cfg, err := vault.ReadConfig(vaultPath)
		if err != nil {
			return err
		}
		password, err := readPasswordPrompt("Vault password to store in OS keychain: ")
		if err != nil {
			return err
		}
		if _, err := vault.Open(vaultPath, password); err != nil {
			return err
		}
		if err := keychain.Set(cfg.VaultID, password); err != nil {
			return err
		}
		fmt.Println("password stored in OS keychain")
		return nil
	case "status":
		if len(args) != 2 {
			return fmt.Errorf("usage: seavault keychain status VAULT_DIR_OR_PROFILE")
		}
		vaultPath, err := resolveVaultArg(args[1])
		if err != nil {
			return err
		}
		cfg, err := vault.ReadConfig(vaultPath)
		if err != nil {
			return err
		}
		if _, err := keychain.Get(cfg.VaultID); err != nil {
			return err
		}
		fmt.Println("OS keychain entry exists")
		return nil
	case "delete", "remove", "rm":
		if len(args) != 2 {
			return fmt.Errorf("usage: seavault keychain delete VAULT_DIR_OR_PROFILE")
		}
		vaultPath, err := resolveVaultArg(args[1])
		if err != nil {
			return err
		}
		cfg, err := vault.ReadConfig(vaultPath)
		if err != nil {
			return err
		}
		if err := keychain.Delete(cfg.VaultID); err != nil {
			return err
		}
		fmt.Println("OS keychain entry deleted")
		return nil
	default:
		return fmt.Errorf("unknown keychain command %q", args[0])
	}
}

func cmdRsync(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: seavault rsync status|install|check-update|update|rollback|verify-runtime|path")
	}
	ctx := context.Background()
	installer := rsyncbin.NewInstaller()
	switch args[0] {
	case "status":
		fs := flag.NewFlagSet("rsync status", flag.ExitOnError)
		binary := fs.String("binary", "", "system rsync binary path or name; default searches PATH after managed rsync")
		check := fs.Bool("check-update", false, "also check latest upstream rsync source release")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		st := rsyncput.Inspect(ctx, *binary)
		if *check {
			st.Managed = installer.Status(ctx, true)
		}
		return printJSON(st)
	case "install":
		fs := flag.NewFlagSet("rsync install", flag.ExitOnError)
		ver := fs.String("version", "", "rsync version to register/install; default latest source release for runtime archive URLs")
		fromBinary := fs.String("from-binary", "", "register/copy an existing rsync-compatible binary into the managed runtime")
		offlineArchive := fs.String("offline-archive", "", "install from a local SeaVault rsync runtime zip archive")
		offlineSHA := fs.String("offline-sha256sums", "", "SHA256SUMS file for --offline-archive")
		runtimeBase := fs.String("runtime-base-url", "", "base URL for SeaVault-built rsync runtime artifacts")
		buildID := fs.String("build-id", "", "optional runtime build identifier for provenance")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		m, err := installer.Install(ctx, rsyncbin.InstallOptions{Version: *ver, FromBinary: *fromBinary, OfflineArchive: *offlineArchive, OfflineSHA256: *offlineSHA, RuntimeBaseURL: *runtimeBase, BuildID: *buildID})
		if printErr := printJSON(m); printErr != nil && err == nil {
			err = printErr
		}
		return err
	case "check-update":
		li, err := installer.Latest(ctx)
		if printErr := printJSON(li); printErr != nil && err == nil {
			err = printErr
		}
		return err
	case "update":
		fs := flag.NewFlagSet("rsync update", flag.ExitOnError)
		ver := fs.String("version", "", "rsync version to install; default latest upstream source release")
		fromBinary := fs.String("from-binary", "", "register/copy an existing rsync-compatible binary into the managed runtime")
		offlineArchive := fs.String("offline-archive", "", "install from a local SeaVault rsync runtime zip archive")
		offlineSHA := fs.String("offline-sha256sums", "", "SHA256SUMS file for --offline-archive")
		runtimeBase := fs.String("runtime-base-url", "", "base URL for SeaVault-built rsync runtime artifacts")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		m, err := installer.Update(ctx, rsyncbin.InstallOptions{Version: *ver, FromBinary: *fromBinary, OfflineArchive: *offlineArchive, OfflineSHA256: *offlineSHA, RuntimeBaseURL: *runtimeBase})
		if printErr := printJSON(m); printErr != nil && err == nil {
			err = printErr
		}
		return err
	case "rollback":
		if len(args) != 1 {
			return fmt.Errorf("usage: seavault rsync rollback")
		}
		m, err := rsyncbin.Rollback()
		if printErr := printJSON(m); printErr != nil && err == nil {
			err = printErr
		}
		return err
	case "verify-runtime":
		m, err := rsyncbin.LoadManifest()
		if err == nil {
			err = rsyncbin.VerifyRuntime(m)
		}
		if err != nil {
			return err
		}
		fmt.Println("managed rsync runtime verified")
		return nil
	case "path":
		bin, err := rsyncbin.BinaryPath()
		if err != nil {
			return err
		}
		fmt.Println(bin)
		return nil
	default:
		return fmt.Errorf("unknown rsync command %q", args[0])
	}
}

func cmdRclone(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: seavault rclone status|install|check-update|update|rollback|version|path|verify-runtime")
	}
	ctx := context.Background()
	installer := rclonebin.NewInstaller()
	switch args[0] {
	case "status":
		fs := flag.NewFlagSet("rclone status", flag.ExitOnError)
		check := fs.Bool("check-update", false, "also check the latest official rclone version")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return printJSON(installer.Status(ctx, *check))
	case "install":
		fs := flag.NewFlagSet("rclone install", flag.ExitOnError)
		ver := fs.String("version", "", "rclone version to install; default latest stable")
		channel := fs.String("channel", "stable", "release channel: stable or beta")
		fromBinary := fs.String("from-binary", "", "register/copy an existing rclone-compatible binary into the managed runtime")
		offlineArchive := fs.String("offline-archive", "", "install from a local rclone zip archive")
		offlineSHA := fs.String("offline-sha256sums", "", "SHA256SUMS file for --offline-archive")
		sig := fs.String("signature", "optional", "signature mode: optional, required, or skip")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		m, err := installer.Install(ctx, rclonebin.InstallOptions{Version: *ver, Channel: *channel, FromBinary: *fromBinary, OfflineArchive: *offlineArchive, OfflineSHA256: *offlineSHA, SignatureMode: *sig})
		if printErr := printJSON(m); printErr != nil && err == nil {
			err = printErr
		}
		return err
	case "check-update":
		fs := flag.NewFlagSet("rclone check-update", flag.ExitOnError)
		channel := fs.String("channel", "stable", "release channel")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		li, err := installer.Latest(ctx, *channel)
		if printErr := printJSON(li); printErr != nil && err == nil {
			err = printErr
		}
		return err
	case "update":
		fs := flag.NewFlagSet("rclone update", flag.ExitOnError)
		ver := fs.String("version", "", "rclone version to install; default latest")
		channel := fs.String("channel", "", "release channel")
		sig := fs.String("signature", "optional", "signature mode: optional, required, or skip")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		m, err := installer.Update(ctx, rclonebin.InstallOptions{Version: *ver, Channel: *channel, SignatureMode: *sig})
		if printErr := printJSON(m); printErr != nil && err == nil {
			err = printErr
		}
		return err
	case "rollback":
		if len(args) != 1 {
			return fmt.Errorf("usage: seavault rclone rollback")
		}
		m, err := rclonebin.Rollback()
		if printErr := printJSON(m); printErr != nil && err == nil {
			err = printErr
		}
		return err
	case "version":
		bin, err := rclonebin.BinaryPath()
		if err != nil {
			return err
		}
		v, err := rclonebin.Version(ctx, bin)
		if err != nil {
			return err
		}
		fmt.Println(v)
		return nil
	case "path":
		bin, err := rclonebin.BinaryPath()
		if err != nil {
			return err
		}
		fmt.Println(bin)
		return nil
	case "verify-runtime":
		m, err := rclonebin.LoadManifest()
		if err != nil {
			return err
		}
		if err := rclonebin.VerifyRuntime(m); err != nil {
			return err
		}
		fmt.Println("managed rclone runtime verified")
		return nil
	default:
		return fmt.Errorf("unknown rclone command %q", args[0])
	}
}

func cmdRemote(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: seavault remote add|list|show|edit|delete|test|dry-run|push|pull|sync|check|config")
	}
	switch args[0] {
	case "add", "edit":
		fs := flag.NewFlagSet("remote "+args[0], flag.ExitOnError)
		backend := fs.String("backend", "", "rclone backend label, e.g. local, sftp, s3, b2, onedrive, webdav")
		typeName := fs.String("type", "rclone", "profile type: rclone or local")
		configPath := fs.String("config", "", "rclone config path, default app-managed config")
		transfers := fs.Int("transfers", 8, "parallel rclone transfers")
		checkers := fs.Int("checkers", 16, "parallel rclone checkers")
		fastList := fs.Bool("fast-list", true, "enable rclone --fast-list where supported")
		bandwidth := fs.String("bwlimit", "", "optional rclone bandwidth limit")
		allowSync := fs.Bool("allow-destructive-sync", false, "allow advanced destructive rclone sync for this profile")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 3 {
			return fmt.Errorf("usage: seavault remote %s [flags] NAME VAULT_DIR_OR_PROFILE RCLONE_REMOTE_PATH", args[0])
		}
		vaultPath, err := resolveVaultArg(fs.Arg(1))
		if err != nil {
			return err
		}
		p := remotes.DefaultProfile(fs.Arg(0), vaultPath, fs.Arg(2), *backend)
		p.Type = strings.ToLower(strings.TrimSpace(*typeName))
		p.Remote.Transfers = *transfers
		p.Remote.Checkers = *checkers
		p.Remote.FastList = *fastList
		p.Remote.BandwidthLimit = *bandwidth
		if *configPath != "" {
			cfg, err := remotes.ResolveConfigPath(*configPath)
			if err != nil {
				return err
			}
			p.Remote.RcloneConfigPath = cfg
		}
		p.Safety.AllowDestructiveSync = *allowSync
		entry, err := remotes.Add(p)
		if err != nil {
			return err
		}
		return printJSON(entry)
	case "list":
		if len(args) != 1 {
			return fmt.Errorf("usage: seavault remote list")
		}
		entries, err := remotes.Entries()
		if err != nil {
			return err
		}
		for _, e := range entries {
			fmt.Printf("%s\t%s\t%s\t%s\n", e.Name, e.Type, e.Vault, e.Remote.RemotePath)
		}
		return nil
	case "show":
		if len(args) != 2 {
			return fmt.Errorf("usage: seavault remote show NAME")
		}
		p, ok, err := remotes.Get(args[1])
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("remote profile %q not found", args[1])
		}
		return printJSON(p)
	case "delete", "remove", "rm":
		if len(args) != 2 {
			return fmt.Errorf("usage: seavault remote delete NAME")
		}
		return remotes.Remove(args[1])
	case "test", "dry-run", "push", "pull", "check", "sync":
		if len(args) != 2 {
			return fmt.Errorf("usage: seavault remote %s NAME", args[0])
		}
		return runRemote(args[0], args[1])
	case "config":
		return cmdRemoteConfig(args[1:])
	default:
		return fmt.Errorf("unknown remote command %q", args[0])
	}
}

func runRemote(op, name string) error {
	ctx := context.Background()
	p, ok, err := remotes.Get(name)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("remote profile %q not found", name)
	}
	var res any
	if p.Type == "local" {
		t := localtransport.New(p)
		switch op {
		case "test":
			res, err = t.Test(ctx)
		case "dry-run":
			res, err = t.DryRunPush(ctx)
		case "push":
			res, err = t.Push(ctx, transport.Options{})
		case "pull":
			res, err = t.Pull(ctx, transport.Options{})
		case "check":
			res, err = t.Check(ctx)
		case "sync":
			res, err = t.Sync(ctx, transport.Options{})
		}
	} else {
		bin, err := rclonebin.BinaryPath()
		if err != nil {
			return err
		}
		t := rclonetransport.New(bin, p)
		switch op {
		case "test":
			res, err = t.Test(ctx)
		case "dry-run":
			res, err = t.DryRunPush(ctx)
		case "push":
			res, err = t.Push(ctx, transport.Options{})
		case "pull":
			res, err = t.Pull(ctx, transport.Options{})
		case "check":
			res, err = t.Check(ctx)
		case "sync":
			if !p.Safety.AllowDestructiveSync {
				return fmt.Errorf("destructive sync is disabled for %s; use push/pull/copy-safe flow or enable allowDestructiveSync after dry-run review", name)
			}
			return fmt.Errorf("destructive sync command is intentionally not automated; use copy-safe push/pull or vault-aware reconcile")
		}
	}
	if err != nil {
		if res != nil {
			_ = printJSON(res)
		}
		return err
	}
	return printJSON(res)
}

func cmdRemoteConfig(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: seavault remote config path|import|export-redacted|validate")
	}
	switch args[0] {
	case "path":
		if len(args) != 1 {
			return fmt.Errorf("usage: seavault remote config path")
		}
		fmt.Println(remotes.DefaultRcloneConfigPath())
		return nil
	case "import":
		if len(args) != 2 {
			return fmt.Errorf("usage: seavault remote config import SOURCE_RCLONE_CONF")
		}
		src, err := userpath.Abs(args[1])
		if err != nil {
			return err
		}
		dst := remotes.DefaultRcloneConfigPath()
		if err := copyFile(src, dst, 0o600); err != nil {
			return err
		}
		fmt.Println("imported rclone config to", dst)
		return nil
	case "export-redacted":
		if len(args) > 2 {
			return fmt.Errorf("usage: seavault remote config export-redacted [CONFIG_PATH]")
		}
		cfg := remotes.DefaultRcloneConfigPath()
		if len(args) == 2 {
			var err error
			cfg, err = userpath.Abs(args[1])
			if err != nil {
				return err
			}
		}
		data, err := os.ReadFile(cfg)
		if err != nil {
			return err
		}
		fmt.Println(remotes.RedactConfig(string(data)))
		return nil
	case "validate":
		bin, err := rclonebin.BinaryPath()
		if err != nil {
			return err
		}
		cfg := remotes.DefaultRcloneConfigPath()
		if len(args) == 2 {
			cfg, err = userpath.Abs(args[1])
			if err != nil {
				return err
			}
		} else if len(args) != 1 {
			return fmt.Errorf("usage: seavault remote config validate [CONFIG_PATH]")
		}
		out, err := exec.Command(bin, "--config", cfg, "config", "show").CombinedOutput()
		if err != nil {
			return fmt.Errorf("rclone config validate failed: %w: %s", err, strings.TrimSpace(remotes.RedactConfig(string(out))))
		}
		fmt.Println(remotes.RedactConfig(string(out)))
		return nil
	case "create":
		_, err := remotes.EnsureManagedConfig()
		if err != nil {
			return err
		}
		fmt.Println(remotes.DefaultRcloneConfigPath())
		return nil
	default:
		return fmt.Errorf("unknown remote config command %q", args[0])
	}
}

func cmdSSHKey(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: seavault ssh-key generate NAME | list | public PRIVATE_KEY_OR_NAME | import NAME PRIVATE_KEY")
	}
	ctx := context.Background()
	switch args[0] {
	case "generate":
		if len(args) != 2 {
			return fmt.Errorf("usage: seavault ssh-key generate NAME")
		}
		info, err := sshkeys.Generate(ctx, args[1])
		if err != nil {
			return err
		}
		return printJSON(info)
	case "import":
		if len(args) != 3 {
			return fmt.Errorf("usage: seavault ssh-key import NAME PRIVATE_KEY")
		}
		info, err := sshkeys.Import(args[1], args[2])
		if err != nil {
			return err
		}
		return printJSON(info)
	case "public":
		if len(args) != 2 {
			return fmt.Errorf("usage: seavault ssh-key public PRIVATE_KEY_OR_NAME")
		}
		pub, err := sshkeys.Public(args[1])
		if err != nil {
			return err
		}
		fmt.Println(pub)
		return nil
	case "list":
		if len(args) != 1 {
			return fmt.Errorf("usage: seavault ssh-key list")
		}
		keys, err := sshkeys.List()
		if err != nil {
			return err
		}
		return printJSON(keys)
	default:
		return fmt.Errorf("unknown ssh-key command %q", args[0])
	}
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func copyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func resolveVaultArg(input string) (string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", fmt.Errorf("vault path or profile is required")
	}
	if !strings.ContainsAny(input, `/\\`) && !filepath.IsAbs(input) {
		if e, ok, err := profile.Resolve(input); err != nil {
			return "", err
		} else if ok {
			return e.VaultPath, nil
		}
	}
	return userpath.Abs(input)
}

func readPasswordForVault(vaultPath string, useKeychain bool) (string, error) {
	if p := os.Getenv("SEAVAULT_PASSWORD"); p != "" {
		return p, nil
	}
	if useKeychain {
		if cfg, err := vault.ReadConfig(vaultPath); err == nil && cfg.VaultID != "" {
			if p, err := keychain.Get(cfg.VaultID); err == nil && p != "" {
				return p, nil
			}
		}
	}
	return readPasswordPrompt("Vault password: ")
}

func readPasswordPrompt(prompt string) (string, error) {
	if p := os.Getenv("SEAVAULT_PASSWORD"); p != "" {
		return p, nil
	}
	return passphrase.Read(prompt)
}

func openBrowser(url string) error {
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		return exec.Command("open", url).Start()
	default:
		return exec.Command("xdg-open", url).Start()
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `seavault %s

Cloud-folder client-side encrypted storage.

Usage:
  seavault init [flags] VAULT_DIR
  seavault put [--method auto|native|managed-rsync|system-rsync|rsync] [flags] VAULT_DIR_OR_PROFILE SOURCE_PATH [VIRTUAL_PATH]
  seavault get [flags] VAULT_DIR_OR_PROFILE VIRTUAL_PATH DEST_PATH
  seavault export [--overwrite fail|skip|replace] [--zip] [--dry-run] VAULT_DIR_OR_PROFILE VIRTUAL_PATH DEST_LOCAL_FOLDER_OR_ZIP
  seavault list [flags] VAULT_DIR_OR_PROFILE
  seavault remove [flags] VAULT_DIR_OR_PROFILE VIRTUAL_PATH
  seavault verify [flags] VAULT_DIR_OR_PROFILE
  seavault gc [flags] VAULT_DIR_OR_PROFILE
  seavault stats [flags] VAULT_DIR_OR_PROFILE
  seavault serve [flags] VAULT_DIR_OR_PROFILE
  seavault gui [flags] [VAULT_DIR_OR_PROFILE]
  seavault gui reset-config | reset-login | config-path
  seavault app-config path | reset | reset-gui-login
  seavault profile add [--save-password] NAME VAULT_DIR
  seavault profile save [--save-password] NAME VAULT_DIR
  seavault profile move [--replace] [--update-remotes=true] NAME NEW_VAULT_DIR
  seavault move [--profile NAME] [--replace] SOURCE_VAULT_DIR_OR_PROFILE DEST_VAULT_DIR
  seavault profile list [--status]
  seavault profile remove NAME
  seavault keychain store VAULT_DIR_OR_PROFILE
  seavault keychain status VAULT_DIR_OR_PROFILE
  seavault keychain delete VAULT_DIR_OR_PROFILE
  seavault rclone status | install | check-update | update | rollback | verify-runtime
  seavault rsync status | install | check-update | update | rollback | verify-runtime | path
  seavault remote add NAME VAULT_DIR_OR_PROFILE RCLONE_REMOTE_PATH
  seavault remote list | show NAME | test NAME | dry-run NAME | push NAME | pull NAME | check NAME
  seavault ssh-key generate NAME | list | public NAME | import NAME PRIVATE_KEY

VAULT_DIR is the encrypted folder. Put it inside any local cloud-sync directory.
Passwords are read from SEAVAULT_PASSWORD, then OS keychain, then a hidden prompt.
`, version)
}
