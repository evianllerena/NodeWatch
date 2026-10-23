//go:build windows

// NodeWatch-Sign: signs NodeWatch releases on your own PC, with keys that never leave it (Phase 3).
//
//	NodeWatch-Sign.exe setup                         once: make the code-signing certificate and the minisign key
//	NodeWatch-Sign.exe sign NodeWatch.exe NodeWatch.zip
//	NodeWatch-Sign.exe verify <file> [minisign.pub]   check a file's .minisig
//	NodeWatch-Sign.exe backup <folder>                password-protected copy of both keys (keep it offline)
//	NodeWatch-Sign.exe restore <backup file>          put both keys on another PC
//
// Windows (NodeWatch.exe): every program file inside the installer (the launcher, the backend host, the app window,
// the compiled app and the Python runtime's unsigned files) is Authenticode-signed with your certificate, the
// integrity list is rebuilt over the signed files, the launcher's pinned hash is updated and the launcher signed,
// and the installer itself is signed last. macOS (NodeWatch.zip): the app keeps its ad-hoc signature (Apple
// signing is not free); like the installer it gets a minisign signature (.minisig) proving it came from you.
//
// Keys: the certificate's private key lives in your Windows certificate store (Current User); the minisign secret key
// is stored encrypted for your Windows account (DPAPI) in %APPDATA%\NodeWatch-Signing. Nothing is uploaded anywhere.
package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
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

const (
	subject       = "CN=BWN NodeWatch Code Signing, O=BWN"
	timestampURL  = "http://timestamp.digicert.com"
	trustedPrefix = "NodeWatch release"
)

func main() {
	if len(os.Args) < 2 {
		interactive() // double-clicked: a simple menu instead of commands
		return
	}
	var err error
	switch strings.ToLower(os.Args[1]) {
	case "setup":
		err = setup()
	case "sign":
		if len(os.Args) < 3 {
			usage()
		}
		err = signRelease(os.Args[2:])
	case "verify":
		if len(os.Args) < 3 {
			usage()
		}
		pub := filepath.Join(keyDir(), "minisign.pub")
		if len(os.Args) > 3 {
			pub = os.Args[3]
		}
		err = verifyFile(os.Args[2], pub)
	case "backup":
		if len(os.Args) < 3 {
			usage()
		}
		err = backup(os.Args[2])
	case "export-github":
		err = exportForGitHub()
	case "restore":
		if len(os.Args) < 3 {
			usage()
		}
		err = restore(os.Args[2])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Println(`NodeWatch-Sign: sign NodeWatch releases on this PC

  NodeWatch-Sign.exe setup
  NodeWatch-Sign.exe sign NodeWatch.exe [NodeWatch.zip]
  NodeWatch-Sign.exe verify <file> [minisign.pub]
  NodeWatch-Sign.exe backup <folder>
  NodeWatch-Sign.exe restore <backup file>`)
	os.Exit(2)
}

func keyDir() string { return filepath.Join(os.Getenv("APPDATA"), "NodeWatch-Signing") }

// ---------------------------------------------------------------------------------------------- PowerShell

func systemDir() string {
	buf := make([]uint16, 260)
	n, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("GetSystemDirectoryW").Call(uintptr(unsafe.Pointer(&buf[0])), 260)
	if n == 0 {
		return `C:\Windows\System32`
	}
	return syscall.UTF16ToString(buf[:n])
}

func ps(script string, env ...string) (string, error) {
	cmd := exec.Command(filepath.Join(systemDir(), `WindowsPowerShell\v1.0\powershell.exe`),
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	cmd.Env = append(cleanEnv(), env...)
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, fmt.Errorf("%v: %s", err, text)
	}
	return text, nil
}

const findCert = `$c = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object { $_.Subject -eq $env:NW_SUBJECT -and $_.NotAfter -gt (Get-Date) } | Sort-Object NotAfter -Descending | Select-Object -First 1
if (-not $c) { throw "No NodeWatch code-signing certificate on this PC. Run: NodeWatch-Sign.exe setup" }`

// ---------------------------------------------------------------------------------------------- setup

func setup() error {
	out, err := ps(`$c = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object { $_.Subject -eq $env:NW_SUBJECT -and $_.NotAfter -gt (Get-Date) } | Select-Object -First 1
if (-not $c) {
  $c = New-SelfSignedCertificate -Type CodeSigningCert -Subject $env:NW_SUBJECT -CertStoreLocation Cert:\CurrentUser\My `+"`"+`
       -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 -KeyExportPolicy Exportable -NotAfter (Get-Date).AddYears(5)
  "created"
} else { "existing" }
Export-Certificate -Cert $c -FilePath $env:NW_CER -Type CERT | Out-Null
"thumbprint " + $c.Thumbprint
"valid until " + $c.NotAfter.ToString('yyyy-MM-dd')`,
		"NW_SUBJECT="+subject, "NW_CER="+filepath.Join(mustCwd(), "BWN-NodeWatch-CodeSigning.cer"))
	if err != nil {
		return fmt.Errorf("certificate: %w", err)
	}
	fmt.Println("Code-signing certificate:", strings.ReplaceAll(out, "\r\n", "; "))
	fmt.Println("  Give BWN-NodeWatch-CodeSigning.cer (public, safe to share) to the customer's IT: they add it to")
	fmt.Println("  Trusted Publishers and Trusted Root Certification Authorities by Group Policy.")

	if err := os.MkdirAll(keyDir(), 0o700); err != nil {
		return err
	}
	secPath := filepath.Join(keyDir(), "minisign.key")
	if _, err := os.Stat(secPath); err == nil {
		fmt.Println("Minisign key: existing", filepath.Join(keyDir(), "minisign.pub"))
	} else {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		keyID := make([]byte, 8)
		if _, err := rand.Read(keyID); err != nil {
			return err
		}
		blob, err := dpapi(append(append([]byte{}, keyID...), priv...), true)
		if err != nil {
			return fmt.Errorf("protect the minisign key: %w", err)
		}
		if err := os.WriteFile(secPath, blob, 0o600); err != nil {
			return err
		}
		pubText := "untrusted comment: minisign public key " + strings.ToUpper(hex.EncodeToString(reverse(keyID))) + "\n" +
			base64.StdEncoding.EncodeToString(append(append([]byte("Ed"), keyID...), pub...)) + "\n"
		if err := os.WriteFile(filepath.Join(keyDir(), "minisign.pub"), []byte(pubText), 0o644); err != nil {
			return err
		}
		fmt.Println("Minisign key: created")
	}
	pub, _ := os.ReadFile(filepath.Join(keyDir(), "minisign.pub"))
	_ = os.WriteFile(filepath.Join(mustCwd(), "minisign.pub"), pub, 0o644)
	fmt.Println("  minisign.pub (public, safe to share) is in this folder; customers check downloads with it:")
	fmt.Println("    minisign -Vm NodeWatch.exe -p minisign.pub")
	fmt.Println("Make an offline backup of both keys now: NodeWatch-Sign.exe backup E:\\  (a USB drive kept safe)")
	return nil
}

func mustCwd() string { d, _ := os.Getwd(); return d }

func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[len(b)-1-i]
	}
	return out
}

// ---------------------------------------------------------------------------------------------- DPAPI

type dataBlob struct {
	Size uint32
	Data *byte
}

func dpapi(data []byte, protect bool) ([]byte, error) {
	crypt32 := syscall.NewLazyDLL(filepath.Join(systemDir(), "crypt32.dll"))
	in := dataBlob{Size: uint32(len(data)), Data: &data[0]}
	var out dataBlob
	proc := crypt32.NewProc("CryptUnprotectData")
	if protect {
		proc = crypt32.NewProc("CryptProtectData")
	}
	r, _, err := proc.Call(uintptr(unsafe.Pointer(&in)), 0, 0, 0, 0, 0x1, uintptr(unsafe.Pointer(&out)))
	if r == 0 {
		return nil, err
	}
	defer syscall.NewLazyDLL("kernel32.dll").NewProc("LocalFree").Call(uintptr(unsafe.Pointer(out.Data)))
	return append([]byte{}, unsafe.Slice(out.Data, out.Size)...), nil
}

func loadSecret() ([]byte, ed25519.PrivateKey, error) {
	// On GitHub (automatic signing) the key comes from the encrypted secret NW_MINISIGN_KEY.
	if v := strings.TrimSpace(os.Getenv("NW_MINISIGN_KEY")); v != "" {
		raw, err := base64.StdEncoding.DecodeString(v)
		if err != nil || len(raw) != 8+ed25519.PrivateKeySize {
			return nil, nil, errors.New("NW_MINISIGN_KEY is not a NodeWatch-Sign key")
		}
		return raw[:8], ed25519.PrivateKey(raw[8:]), nil
	}
	blob, err := os.ReadFile(filepath.Join(keyDir(), "minisign.key"))
	if err != nil {
		return nil, nil, errors.New("no minisign key on this PC. Run: NodeWatch-Sign.exe setup")
	}
	raw, err := dpapi(blob, false)
	if err != nil || len(raw) != 8+ed25519.PrivateKeySize {
		return nil, nil, errors.New("the minisign key cannot be opened by this Windows account")
	}
	return raw[:8], ed25519.PrivateKey(raw[8:]), nil
}

// ---------------------------------------------------------------------------------------------- minisign

// minisignFile writes <path>.minisig in minisign's format (prehashed "ED": BLAKE2b-512 is not in Go's standard
// library, so the legacy "Ed" form over the whole file is used; minisign -V verifies both).
func minisignFile(path string) error {
	keyID, priv, err := loadSecret()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, data)
	trusted := fmt.Sprintf("%s %s timestamp:%d file:%s sha256:%x", trustedPrefix, filepath.Base(path), time.Now().Unix(),
		filepath.Base(path), sha256.Sum256(data))
	global := ed25519.Sign(priv, append(append([]byte{}, sig...), []byte(trusted)...))
	text := "untrusted comment: signature from NodeWatch-Sign\n" +
		base64.StdEncoding.EncodeToString(append(append([]byte("Ed"), keyID...), sig...)) + "\n" +
		"trusted comment: " + trusted + "\n" +
		base64.StdEncoding.EncodeToString(global) + "\n"
	return os.WriteFile(path+".minisig", []byte(text), 0o644)
}

func verifyFile(path, pubPath string) error {
	pubText, err := os.ReadFile(pubPath)
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimSpace(string(pubText)), "\n")
	pk, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[len(lines)-1]))
	if err != nil || len(pk) != 42 || string(pk[:2]) != "Ed" {
		return errors.New("not a minisign public key")
	}
	sigText, err := os.ReadFile(path + ".minisig")
	if err != nil {
		return err
	}
	sl := strings.Split(strings.ReplaceAll(string(sigText), "\r", ""), "\n")
	if len(sl) < 4 || !strings.HasPrefix(sl[2], "trusted comment: ") {
		return errors.New("not a minisign signature file")
	}
	sig, err := base64.StdEncoding.DecodeString(sl[1])
	if err != nil || len(sig) != 74 || !bytes.Equal(sig[2:10], pk[2:10]) {
		return errors.New("signature made with a different key")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	pub := ed25519.PublicKey(pk[10:])
	if string(sig[:2]) != "Ed" || !ed25519.Verify(pub, data, sig[10:]) {
		return errors.New("SIGNATURE DOES NOT MATCH: the file was changed or not signed with this key")
	}
	trusted := strings.TrimPrefix(sl[2], "trusted comment: ")
	global, err := base64.StdEncoding.DecodeString(sl[3])
	if err != nil || !ed25519.Verify(pub, append(append([]byte{}, sig[10:]...), []byte(trusted)...), global) {
		return errors.New("the trusted comment was changed")
	}
	fmt.Println("Signature OK:", trusted)
	return nil
}

// ---------------------------------------------------------------------------------------------- backup

var stdin = bufio.NewReader(os.Stdin)

func readLine(prompt string) string {
	fmt.Print(prompt)
	line, _ := stdin.ReadString('\n')
	return strings.TrimSpace(line)
}

// readPassword reads a line without showing it on screen.
func readPassword(prompt string) string {
	k32 := syscall.NewLazyDLL("kernel32.dll")
	h, _, _ := k32.NewProc("GetStdHandle").Call(uintptr(0xFFFFFFF6)) // STD_INPUT_HANDLE
	var mode uint32
	if r, _, _ := k32.NewProc("GetConsoleMode").Call(h, uintptr(unsafe.Pointer(&mode))); r != 0 {
		k32.NewProc("SetConsoleMode").Call(h, uintptr(mode&^0x4)) // no echo
		defer k32.NewProc("SetConsoleMode").Call(h, uintptr(mode))
	}
	pw := readLine(prompt)
	fmt.Println()
	return pw
}

func backupKey(pw string, salt []byte) ([]byte, error) { return pbkdf2.Key(sha512.New, pw, salt, 600000, 32) }

// backup writes both keys (the certificate with its private key, and the minisign key) into one file encrypted
// with a password you choose. Keep it offline (a USB drive in a safe place); restore it with "restore".
func backup(folder string) error {
	pw := readPassword("Choose a password for the backup (at least 12 characters, it is not shown): ")
	if len(pw) < 12 {
		return errors.New("use at least 12 characters")
	}
	if readPassword("Type the same password again: ") != pw {
		return errors.New("the two passwords are different; nothing was written")
	}
	keyID, priv, err := loadSecret()
	if err != nil {
		return err
	}
	pfx := filepath.Join(os.TempDir(), fmt.Sprintf("nw-%x.pfx", time.Now().UnixNano()))
	defer os.Remove(pfx)
	if _, err := ps(findCert+`
$pw = ConvertTo-SecureString -String $env:NW_PW -AsPlainText -Force
Export-PfxCertificate -Cert $c -FilePath $env:NW_OUT -Password $pw | Out-Null`, "NW_SUBJECT="+subject, "NW_OUT="+pfx, "NW_PW="+pw); err != nil {
		return fmt.Errorf("export the certificate: %w", err)
	}
	cert, err := os.ReadFile(pfx)
	if err != nil {
		return err
	}
	pub, _ := os.ReadFile(filepath.Join(keyDir(), "minisign.pub"))
	plain, _ := json.Marshal(map[string]string{
		"minisign_key": base64.StdEncoding.EncodeToString(append(append([]byte{}, keyID...), priv...)),
		"minisign_pub": string(pub), "certificate_pfx": base64.StdEncoding.EncodeToString(cert),
	})
	salt, nonce := make([]byte, 16), make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	key, err := backupKey(pw, salt)
	if err != nil {
		return err
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	sealed := gcm.Seal(nil, nonce, plain, []byte("NodeWatch-Sign backup v1"))
	path := filepath.Join(folder, "NodeWatch-signing-backup.nwsb")
	if err := os.WriteFile(path, append(append(append([]byte("NWSB1"), salt...), nonce...), sealed...), 0o600); err != nil {
		return err
	}
	fmt.Println("Backup written:", path)
	fmt.Println("Keep it and its password apart, offline. To move signing to another PC: NodeWatch-Sign.exe restore <file>")
	return nil
}

func restore(path string) error {
	blob, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(blob) < 5+16+12+16 || string(blob[:5]) != "NWSB1" {
		return errors.New("not a NodeWatch signing backup")
	}
	pw := readPassword("Backup password: ")
	salt, nonce, sealed := blob[5:21], blob[21:33], blob[33:]
	key, err := backupKey(pw, salt)
	if err != nil {
		return err
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	plain, err := gcm.Open(nil, nonce, sealed, []byte("NodeWatch-Sign backup v1"))
	if err != nil {
		return errors.New("wrong password or damaged backup")
	}
	var b map[string]string
	if err := json.Unmarshal(plain, &b); err != nil {
		return err
	}
	raw, err := base64.StdEncoding.DecodeString(b["minisign_key"])
	if err != nil || len(raw) != 8+ed25519.PrivateKeySize {
		return errors.New("damaged backup")
	}
	if err := os.MkdirAll(keyDir(), 0o700); err != nil {
		return err
	}
	protected, err := dpapi(raw, true)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(keyDir(), "minisign.key"), protected, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(keyDir(), "minisign.pub"), []byte(b["minisign_pub"]), 0o644); err != nil {
		return err
	}
	cert, _ := base64.StdEncoding.DecodeString(b["certificate_pfx"])
	pfx := filepath.Join(os.TempDir(), fmt.Sprintf("nw-%x.pfx", time.Now().UnixNano()))
	defer os.Remove(pfx)
	if err := os.WriteFile(pfx, cert, 0o600); err != nil {
		return err
	}
	if _, err := ps(`$pw = ConvertTo-SecureString -String $env:NW_PW -AsPlainText -Force
Import-PfxCertificate -FilePath $env:NW_PFX -CertStoreLocation Cert:\CurrentUser\My -Password $pw | Out-Null`, "NW_PFX="+pfx, "NW_PW="+pw); err != nil {
		return fmt.Errorf("import the certificate: %w", err)
	}
	fmt.Println("Restored: the code-signing certificate and the minisign key are on this PC.")
	return nil
}

// ---------------------------------------------------------------------------------------------- signing a release

type entry struct {
	name string
	data []byte
	mod  time.Time
}

func signRelease(files []string) error {
	if _, err := ps(findCert, "NW_SUBJECT="+subject); err != nil {
		return err
	}
	if _, _, err := loadSecret(); err != nil {
		return err
	}
	for _, f := range files {
		switch strings.ToLower(filepath.Ext(f)) {
		case ".exe":
			if err := signInstaller(f); err != nil {
				return fmt.Errorf("%s: %w", f, err)
			}
		case ".zip":
			fmt.Println("macOS app: keeps its ad-hoc Apple signature (Apple signing is not free); adding the minisign signature")
		default:
			return fmt.Errorf("%s: expected NodeWatch.exe or NodeWatch.zip", f)
		}
		if err := minisignFile(f); err != nil {
			return err
		}
		fmt.Println("signed:", f, "+", filepath.Base(f)+".minisig")
	}
	return nil
}

// findPayload locates the embedded payload zip (padded to a fixed size by tools/build_release.py).
func findPayload(exe []byte) (int, int, error) {
	eocd := bytes.LastIndex(exe, []byte("PK\x05\x06"))
	for eocd >= 0 {
		if eocd+22 <= len(exe) {
			cdSize := int(binary.LittleEndian.Uint32(exe[eocd+12:]))
			cdOff := int(binary.LittleEndian.Uint32(exe[eocd+16:]))
			clen := int(binary.LittleEndian.Uint16(exe[eocd+20:]))
			start := eocd - cdSize - cdOff
			if start >= 0 && bytes.Equal(exe[start:start+4], []byte("PK\x03\x04")) && bytes.Equal(exe[eocd-cdSize:eocd-cdSize+4], []byte("PK\x01\x02")) {
				return start, eocd + 22 + clen - start, nil
			}
		}
		eocd = bytes.LastIndex(exe[:eocd], []byte("PK\x05\x06"))
	}
	return 0, 0, errors.New("no NodeWatch payload found in this file")
}

func isPE(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".exe", ".dll", ".pyd":
		return true
	}
	return false
}

func signInstaller(path string) error {
	exe, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if authenticodeValid(path) {
		return errors.New("this installer is already signed; sign the file downloaded from GitHub")
	}
	start, size, err := findPayload(exe)
	if err != nil {
		return err
	}
	zr, err := zip.NewReader(bytes.NewReader(exe[start:start+size]), int64(size))
	if err != nil {
		return err
	}
	var entries []entry
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, "/") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return err
		}
		entries = append(entries, entry{name: f.Name, data: data, mod: f.Modified})
	}
	work, err := os.MkdirTemp("", "nw-sign-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)

	// 1. Program files inside _internal that are not signed yet.
	const internal = "NodeWatch/_internal/"
	var targets []int
	for i, e := range entries {
		if strings.HasPrefix(e.name, internal) && isPE(e.name) {
			targets = append(targets, i)
		}
	}
	fmt.Printf("signing %d program files inside the installer…\n", len(targets))
	if err := signEntries(entries, targets, work, true); err != nil {
		return err
	}

	// 2. integrity.json over the signed files (same rules and order as the release tool).
	idx := map[string]int{}
	for i, e := range entries {
		idx[e.name] = i
	}
	mi, ok := idx[internal+"integrity.json"]
	if !ok {
		return errors.New("integrity.json not found in the payload")
	}
	oldManifest := entries[mi].data
	var manifest struct {
		Files map[string]string `json:"files"`
	}
	if err := json.Unmarshal(oldManifest, &manifest); err != nil {
		return err
	}
	updated := map[string]string{}
	for rel := range manifest.Files {
		i, ok := idx[internal+rel]
		if !ok {
			return fmt.Errorf("%s is listed but not in the payload", rel)
		}
		updated[rel] = fmt.Sprintf("%x", sha256.Sum256(entries[i].data))
	}
	newManifest, err := updateManifest(oldManifest, manifest.Files, updated)
	if err != nil {
		return err
	}
	entries[mi].data = newManifest
	oldHash := fmt.Sprintf("%x", sha256.Sum256(oldManifest))
	newHash := fmt.Sprintf("%x", sha256.Sum256(newManifest))

	// 3. The launcher pins the manifest hash: replace it (same length), then sign the launcher.
	li, ok := idx["NodeWatch/NodeWatch.exe"]
	if !ok {
		return errors.New("launcher not found in the payload")
	}
	if n := bytes.Count(entries[li].data, []byte(oldHash)); n != 1 {
		return fmt.Errorf("the launcher holds the manifest hash %d times, expected once", n)
	}
	entries[li].data = bytes.Replace(entries[li].data, []byte(oldHash), []byte(newHash), 1)
	if err := signEntries(entries, []int{li}, work, false); err != nil {
		return err
	}

	// 4. The payload goes back into the installer at the same place and size; then the installer is signed.
	payload, err := writePayload(entries, size)
	if err != nil {
		return err
	}
	signed := append(append(append([]byte{}, exe[:start]...), payload...), exe[start+size:]...)
	tmp := filepath.Join(work, "NodeWatch.exe")
	if err := os.WriteFile(tmp, signed, 0o644); err != nil {
		return err
	}
	if err := authenticode([]string{tmp}); err != nil {
		return err
	}
	final, err := os.ReadFile(tmp)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, final, 0o644); err != nil {
		return err
	}
	fmt.Printf("installer signed: %d program files inside, launcher (manifest %s…), installer\n", len(targets), newHash[:12])
	return nil
}

// updateManifest changes only the hashes of the files that changed, keeping the file's exact layout and order.
func updateManifest(old []byte, oldFiles, newFiles map[string]string) ([]byte, error) {
	out := old
	for rel, h := range newFiles {
		if oldFiles[rel] == h {
			continue
		}
		key, _ := json.Marshal(rel)
		from := []byte(string(key) + `: "` + oldFiles[rel] + `"`)
		if bytes.Count(out, from) != 1 {
			return nil, fmt.Errorf("integrity.json: entry for %s not found once", rel)
		}
		out = bytes.Replace(out, from, []byte(string(key)+`: "`+h+`"`), 1)
	}
	return out, nil
}

// authenticodeValid: the file already carries an Authenticode signature (any signer).
func authenticodeValid(path string) bool {
	out, err := ps(`[bool](Get-AuthenticodeSignature -LiteralPath $env:NW_FILE).SignerCertificate`, "NW_FILE="+path)
	return err == nil && strings.TrimSpace(out) == "True"
}

// signEntries writes the entries to disk, signs the unsigned ones in one PowerShell call, and reads them back.
func signEntries(entries []entry, idx []int, work string, skipSigned bool) error {
	var paths []string
	for _, i := range idx {
		p := filepath.Join(work, "f", filepath.FromSlash(entries[i].name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		entries[i].data = clearBrokenCertificateEntry(entries[i].data)
		if err := os.WriteFile(p, entries[i].data, 0o644); err != nil {
			return err
		}
		paths = append(paths, p)
	}
	list := filepath.Join(work, "list.txt")
	if err := os.WriteFile(list, []byte(strings.Join(paths, "\r\n")), 0o644); err != nil {
		return err
	}
	skip := "0"
	if skipSigned {
		skip = "1"
	}
	out, err := ps(findCert+`
$n = 0; $kept = 0
foreach ($f in Get-Content -LiteralPath $env:NW_LIST) {
  if ($env:NW_SKIP -eq '1' -and (Get-AuthenticodeSignature -LiteralPath $f).Status -eq 'Valid') { $kept++; continue }
  $r = Set-AuthenticodeSignature -LiteralPath $f -Certificate $c -HashAlgorithm SHA256 -TimestampServer $env:NW_TSA -ErrorAction SilentlyContinue
  if (-not $r -or -not $r.TimeStamperCertificate) { $r = Set-AuthenticodeSignature -LiteralPath $f -Certificate $c -HashAlgorithm SHA256 }
  if ((Get-AuthenticodeSignature -LiteralPath $f).SignerCertificate.Thumbprint -ne $c.Thumbprint) { throw "could not sign ${f}: $($r.StatusMessage)" }
  $n++
}
"signed $n, already signed by their maker $kept"`, "NW_SUBJECT="+subject, "NW_LIST="+list, "NW_SKIP="+skip, "NW_TSA="+timestampURL)
	if err != nil {
		return err
	}
	fmt.Println("  " + out)
	for k, i := range idx {
		data, err := os.ReadFile(paths[k])
		if err != nil {
			return err
		}
		entries[i].data = data
	}
	return nil
}

func authenticode(paths []string) error {
	work := filepath.Dir(paths[0])
	list := filepath.Join(work, "single.txt")
	if err := os.WriteFile(list, []byte(strings.Join(paths, "\r\n")), 0o644); err != nil {
		return err
	}
	_, err := ps(findCert+`
foreach ($f in Get-Content -LiteralPath $env:NW_LIST) {
  $r = Set-AuthenticodeSignature -LiteralPath $f -Certificate $c -HashAlgorithm SHA256 -TimestampServer $env:NW_TSA -ErrorAction SilentlyContinue
  if (-not $r -or -not $r.TimeStamperCertificate) { $r = Set-AuthenticodeSignature -LiteralPath $f -Certificate $c -HashAlgorithm SHA256 }
  if ((Get-AuthenticodeSignature -LiteralPath $f).SignerCertificate.Thumbprint -ne $c.Thumbprint) { throw "could not sign ${f}: $($r.StatusMessage)" }
}`, "NW_SUBJECT="+subject, "NW_LIST="+list, "NW_TSA="+timestampURL)
	return err
}

// writePayload builds the zip again and pads it (between the files and the central directory) to the slot size.
func writePayload(entries []entry, size int) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: e.name, Method: zip.Deflate, Modified: e.mod})
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(e.data); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	z := buf.Bytes()
	eocd := bytes.LastIndex(z, []byte("PK\x05\x06"))
	cdSize := int(binary.LittleEndian.Uint32(z[eocd+12:]))
	cdOff := int(binary.LittleEndian.Uint32(z[eocd+16:]))
	pad := size - len(z)
	if pad < 0 {
		return nil, fmt.Errorf("the signed files are %d bytes larger than the space the installer keeps for them", -pad)
	}
	out := make([]byte, 0, size)
	out = append(out, z[:cdOff]...)
	out = append(out, make([]byte, pad)...)
	out = append(out, z[cdOff:cdOff+cdSize]...)
	tail := append([]byte{}, z[eocd:]...)
	binary.LittleEndian.PutUint32(tail[16:], uint32(cdOff+pad))
	out = append(out, tail...)
	return out, nil
}

// cleanEnv is this process's environment without PSModulePath: started from PowerShell 7, Windows PowerShell would
// otherwise load PowerShell 7's modules and lose the Cert: drive and the signing commands.
func cleanEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(kv), "PSMODULEPATH=") {
			env = append(env, kv)
		}
	}
	return env
}

// clearBrokenCertificateEntry: a file whose signature was cut off but whose header still points at it (the bundled
// zlib1.dll) cannot be signed ("not a valid Win32 application"). The loader ignores that entry, so it is cleared.
func clearBrokenCertificateEntry(pe []byte) []byte {
	if len(pe) < 0x40 || string(pe[:2]) != "MZ" {
		return pe
	}
	off := int(binary.LittleEndian.Uint32(pe[0x3c:]))
	if off+24+2 > len(pe) || string(pe[off:off+4]) != "PE\x00\x00" {
		return pe
	}
	magic := binary.LittleEndian.Uint16(pe[off+24:])
	dirs := off + 24 + 96
	if magic == 0x20b {
		dirs = off + 24 + 112
	}
	entry := dirs + 4*8 // IMAGE_DIRECTORY_ENTRY_SECURITY
	if entry+8 > len(pe) {
		return pe
	}
	at := int(binary.LittleEndian.Uint32(pe[entry:]))
	size := int(binary.LittleEndian.Uint32(pe[entry+4:]))
	if size == 0 || at+size <= len(pe) {
		return pe
	}
	out := append([]byte{}, pe...)
	binary.LittleEndian.PutUint32(out[entry:], 0)
	binary.LittleEndian.PutUint32(out[entry+4:], 0)
	return out
}

// ---------------------------------------------------------------------------------------------- menu (double-click)

func exeDir() string {
	self, err := os.Executable()
	if err != nil {
		return mustCwd()
	}
	return filepath.Dir(self)
}

func haveKeys() bool {
	_, err := os.Stat(filepath.Join(keyDir(), "minisign.key"))
	return err == nil
}

// findDownload looks for a release file next to this program, then in Downloads.
func findDownload(name string) string {
	for _, dir := range []string{exeDir(), filepath.Join(os.Getenv("USERPROFILE"), "Downloads")} {
		p := filepath.Join(dir, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

func interactive() {
	_ = os.Chdir(exeDir()) // the public files are written next to this program
	for {
		fmt.Println()
		fmt.Println("==============================================")
		fmt.Println(" NodeWatch-Sign  -  sign NodeWatch releases")
		fmt.Println("==============================================")
		if haveKeys() {
			fmt.Println(" Keys on this PC: yes")
		} else {
			fmt.Println(" Keys on this PC: not yet - start with 1")
		}
		fmt.Println()
		fmt.Println("  1  First-time setup (make your certificate and signing key)")
		fmt.Println("  2  Back up the keys to a USB drive")
		fmt.Println("  3  Sign a release (NodeWatch.exe and NodeWatch.zip)")
		fmt.Println("  4  Check a signed file")
		fmt.Println("  5  Restore the keys from a backup (new PC)")
		fmt.Println("  6  Let GitHub sign every release (copy the keys into GitHub, once)")
		fmt.Println("  0  Close")
		fmt.Println()
		choice := readLine("Type a number and press Enter: ")
		var err error
		switch choice {
		case "1":
			err = setup()
			if err == nil {
				fmt.Println()
				fmt.Println("Done. In this folder (" + exeDir() + "):")
				fmt.Println("  BWN-NodeWatch-CodeSigning.cer  -> send to the customer's IT")
				fmt.Println("  minisign.pub                   -> send to the customer")
				fmt.Println("Next: choose 2 to back up the keys.")
			}
		case "2":
			drive := readLine("Plug in the USB drive, then type its letter (for example E): ")
			drive = strings.TrimRight(strings.TrimSpace(drive), ":\\/")
			if len(drive) != 1 {
				err = errors.New("type just the drive letter, for example E")
			} else {
				err = backup(strings.ToUpper(drive) + ":\\")
			}
		case "3":
			err = menuSign()
		case "4":
			f := findDownload("NodeWatch.exe")
			if in := readLine("File to check [" + f + "] (Enter = this one): "); in != "" {
				f = strings.Trim(in, `"`)
			}
			if f == "" {
				err = errors.New("no file given")
			} else {
				err = verifyFile(f, filepath.Join(keyDir(), "minisign.pub"))
			}
		case "6":
			err = exportForGitHub()
		case "5":
			f := strings.Trim(readLine("Full path of the backup file (for example E:\\NodeWatch-signing-backup.nwsb): "), `"`)
			err = restore(f)
		case "0", "":
			return
		default:
			fmt.Println("Type 1, 2, 3, 4, 5, 6 or 0.")
			continue
		}
		if err != nil {
			fmt.Println()
			fmt.Println("PROBLEM:", err)
		}
		readLine("\nPress Enter to go back to the menu...")
	}
}

func menuSign() error {
	if !haveKeys() {
		return errors.New("no keys on this PC yet: choose 1 (first-time setup) first")
	}
	var files []string
	for _, name := range []string{"NodeWatch.exe", "NodeWatch.zip"} {
		if p := findDownload(name); p != "" {
			files = append(files, p)
		}
	}
	if len(files) == 0 {
		return fmt.Errorf("NodeWatch.exe and NodeWatch.zip were not found in %s or in Downloads. Download them from the latest release first", exeDir())
	}
	fmt.Println("Files to sign:")
	for _, f := range files {
		fmt.Println("  " + f)
	}
	if strings.ToLower(readLine("Sign these? (y/n): ")) != "y" {
		return nil
	}
	if err := signRelease(files); err != nil {
		return err
	}
	fmt.Println()
	fmt.Println("Done. Send the customer these files (same folder):")
	for _, f := range files {
		fmt.Println("  " + filepath.Base(f) + "  and  " + filepath.Base(f) + ".minisig")
	}
	return nil
}

// ---------------------------------------------------------------------------------------------- GitHub secrets

func toClipboard(text string) error {
	cmd := exec.Command(filepath.Join(systemDir(), "clip.exe"))
	cmd.Stdin = strings.NewReader(text)
	return cmd.Run()
}

// exportForGitHub puts the three values GitHub needs on the clipboard one at a time (nothing is written to disk
// except a temporary certificate file that is deleted at once). GitHub stores them encrypted as repository secrets.
func exportForGitHub() error {
	keyID, priv, err := loadSecret()
	if err != nil {
		return err
	}
	pwBytes := make([]byte, 24)
	if _, err := rand.Read(pwBytes); err != nil {
		return err
	}
	pfxPassword := base64.RawURLEncoding.EncodeToString(pwBytes)
	pfx := filepath.Join(os.TempDir(), fmt.Sprintf("nw-%x.pfx", time.Now().UnixNano()))
	defer os.Remove(pfx)
	if _, err := ps(findCert+`
$pw = ConvertTo-SecureString -String $env:NW_PW -AsPlainText -Force
Export-PfxCertificate -Cert $c -FilePath $env:NW_OUT -Password $pw | Out-Null`, "NW_SUBJECT="+subject, "NW_OUT="+pfx, "NW_PW="+pfxPassword); err != nil {
		return fmt.Errorf("export the certificate: %w", err)
	}
	cert, err := os.ReadFile(pfx)
	if err != nil {
		return err
	}
	_ = os.Remove(pfx)
	secrets := []struct{ name, value string }{
		{"NW_SIGN_PFX", base64.StdEncoding.EncodeToString(cert)},
		{"NW_SIGN_PFX_PASSWORD", pfxPassword},
		{"NW_MINISIGN_KEY", base64.StdEncoding.EncodeToString(append(append([]byte{}, keyID...), priv...))},
	}
	fmt.Println()
	fmt.Println("GitHub will sign every release with your keys. Do this once:")
	fmt.Println("  1. In your browser open:  https://github.com/evianllerena/NodeWatch/settings/secrets/actions")
	fmt.Println("  2. For each of the 3 secrets below: click \"New repository secret\", type the Name shown,")
	fmt.Println("     click in the Secret box and press Ctrl+V (the value is already copied), then \"Add secret\".")
	fmt.Println()
	for i, s := range secrets {
		if err := toClipboard(s.value); err != nil {
			return fmt.Errorf("copy to the clipboard: %w", err)
		}
		fmt.Printf("Secret %d of 3   Name:  %s   (value copied - paste it with Ctrl+V)\n", i+1, s.name)
		readLine("   Press Enter when you have clicked Add secret... ")
	}
	_ = toClipboard(" ")
	fmt.Println()
	fmt.Println("Done (the clipboard was cleared). From now on every release on GitHub is signed: NodeWatch.exe,")
	fmt.Println("NodeWatch.zip and their .minisig files. Your keys also stay on this PC; keep the USB backup.")
	return nil
}
