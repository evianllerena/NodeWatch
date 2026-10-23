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
		usage()
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

func readPassword(prompt string) string {
	fmt.Print(prompt)
	var pw string
	fmt.Scanln(&pw)
	return pw
}

func backupKey(pw string, salt []byte) ([]byte, error) { return pbkdf2.Key(sha512.New, pw, salt, 600000, 32) }

// backup writes both keys (the certificate with its private key, and the minisign key) into one file encrypted
// with a password you choose. Keep it offline (a USB drive in a safe place); restore it with "restore".
func backup(folder string) error {
	pw := readPassword("Password for the backup (at least 12 characters): ")
	if len(pw) < 12 {
		return errors.New("use at least 12 characters")
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
