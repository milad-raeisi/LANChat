package transfer

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSafeFileName(t *testing.T) {
	cases := map[string]string{
		"report.pdf":                 "report.pdf",
		"../../etc/passwd":           "passwd",
		`..\..\Windows\System32\x`:   "x",
		"C:evil.txt":                 "C_evil.txt",
		".bashrc":                    "bashrc",
		"name. ":                     "name",
		"CON":                        "_CON",
		"nul.txt":                    "_nul.txt",
		"a<b>c:d\"e|f?g*h":           "a_b_c_d_e_f_g_h",
		"evil\x1b[2J.txt":            "evil[2J.txt",
		"rtl\u202egnp.exe":           "rtlgnp.exe",
		"résumé 2026.docx":           "résumé 2026.docx",
		"/absolute/path/to/file.zip": "file.zip",
	}
	for in, want := range cases {
		got, err := SafeFileName(in)
		if err != nil || got != want {
			t.Errorf("SafeFileName(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", ".", "..", "../", "   ", "...", "/"} {
		if got, err := SafeFileName(bad); !errors.Is(err, ErrUnsafeName) {
			t.Errorf("SafeFileName(%q) = %q, %v; want ErrUnsafeName", bad, got, err)
		}
	}
	long, err := SafeFileName(strings.Repeat("é", 300) + ".txt")
	if err != nil || len(long) > maxNameBytes || !strings.HasSuffix(long, ".txt") {
		t.Fatalf("long name handling: %q (%d) %v", long, len(long), err)
	}
}

func TestIncomingVerifiesAndAvoidsCollisions(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "report.pdf"), []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	data := []byte("hello world, this is the file")
	sum := sha256.Sum256(data)
	in, err := CreateIncoming(dir, "report.pdf", int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := in.Write(5, data); !errors.Is(err, ErrOutOfOrder) {
		t.Fatalf("gap accepted: %v", err)
	}
	if err := in.Write(0, data[:10]); err != nil {
		t.Fatal(err)
	}
	if err := in.Write(10, data[10:]); err != nil {
		t.Fatal(err)
	}
	if err := in.Write(uint64(len(data)), []byte("x")); !errors.Is(err, ErrTooMuchData) {
		t.Fatalf("overflow accepted: %v", err)
	}
	final, err := in.Finish(int64(len(data)), hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(final) != "report (1).pdf" {
		t.Fatalf("collision handling: %s", final)
	}
	got, _ := os.ReadFile(final)
	if string(got) != string(data) {
		t.Fatal("content mismatch")
	}
	if runtime.GOOS == "darwin" {
		if out, err := exec.Command("xattr", "-p", "com.apple.quarantine", final).Output(); err != nil || !strings.Contains(string(out), "LANChat") {
			t.Fatalf("received file is not quarantined: %q %v", out, err)
		}
	}
	orig, _ := os.ReadFile(filepath.Join(dir, "report.pdf"))
	if string(orig) != "existing" {
		t.Fatal("existing file was overwritten")
	}
	assertNoPartFiles(t, dir)
}

func TestIncomingHashMismatchDeletes(t *testing.T) {
	dir := t.TempDir()
	in, err := CreateIncoming(dir, "a.bin", 3)
	if err != nil {
		t.Fatal(err)
	}
	_ = in.Write(0, []byte("abc"))
	if _, err := in.Finish(3, strings.Repeat("00", 32)); err == nil {
		t.Fatal("hash mismatch accepted")
	}
	assertNoPartFiles(t, dir)
	if _, err := os.Stat(filepath.Join(dir, "a.bin")); !os.IsNotExist(err) {
		t.Fatal("corrupt file left in place")
	}
}

func TestAbortAndCleanup(t *testing.T) {
	dir := t.TempDir()
	in, _ := CreateIncoming(dir, "x", 10)
	_ = in.Write(0, []byte("12345"))
	in.Abort()
	assertNoPartFiles(t, dir)
	_ = os.WriteFile(filepath.Join(dir, ".old.abc.lanchat-part"), nil, 0o600)
	if n := CleanupStale(dir); n != 1 {
		t.Fatalf("CleanupStale = %d", n)
	}
	if _, err := CreateIncoming(dir, "../x", 1); !errors.Is(err, ErrUnsafeName) {
		t.Fatal("unsafe name accepted by CreateIncoming")
	}
}

func TestOpenOutgoingRejectsDirectories(t *testing.T) {
	dir := t.TempDir()
	if _, _, _, err := OpenOutgoing(dir); err == nil {
		t.Fatal("directory accepted")
	}
	p := filepath.Join(dir, "f.txt")
	_ = os.WriteFile(p, []byte("abc"), 0o600)
	f, name, size, err := OpenOutgoing(p)
	if err != nil || name != "f.txt" || size != 3 {
		t.Fatalf("OpenOutgoing: %v %s %d", err, name, size)
	}
	_ = f.Close()
}

func assertNoPartFiles(t *testing.T, dir string) {
	t.Helper()
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".lanchat-part") {
			t.Fatalf("temporary file left behind: %s", e.Name())
		}
	}
}
