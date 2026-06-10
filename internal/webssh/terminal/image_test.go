package terminal

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveImageWritesFile(t *testing.T) {
	dir := t.TempDir()
	h := NewHandler(Config{Shell: "pwsh", UploadsDir: dir, MaxUpload: 25 << 20})

	// A small payload; content fidelity matters more than it being a real PNG.
	want := []byte("\x89PNG\r\n\x1a\nhello-bytes")
	data := base64.StdEncoding.EncodeToString(want)

	path, err := h.saveImage("image/png", data)
	if err != nil {
		t.Fatalf("saveImage: %v", err)
	}
	if filepath.Dir(path) != dir {
		t.Fatalf("path %q not in uploads dir %q", path, dir)
	}
	if !strings.HasSuffix(path, ".png") {
		t.Fatalf("expected .png extension, got %q", path)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("content mismatch: got %q want %q", got, want)
	}
}

func TestSaveImageExtensionFromMime(t *testing.T) {
	dir := t.TempDir()
	h := NewHandler(Config{Shell: "pwsh", UploadsDir: dir, MaxUpload: 25 << 20})
	data := base64.StdEncoding.EncodeToString([]byte("x"))

	cases := map[string]string{
		"image/png":  ".png",
		"image/jpeg": ".jpg",
		"image/gif":  ".gif",
		"image/webp": ".webp",
		"image/tiff": ".png", // unknown -> default
	}
	for mime, ext := range cases {
		path, err := h.saveImage(mime, data)
		if err != nil {
			t.Fatalf("saveImage(%s): %v", mime, err)
		}
		if !strings.HasSuffix(path, ext) {
			t.Errorf("mime %s: expected %s, got %q", mime, ext, path)
		}
	}
}

func TestSaveImageTooLarge(t *testing.T) {
	dir := t.TempDir()
	h := NewHandler(Config{Shell: "pwsh", UploadsDir: dir, MaxUpload: 4}) // 4-byte cap
	data := base64.StdEncoding.EncodeToString([]byte("more than four bytes"))

	if _, err := h.saveImage("image/png", data); err == nil {
		t.Fatal("expected an error for oversized image")
	}
}

func TestSaveImageEmpty(t *testing.T) {
	dir := t.TempDir()
	h := NewHandler(Config{Shell: "pwsh", UploadsDir: dir, MaxUpload: 25 << 20})
	path, err := h.saveImage("image/png", "")
	if err != nil || path != "" {
		t.Fatalf("empty image: got path=%q err=%v, want empty/no-op", path, err)
	}
}

func TestInjectTextQuoting(t *testing.T) {
	if got := injectText(`C:\tmp\paste-ab.png`); got != `C:\tmp\paste-ab.png ` {
		t.Errorf("no-space path: got %q", got)
	}
	if got := injectText(`C:\Program Files\x.png`); got != `"C:\Program Files\x.png" ` {
		t.Errorf("spaced path: got %q", got)
	}
}
