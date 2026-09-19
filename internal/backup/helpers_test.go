package backup

import (
	"bytes"
	"compress/gzip"
	"io"
	"testing"
)

// expand returns the uncompressed tar stream, so a test can look for a string
// in what the archive actually holds rather than in its compressed form.
func expand(t *testing.T, gzipped []byte) []byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(gzipped))
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	out, err := io.ReadAll(gz)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func recompress(t *testing.T, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
