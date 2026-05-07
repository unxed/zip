package zip

import (
	"bytes"
	"testing"
)

func TestNtfsAcl_SerDes(t *testing.T) {
	fakeAcl := []byte{0x01, 0x00, 0x04, 0x80, 0x30, 0x00, 0x00, 0x00} // Mock SD
	extra := appendNtfsAcl(nil, fakeAcl)

	parsed := parseNtfsAcl(extra)
	if !bytes.Equal(parsed, fakeAcl) {
		t.Errorf("NTFS ACL mismatch. Got %x, want %x", parsed, fakeAcl)
	}
}

func TestWriter_NtfsAclIntegration(t *testing.T) {
	buf := new(bytes.Buffer)
	zw := NewWriter(buf)

	acl := []byte("windows-security-descriptor")
	fh := &FileHeader{
		Name: "acl.txt",
		Acl:  acl,
	}
	zw.CreateHeader(fh)
	zw.Close()

	zr, _ := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if !bytes.Equal(zr.File[0].Acl, acl) {
		t.Errorf("Acl field was not recovered: %q", string(zr.File[0].Acl))
	}
}