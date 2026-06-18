package cloud

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewSASUploaderRejectsBlobScope(t *testing.T) {
	// sr=b is blob-scoped; a blob name cannot be appended.
	_, err := NewSASUploader("https://acct.blob.core.windows.net/c?sr=b&sv=2022-11-02&sig=x", "CASE1", false)
	if err == nil {
		t.Fatal("expected error for blob-scoped (sr=b) SAS, got nil")
	}
}

func TestNewSASUploaderAcceptsContainerScope(t *testing.T) {
	u, err := NewSASUploader("https://acct.blob.core.windows.net/c?sr=c&sp=cw&sv=2022-11-02&sig=x", "CASE1", false)
	if err != nil {
		t.Fatalf("expected container-scoped (sr=c) SAS to be accepted, got %v", err)
	}
	u.Wait() // stop the background worker goroutine
}

func writeTempFile(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "PF-1.zip")
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

// newTestUploader points an uploader at an httptest server.
func newTestUploader(t *testing.T, serverURL string) *SASUploader {
	t.Helper()
	u, err := NewSASUploader(serverURL+"/cont?sr=c&sp=cw&sv=2022-11-02&sig=x", "PF-1", false)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestSinglePutRequestShape(t *testing.T) {
	body := []byte("evidence-bytes")
	want := md5.Sum(body)
	wantMD5 := base64.StdEncoding.EncodeToString(want[:])

	var gotMethod, gotBlobType, gotMD5, gotCT string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotBlobType = r.Header.Get("x-ms-blob-type")
		gotMD5 = r.Header.Get("Content-MD5")
		gotCT = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	u := newTestUploader(t, srv.URL)
	if err := u.putSingle(writeTempFile(t, body)); err != nil {
		t.Fatalf("putSingle: %v", err)
	}
	if gotMethod != http.MethodPut {
		t.Errorf("method = %q, want PUT", gotMethod)
	}
	if gotBlobType != "BlockBlob" {
		t.Errorf("x-ms-blob-type = %q, want BlockBlob", gotBlobType)
	}
	if gotCT != "application/octet-stream" {
		t.Errorf("Content-Type = %q", gotCT)
	}
	if gotMD5 != wantMD5 {
		t.Errorf("Content-MD5 = %q, want %q", gotMD5, wantMD5)
	}
	if string(gotBody) != string(body) {
		t.Errorf("body = %q, want %q", gotBody, body)
	}
}

func TestSinglePutRetriesOn503(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	u := newTestUploader(t, srv.URL)
	if err := u.putSingle(writeTempFile(t, []byte("x"))); err != nil {
		t.Fatalf("putSingle should succeed after retry: %v", err)
	}
	if atomic.LoadInt32(&calls) != 2 {
		t.Errorf("calls = %d, want 2 (1 failure + 1 success)", calls)
	}
}

func TestSinglePutFailsAfterExhaustingRetries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	u := newTestUploader(t, srv.URL)
	if err := u.putSingle(writeTempFile(t, []byte("x"))); err == nil {
		t.Fatal("expected error after exhausting retries, got nil")
	}
}

func TestBlobURLAppendsCaseAndFilenameAndPreservesQuery(t *testing.T) {
	u, err := NewSASUploader("https://acct.blob.core.windows.net/eviction?sr=c&sp=cw&sv=2022-11-02&sig=ab%2Bcd", "PF-1", false)
	if err != nil {
		t.Fatal(err)
	}
	got := u.blobURL("/tmp/PF-1.zip")
	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatalf("blobURL produced unparseable URL: %v", err)
	}
	if parsed.Path != "/eviction/PF-1/PF-1.zip" {
		t.Errorf("path = %q, want /eviction/PF-1/PF-1.zip", parsed.Path)
	}
	if !strings.Contains(parsed.RawQuery, "sig=ab%2Bcd") {
		t.Errorf("raw query lost SAS token: %q", parsed.RawQuery)
	}
}

func TestChunkedUploadStagesBlocksAndCommits(t *testing.T) {
	// 250 KiB of data with a 100 KiB block size => 3 blocks + 1 commit.
	data := make([]byte, 250*1024)
	for i := range data {
		data[i] = byte(i)
	}

	var blockBodies [][]byte
	var blockIDs []string
	var commitBody []byte
	var sawBlockList bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		switch r.URL.Query().Get("comp") {
		case "block":
			blockBodies = append(blockBodies, b)
			blockIDs = append(blockIDs, r.URL.Query().Get("blockid"))
		case "blocklist":
			sawBlockList = true
			commitBody = b
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	u := newTestUploader(t, srv.URL)
	u.blockSize = 100 * 1024
	if err := u.putChunked(writeTempFile(t, data)); err != nil {
		t.Fatalf("putChunked: %v", err)
	}
	if len(blockBodies) != 3 {
		t.Fatalf("staged %d blocks, want 3", len(blockBodies))
	}
	var got []byte
	for _, b := range blockBodies {
		got = append(got, b...)
	}
	if len(got) != len(data) {
		t.Errorf("reassembled %d bytes, want %d", len(got), len(data))
	}
	if !sawBlockList {
		t.Fatal("Put Block List commit was never sent")
	}
	for _, id := range blockIDs {
		if !bytesContains(commitBody, id) {
			t.Errorf("commit XML missing block id %q", id)
		}
	}
}

func bytesContains(haystack []byte, needle string) bool {
	return strings.Contains(string(haystack), needle)
}

func TestDoWithRetryHonorsDeadline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second) // stall longer than the request deadline
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	u := newTestUploader(t, srv.URL)
	u.maxRetries = 1

	start := time.Now()
	err := u.doWithRetry(100*time.Millisecond, func(ctx context.Context) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodPut, srv.URL, nil)
	})
	if err == nil {
		t.Fatal("expected deadline error, got nil")
	}
	if elapsed := time.Since(start); elapsed > 1500*time.Millisecond {
		t.Fatalf("doWithRetry did not abort on deadline; took %v", elapsed)
	}
}

func TestNewSASUploaderValidatesCaseID(t *testing.T) {
	const u = "https://acct.blob.core.windows.net/c?sr=c&sp=cw&sv=2022-11-02&sig=x"
	bad := []string{"../x", "..", ".", "a/b", "a b", "a;b"}
	for _, c := range bad {
		if _, err := NewSASUploader(u, c, false); err == nil {
			t.Errorf("caseID %q: want error, got nil", c)
		}
	}
	good := []string{"PF-1", "case_01", "a.b-c", ""}
	for _, c := range good {
		if _, err := NewSASUploader(u, c, false); err != nil {
			t.Errorf("caseID %q: want nil, got %v", c, err)
		}
	}
}

func TestWaitReturnsErrorOnUploadFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	u := newTestUploader(t, srv.URL)
	u.Upload(writeTempFile(t, make([]byte, 500))) // single-put path (under threshold)
	if err := u.Wait(); err == nil {
		t.Fatal("expected Wait to return an error after a 500 upload, got nil")
	}
}

func TestUploadDispatchPicksSingleUnderThreshold(t *testing.T) {
	var comps []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		comps = append(comps, r.URL.Query().Get("comp"))
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	u := newTestUploader(t, srv.URL)
	u.singlePutThreshold = 1024
	u.Upload(writeTempFile(t, make([]byte, 500))) // under threshold => single
	u.Wait()
	if len(comps) != 1 || comps[0] != "" {
		t.Errorf("expected one single-PUT (no comp), got %v", comps)
	}
}

func TestNewSASUploaderWarnsOnInsecure(t *testing.T) {
	r, w, _ := os.Pipe()
	old := os.Stderr
	os.Stderr = w
	_, err := NewSASUploader("https://acct.blob.core.windows.net/c?sr=c&sp=cw&sv=2022-11-02&sig=x", "PF-1", true)
	w.Close()
	os.Stderr = old
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	n, _ := r.Read(buf)
	if !strings.Contains(string(buf[:n]), "DISABLED") {
		t.Errorf("expected insecure warning on stderr, got %q", buf[:n])
	}
}

func TestUploadDispatchPicksChunkedAtThreshold(t *testing.T) {
	var sawBlock, sawList bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		switch r.URL.Query().Get("comp") {
		case "block":
			sawBlock = true
		case "blocklist":
			sawList = true
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	u := newTestUploader(t, srv.URL)
	u.singlePutThreshold = 1024
	u.blockSize = 512
	u.Upload(writeTempFile(t, make([]byte, 2000))) // over threshold => chunked
	u.Wait()
	if !sawBlock || !sawList {
		t.Errorf("expected chunked path: sawBlock=%v sawList=%v", sawBlock, sawList)
	}
}
