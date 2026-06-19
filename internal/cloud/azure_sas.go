package cloud

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"sync"
	"time"
)

const (
	singlePutThreshold = 256 << 20 // 256 MiB: max single Put Blob across all SAS versions
	blockSize          = 100 << 20 // 100 MiB per staged block
	maxRetries         = 3
)

var caseIDRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// uploadTimeout sizes a per-request deadline to the payload: a 120s base plus a
// deliberately generous 1 MiB/s throughput floor for slow or satellite DFIR
// links, capped at 6h so a stalled transfer cannot hang the run.
func uploadTimeout(payloadBytes int64) time.Duration {
	const floorBytesPerSec = 1 << 20
	t := 120*time.Second + time.Duration(payloadBytes/floorBytesPerSec)*time.Second
	if t > 6*time.Hour {
		return 6 * time.Hour
	}
	return t
}

// SASUploader streams final evidence artifacts to an Azure container-scoped SAS URL.
// It implements cloud.Uploader. Uploads run on a single background worker so the
// FIFO enqueue order (manifest, then zip) is preserved.
type SASUploader struct {
	base   *url.URL // parsed SAS URL (container-scoped)
	caseID string
	client *http.Client
	queue  chan string
	wg     sync.WaitGroup
	mu     sync.Mutex
	errs   []error

	// tunables, overridable in tests
	singlePutThreshold int64
	blockSize          int64
	maxRetries         int
}

// NewSASUploader validates the SAS URL is container-scoped (sr=c) and starts the
// background upload worker. insecure disables TLS verification (opt-in only).
func NewSASUploader(sasURL, caseID string, insecure bool) (*SASUploader, error) {
	base, err := url.Parse(sasURL)
	if err != nil {
		return nil, fmt.Errorf("azure sas url parse: %w", err)
	}
	if sr := base.Query().Get("sr"); sr != "c" {
		return nil, fmt.Errorf("azure sas url must be container-scoped (sr=c), got sr=%q; blob-scoped SAS cannot take an appended blob name", sr)
	}
	if caseID != "" && (caseID == "." || caseID == ".." || !caseIDRe.MatchString(caseID)) {
		return nil, fmt.Errorf("invalid caseID %q: must match [A-Za-z0-9._-] and not be \".\" or \"..\"", caseID)
	}
	if insecure {
		fmt.Fprintln(os.Stderr, "[!] WARNING: Azure TLS certificate verification is DISABLED. Evidence is uploaded without verifying server identity.")
	}
	u := &SASUploader{
		base:   base,
		caseID: caseID,
		client: &http.Client{
			Transport: &http.Transport{
				DialContext:           (&net.Dialer{Timeout: 30 * time.Second}).DialContext,
				TLSHandshakeTimeout:   30 * time.Second,
				ResponseHeaderTimeout: 5 * time.Minute,
				TLSClientConfig:       &tls.Config{InsecureSkipVerify: insecure}, //nolint:gosec
			},
		},
		queue:              make(chan string, 128),
		singlePutThreshold: singlePutThreshold,
		blockSize:          blockSize,
		maxRetries:         maxRetries,
	}
	u.wg.Add(1)
	go u.worker()
	return u, nil
}

// blobURLWith returns the destination blob URL (SAS container path + caseID +
// filename) with extra query parameters merged into the preserved SAS query.
// Using url.Values handles escaping and an empty base query correctly.
func (u *SASUploader) blobURLWith(localPath string, extra url.Values) string {
	dst := *u.base // copy
	dst.Path = path.Join(dst.Path, u.caseID, path.Base(localPath))
	q := dst.Query()
	for k, vs := range extra {
		for _, v := range vs {
			q.Set(k, v)
		}
	}
	dst.RawQuery = q.Encode()
	return dst.String()
}

func (u *SASUploader) blobURL(localPath string) string {
	return u.blobURLWith(localPath, nil)
}

func (u *SASUploader) worker() {
	defer u.wg.Done()
	for p := range u.queue {
		if err := u.uploadOne(p); err != nil {
			fmt.Fprintf(os.Stderr, "[!] azure upload failed (%s): %v\n", p, err)
			u.mu.Lock()
			u.errs = append(u.errs, fmt.Errorf("upload %s: %w", p, err))
			u.mu.Unlock()
		}
	}
}

func (u *SASUploader) uploadOne(localPath string) error {
	fi, err := os.Stat(localPath)
	if err != nil {
		return err
	}
	if fi.Size() <= u.singlePutThreshold {
		return u.putSingle(localPath)
	}
	return u.putChunked(localPath)
}

// Upload enqueues a final artifact for asynchronous upload. Never blocks collection.
func (u *SASUploader) Upload(localPath string) {
	select {
	case u.queue <- localPath:
	default:
		fmt.Fprintf(os.Stderr, "[!] azure upload queue full, skipping: %s\n", localPath)
		u.mu.Lock()
		u.errs = append(u.errs, fmt.Errorf("upload queue full, skipped: %s", localPath))
		u.mu.Unlock()
	}
}

// Wait closes the queue and blocks until all pending uploads finish. It returns the
// combined error of any uploads that failed or were dropped (nil if all succeeded).
func (u *SASUploader) Wait() error {
	close(u.queue)
	u.wg.Wait()
	u.mu.Lock()
	defer u.mu.Unlock()
	return errors.Join(u.errs...)
}

// fileMD5 streams the file once and returns the base64-encoded MD5 digest.
func fileMD5(localPath string) (string, error) {
	f, err := os.Open(localPath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

// putSingle uploads localPath in one Put Blob request with a Content-MD5 guard.
func (u *SASUploader) putSingle(localPath string) error {
	md5b64, err := fileMD5(localPath)
	if err != nil {
		return err
	}
	fi, err := os.Stat(localPath)
	if err != nil {
		return err
	}
	dst := u.blobURL(localPath)
	return u.doWithRetry(uploadTimeout(fi.Size()), func(ctx context.Context) (*http.Request, error) {
		f, err := os.Open(localPath)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, dst, f)
		if err != nil {
			f.Close()
			return nil, err
		}
		req.ContentLength = fi.Size() // forces Content-Length, not chunked encoding
		req.Header.Set("x-ms-blob-type", "BlockBlob")
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("Content-MD5", md5b64)
		req.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
		return req, nil
	})
}

// doWithRetry runs makeReq with bounded retries under a per-attempt deadline.
// Network errors and HTTP 5xx are retried with exponential backoff; 4xx fail
// immediately. makeReq must build a fresh request (with the supplied ctx) and
// reopen any file body on each call so retries are clean.
func (u *SASUploader) doWithRetry(timeout time.Duration, makeReq func(ctx context.Context) (*http.Request, error)) error {
	var lastErr error
	for attempt := 1; attempt <= u.maxRetries; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		req, err := makeReq(ctx)
		if err != nil {
			cancel()
			return err
		}
		resp, err := u.client.Do(req)
		if err != nil {
			cancel()
			lastErr = err
			if attempt < u.maxRetries {
				time.Sleep(backoff(attempt))
			}
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		cancel() // safe: body fully drained and closed
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		lastErr = fmt.Errorf("azure put: status %d", resp.StatusCode)
		if resp.StatusCode < 500 {
			return lastErr // client error, do not retry
		}
		if attempt < u.maxRetries {
			time.Sleep(backoff(attempt))
		}
	}
	return lastErr
}

func backoff(attempt int) time.Duration {
	return time.Duration(200*(1<<(attempt-1))) * time.Millisecond
}

type blockList struct {
	XMLName xml.Name `xml:"BlockList"`
	Latest  []string `xml:"Latest"`
}

// putChunked stages the file as a sequence of blocks (Put Block) then commits them
// with Put Block List. A running whole-file MD5 is set as x-ms-blob-content-md5 on
// commit for chain-of-custody. Each block carries its own Content-MD5 transfer guard.
func (u *SASUploader) putChunked(localPath string) error {
	f, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer f.Close()

	whole := md5.New()
	var ids []string
	buf := make([]byte, u.blockSize)
	for i := 0; ; i++ {
		n, readErr := io.ReadFull(f, buf)
		if n == 0 {
			if readErr == io.EOF {
				break
			}
			if readErr != nil && readErr != io.ErrUnexpectedEOF {
				return readErr
			}
		}
		block := buf[:n]
		whole.Write(block)

		id := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%06d", i)))
		ids = append(ids, id)
		blockSum := md5.Sum(block)
		blockMD5 := base64.StdEncoding.EncodeToString(blockSum[:])
		blockURL := u.blobURLWith(localPath, url.Values{"comp": {"block"}, "blockid": {id}})

		err := u.doWithRetry(uploadTimeout(int64(n)), func(ctx context.Context) (*http.Request, error) {
			// buf[:n] is stable across retries: doWithRetry returns before the next read overwrites it
			req, err := http.NewRequestWithContext(ctx, http.MethodPut, blockURL, bytes.NewReader(block))
			if err != nil {
				return nil, err
			}
			req.ContentLength = int64(n)
			req.Header.Set("Content-MD5", blockMD5)
			return req, nil
		})
		if err != nil {
			return fmt.Errorf("stage block %d: %w", i, err)
		}

		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
	}

	xmlBody, err := xml.Marshal(blockList{Latest: ids})
	if err != nil {
		return err
	}
	wholeMD5 := base64.StdEncoding.EncodeToString(whole.Sum(nil))
	commitURL := u.blobURLWith(localPath, url.Values{"comp": {"blocklist"}})
	return u.doWithRetry(uploadTimeout(int64(len(xmlBody))), func(ctx context.Context) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, commitURL, bytes.NewReader(xmlBody))
		if err != nil {
			return nil, err
		}
		req.ContentLength = int64(len(xmlBody))
		req.Header.Set("Content-Type", "application/xml")
		req.Header.Set("x-ms-blob-content-type", "application/octet-stream")
		req.Header.Set("x-ms-blob-content-md5", wholeMD5)
		return req, nil
	})
}
