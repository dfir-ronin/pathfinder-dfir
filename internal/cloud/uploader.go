package cloud

// Uploader uploads evidence files to a remote destination asynchronously.
// Upload is non-blocking; Wait drains the queue before program exit and returns
// the combined error of any uploads that failed (nil if all succeeded).
type Uploader interface {
	Upload(path string)
	Wait() error
}
