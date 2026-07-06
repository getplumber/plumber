package utils

import (
	"fmt"
	"io"
	"os"
)

// ReadFileLimit reads a file but returns an error if it exceeds max bytes,
// bounding memory when reading files whose size is not trusted. The open error
// is returned unwrapped so callers can still use os.IsNotExist.
func ReadFileLimit(path string, max int64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // callers pass validated or known paths
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%s exceeds the %d-byte limit", path, max)
	}
	return data, nil
}
