//go:build !darwin || !cgo

package mitm

import (
	"os"
	"path/filepath"
)

func keychainKeyPath(dir string) string {
	return filepath.Join(dir, "ca.key")
}

func keychainSet(dir string, data []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(keychainKeyPath(dir), data, 0o600)
}

func keychainGet(dir string) ([]byte, error) {
	data, err := os.ReadFile(keychainKeyPath(dir))
	if os.IsNotExist(err) {
		return nil, nil
	}
	return data, err
}

func keychainDelete(dir string) error {
	err := os.Remove(keychainKeyPath(dir))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
