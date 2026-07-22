package cache

import (
	"encoding/gob"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"govibe/pkg/models"
)

type CacheFile struct {
	Version int
	Data    models.DomainData
}

func CachePath(outputDir, domain string) string {
	return filepath.Join(outputDir, strings.ToLower(domain)+".govibe")
}

func SaveCache(outputDir, domain string, data *models.DomainData) error {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output dir: %w", err)
	}

	path := CachePath(outputDir, domain)
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create cache file: %w", err)
	}
	defer f.Close()

	cf := CacheFile{Version: 1, Data: *data}
	if err := gob.NewEncoder(f).Encode(cf); err != nil {
		return fmt.Errorf("failed to encode cache: %w", err)
	}

	return nil
}

func LoadCache(outputDir, domain string) (*models.DomainData, error) {
	path := CachePath(outputDir, domain)
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open cache file: %w", err)
	}
	defer f.Close()

	var cf CacheFile
	if err := gob.NewDecoder(f).Decode(&cf); err != nil {
		return nil, fmt.Errorf("failed to decode cache: %w", err)
	}

	return &cf.Data, nil
}

func RemoveCache(outputDir, domain string) error {
	path := CachePath(outputDir, domain)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("no cache found for %s at %s", domain, path)
	}
	return os.Remove(path)
}
