package cli

import (
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/joeyvictorino/tasia/internal/rules"
)

// skipDirs are directory names that recursive scanning never descends into.
var skipDirs = map[string]bool{
	".git":         true,
	".tasia":       true,
	"node_modules": true,
	"vendor":       true,
	"dist":         true,
	"build":        true,
	"__pycache__":  true,
	".terraform":   true,
}

// scanFileNames are basenames (lower-cased) that indicate a directory contains
// scannable infrastructure config.
var scanFileExts = []string{".tf"}
var scanFilePrefixes = []string{"docker-compose", "compose"}
var scanFileExact = map[string]bool{
	"dockerfile":      true,
	".env":            true,
	"caddyfile":       true,
	"nginx.conf":      true,
	"values.yaml":     true,
	"values.yml":      true,
	"ai-stack-manifest.json": true,
}

// hasScannable returns true if a filename (lower-cased) is something tasia can scan.
func hasScannable(lower string) bool {
	if scanFileExact[lower] {
		return true
	}
	for _, ext := range scanFileExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	for _, pfx := range scanFilePrefixes {
		if strings.HasPrefix(lower, pfx) {
			return true
		}
	}
	if strings.HasPrefix(lower, ".env") {
		return true
	}
	return false
}

// findScanDirs walks root and returns every directory that contains at least
// one scannable file. The root itself is always included (even if empty, to
// match non-recursive behaviour). Directories in skipDirs are pruned.
func findScanDirs(root string) []string {
	found := map[string]bool{root: true}

	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if path != root && skipDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		lower := strings.ToLower(d.Name())
		if hasScannable(lower) {
			found[filepath.Dir(path)] = true
		}
		return nil
	})

	dirs := make([]string, 0, len(found))
	for d := range found {
		dirs = append(dirs, d)
	}
	// Sort for deterministic output.
	sortStrings(dirs)
	return dirs
}

// scanRecursive discovers scannable directories under root, runs scanDir on
// each, and returns the aggregated findings with file paths made relative to
// root for readability.
func scanRecursive(root string) []rules.Finding {
	dirs := findScanDirs(root)
	var all []rules.Finding
	for _, dir := range dirs {
		findings := scanDir(dir)
		if dir != root {
			rel, err := filepath.Rel(root, dir)
			if err != nil {
				rel = dir
			}
			for i := range findings {
				findings[i].File = filepath.Join(rel, findings[i].File)
			}
		}
		all = append(all, findings...)
	}
	return all
}

// sortStrings sorts a string slice in place (avoids importing sort for one call).
func sortStrings(ss []string) {
	for i := 1; i < len(ss); i++ {
		for j := i; j > 0 && ss[j] < ss[j-1]; j-- {
			ss[j], ss[j-1] = ss[j-1], ss[j]
		}
	}
}
