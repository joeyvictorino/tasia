package cli

import (
	"flag"
	"fmt"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/apiserver"
)

func runAPI(args []string) error {
	fs := flag.NewFlagSet("api", flag.ContinueOnError)
	path := fs.String("path", ".", "path to scan")
	port := fs.Int("port", 8080, "HTTP listen port")
	recursive := fs.Bool("recursive", false, "scan nested directories")
	corsOrigin := fs.String("cors-origin", "*", "Access-Control-Allow-Origin header value")
	if err := fs.Parse(args); err != nil {
		return err
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	srv := apiserver.NewServer(absPath, *port, *recursive)
	srv.CORSOrigin = *corsOrigin

	fmt.Printf("tasia API server listening on :%d (scanning %s)\n", *port, absPath)
	fmt.Printf("  GET /api/v1/health\n")
	fmt.Printf("  GET /api/v1/scan\n")
	fmt.Printf("  GET /api/v1/findings[?severity=X&rule=Y]\n")
	fmt.Printf("  GET /api/v1/rules\n")
	fmt.Printf("  GET /api/v1/stats\n")
	return srv.Start()
}
