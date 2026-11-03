package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/xmlinjection"
)

func runXmlinjection(args []string) error {
	fs := flag.NewFlagSet("tasia xmlinjection", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runXmlinjectionRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("xmlinjection: %w", err)
	}

	r := xmlinjection.Analyze(c)
	printXmlinjectionResult(r, *format)
	return nil
}

func runXmlinjectionRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "xmlinjection: skipping %s: %v\n", d, err)
			continue
		}
		r := xmlinjection.Analyze(c)
		printXmlinjectionResult(r, format)
	}
	return nil
}

func printXmlinjectionResult(r xmlinjection.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(xmlinjection.FormatText(r))
	}
}
