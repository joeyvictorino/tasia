package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type graphNode struct {
	Name     string
	Category string
}

type graphEdge struct {
	From  string
	To    string
	Label string
}

type serviceGraph struct {
	Nodes []graphNode
	Edges []graphEdge
}

func buildServiceGraph(collected *collect.Collected) serviceGraph {
	var g serviceGraph
	seen := map[string]bool{}

	volumeUsers := map[string][]string{}

	for _, cf := range collected.ComposeFiles {
		for _, svc := range cf.Services {
			if seen[svc.Name] {
				continue
			}
			seen[svc.Name] = true
			g.Nodes = append(g.Nodes, graphNode{
				Name:     svc.Name,
				Category: classifyImage(svc.Image),
			})

			for _, v := range svc.Volumes {
				src, _, _ := parseVolumeSpec(v)
				if src != "" && !strings.HasPrefix(src, ".") && !strings.HasPrefix(src, "/") {
					volumeUsers[src] = append(volumeUsers[src], svc.Name)
				}
			}
		}
	}

	edgeSeen := map[string]bool{}
	for vol, users := range volumeUsers {
		if len(users) < 2 {
			continue
		}
		sort.Strings(users)
		for i := 0; i < len(users); i++ {
			for j := i + 1; j < len(users); j++ {
				key := users[i] + "->" + users[j] + ":" + vol
				if edgeSeen[key] {
					continue
				}
				edgeSeen[key] = true
				g.Edges = append(g.Edges, graphEdge{
					From:  users[i],
					To:    users[j],
					Label: "vol:" + vol,
				})
			}
		}
	}

	sort.Slice(g.Nodes, func(i, j int) bool { return g.Nodes[i].Name < g.Nodes[j].Name })
	sort.Slice(g.Edges, func(i, j int) bool {
		if g.Edges[i].From != g.Edges[j].From {
			return g.Edges[i].From < g.Edges[j].From
		}
		return g.Edges[i].To < g.Edges[j].To
	})

	return g
}

func buildServiceGraphFromFiles(files []compose.File) serviceGraph {
	c := &collect.Collected{ComposeFiles: files}
	return buildServiceGraph(c)
}

var categoryColors = map[string]string{
	"agent-runtime": "#e74c3c",
	"inference":     "#f39c12",
	"ui":            "#3498db",
	"vector-db":     "#9b59b6",
	"datastore":     "#2ecc71",
	"other":         "#95a5a6",
}

var categoryShapes = map[string]string{
	"agent-runtime": "box3d",
	"inference":     "hexagon",
	"ui":            "component",
	"vector-db":     "cylinder",
	"datastore":     "cylinder",
	"other":         "box",
}

func graphToDOT(g serviceGraph) string {
	var b strings.Builder
	b.WriteString("digraph stack {\n")
	b.WriteString("  rankdir=LR;\n")
	b.WriteString("  node [style=filled, fontname=\"Helvetica\"];\n\n")

	for _, n := range g.Nodes {
		color := categoryColors[n.Category]
		if color == "" {
			color = "#95a5a6"
		}
		shape := categoryShapes[n.Category]
		if shape == "" {
			shape = "box"
		}
		b.WriteString(fmt.Sprintf("  %q [label=%q, fillcolor=%q, shape=%s];\n",
			n.Name, n.Name+" ["+n.Category+"]", color, shape))
	}

	if len(g.Edges) > 0 {
		b.WriteString("\n")
		for _, e := range g.Edges {
			b.WriteString(fmt.Sprintf("  %q -> %q [label=%q, style=dashed];\n",
				e.From, e.To, e.Label))
		}
	}

	b.WriteString("}\n")
	return b.String()
}

func graphToMermaid(g serviceGraph) string {
	var b strings.Builder
	b.WriteString("graph LR\n")

	mermaidShapes := map[string][2]string{
		"agent-runtime": {"{{", "}}"},
		"inference":     {"[/", "/]"},
		"ui":            {"[", "]"},
		"vector-db":     {"[(", ")]"},
		"datastore":     {"[(", ")]"},
		"other":         {"[", "]"},
	}

	for _, n := range g.Nodes {
		shape := mermaidShapes[n.Category]
		if shape == [2]string{} {
			shape = [2]string{"[", "]"}
		}
		id := sanitizeMermaidID(n.Name)
		b.WriteString(fmt.Sprintf("  %s%s%s %s%s\n",
			id, shape[0], n.Name+" : "+n.Category, shape[1], ""))
	}

	for _, e := range g.Edges {
		from := sanitizeMermaidID(e.From)
		to := sanitizeMermaidID(e.To)
		b.WriteString(fmt.Sprintf("  %s -. %s .-> %s\n", from, e.Label, to))
	}

	return b.String()
}

func sanitizeMermaidID(s string) string {
	r := strings.NewReplacer("-", "_", ".", "_", " ", "_")
	return r.Replace(s)
}

func graphToText(g serviceGraph) string {
	var b strings.Builder

	byCategory := map[string][]string{}
	for _, n := range g.Nodes {
		byCategory[n.Category] = append(byCategory[n.Category], n.Name)
	}

	cats := make([]string, 0, len(byCategory))
	for c := range byCategory {
		cats = append(cats, c)
	}
	sort.Strings(cats)

	b.WriteString(fmt.Sprintf("Stack graph (%d services):\n\n", len(g.Nodes)))
	for _, cat := range cats {
		svcs := byCategory[cat]
		sort.Strings(svcs)
		b.WriteString(fmt.Sprintf("  [%s]\n", cat))
		for _, s := range svcs {
			b.WriteString(fmt.Sprintf("    %s\n", s))
		}
	}

	if len(g.Edges) > 0 {
		b.WriteString(fmt.Sprintf("\nConnections (%d):\n", len(g.Edges)))
		for _, e := range g.Edges {
			b.WriteString(fmt.Sprintf("  %s <-> %s  (%s)\n", e.From, e.To, e.Label))
		}
	}

	return b.String()
}

func runGraph(args []string) error {
	fs := flag.NewFlagSet("graph", flag.ContinueOnError)
	path := fs.String("path", ".", "path to scan")
	format := fs.String("format", "text", "output format: text, dot, or mermaid")
	recursive := fs.Bool("recursive", false, "scan nested directories")
	if err := fs.Parse(args); err != nil {
		return err
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	var collected *collect.Collected
	if *recursive {
		dirs := findScanDirs(absPath)
		merged := &collect.Collected{Root: absPath}
		for _, d := range dirs {
			c, err := collect.WalkAndCollect(d)
			if err != nil {
				continue
			}
			merged.ComposeFiles = append(merged.ComposeFiles, c.ComposeFiles...)
		}
		collected = merged
	} else {
		collected, err = collect.WalkAndCollect(absPath)
		if err != nil {
			return err
		}
	}

	if len(collected.ParseErrors) > 0 {
		fmt.Fprintln(os.Stderr, "tasia graph: cannot parse config; fix parse errors first")
		os.Exit(2)
	}

	g := buildServiceGraph(collected)

	switch *format {
	case "dot":
		fmt.Print(graphToDOT(g))
	case "mermaid":
		fmt.Print(graphToMermaid(g))
	default:
		fmt.Print(graphToText(g))
	}
	return nil
}
