package output

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

type treeNode struct {
	name     string
	children []*treeNode
}

func (n *treeNode) findOrCreate(name string) *treeNode {
	for _, c := range n.children {
		if c.name == name {
			return c
		}
	}
	child := &treeNode{name: name}
	n.children = append(n.children, child)
	return child
}

// PrintTree renders a directory tree to w from a list of discovered directory
// paths (e.g. ["admin", "admin/config", "js", "js/asset"]).
func PrintTree(w io.Writer, dirs []string) {
	if len(dirs) == 0 {
		return
	}

	sort.Strings(dirs)

	// Deduplicate.
	seen := make(map[string]bool, len(dirs))
	unique := make([]string, 0, len(dirs))
	for _, d := range dirs {
		d = strings.TrimRight(d, "/")
		if d != "" && !seen[d] {
			unique = append(unique, d)
			seen[d] = true
		}
	}

	root := &treeNode{name: "/"}
	for _, d := range unique {
		parts := strings.Split(d, "/")
		node := root
		for _, p := range parts {
			node = node.findOrCreate(p)
		}
	}

	fmt.Fprintf(w, "\n  Discovered directories:\n")
	printChildren(w, root, "  ")
}

func printChildren(w io.Writer, node *treeNode, prefix string) {
	for i, child := range node.children {
		isLast := i == len(node.children)-1
		connector := "├── "
		if isLast {
			connector = "└── "
		}
		fmt.Fprintf(w, "%s%s%s\n", prefix, connector, child.name)
		nextPrefix := prefix + "│   "
		if isLast {
			nextPrefix = prefix + "    "
		}
		printChildren(w, child, nextPrefix)
	}
}
