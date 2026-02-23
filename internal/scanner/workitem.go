package scanner

// WorkItem represents a single unit of work for the worker pool.
type WorkItem struct {
	Method string // HTTP method (GET, POST, etc.). Empty defaults to GET.
	Path   string // URL path to fuzz.
	Host   string // Override Host header. Empty means use default.
}
