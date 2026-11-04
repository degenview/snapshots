package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"

	"github.com/degenview/snapshots/web"
)

// pageData is what the HTML templates receive.
type pageData struct {
	Title    string
	Heading  string
	Text     string
	ImageURL string
	Version  string
	Scripts  []string
	Setup    *setupPageData
}

type setupPageData struct {
	CanSeal      bool
	Postgres     bool
	SuggestedURL string
	URLFromEnv   bool
	DataDir      string
}

func loadTemplates() (map[string]*template.Template, error) {
	// Every page is the layout plus its own "content"; parsing them all
	// together would make the "content" definitions collide.
	pages := map[string]*template.Template{}
	files, err := fs.Glob(web.FS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	for _, p := range files {
		name := strings.TrimSuffix(path.Base(p), ".html")
		if name == "layout" {
			continue
		}
		t, err := template.New(name).ParseFS(web.FS, "templates/layout.html", p)
		if err != nil {
			return nil, fmt.Errorf("template %s: %w", name, err)
		}
		pages[name] = t
	}
	return pages, nil
}

// page renders a named page with the standard security headers already set.
func (s *Server) page(w http.ResponseWriter, r *http.Request, status int, name string, d pageData) {
	t := s.pages[name]
	if t == nil {
		s.log.Error("unknown template", "name", name)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	d.Version = s.version
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", d); err != nil {
		s.log.Error("rendering template failed", "name", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Robots-Tag", "noindex")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// Static assets -----------------------------------------------------------

type staticFile struct {
	body        []byte
	etag        string
	contentType string
}

func loadStatic() (map[string]staticFile, error) {
	files := map[string]staticFile{}
	entries, err := fs.ReadDir(web.FS, "static")
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := fs.ReadFile(web.FS, "static/"+e.Name())
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(b)
		ct := mime.TypeByExtension(path.Ext(e.Name()))
		if ct == "" {
			ct = "application/octet-stream"
		}
		files[e.Name()] = staticFile{body: b, etag: `"` + hex.EncodeToString(sum[:8]) + `"`, contentType: ct}
	}
	return files, nil
}

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	f, ok := s.static[r.PathValue("file")]
	if !ok {
		notFound(w)
		return
	}
	h := w.Header()
	h.Set("Content-Type", f.contentType)
	h.Set("ETag", f.etag)
	h.Set("Cache-Control", "no-cache") // always revalidate; the ETag makes that cheap
	if match := r.Header.Get("If-None-Match"); match == f.etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	_, _ = w.Write(f.body)
}

// handleIndex is the landing page.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if !s.Configured() {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	s.page(w, r, http.StatusOK, "message", pageData{
		Title: "Snapshots", Heading: "DegenView Snapshots",
		Text: "This is a private image host for DegenView chart snapshots.",
	})
}
