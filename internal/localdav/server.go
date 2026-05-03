package localdav

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/example/seavault-fast/internal/vault"
)

type Server struct {
	Vault    *vault.Vault
	ReadOnly bool
	Prefix   string
	mu       sync.Mutex
}

func New(v *vault.Vault) *Server {
	return &Server{Vault: v}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("DAV", "1, 2")
	w.Header().Set("MS-Author-Via", "DAV")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	switch r.Method {
	case http.MethodOptions:
		w.Header().Set("Allow", "OPTIONS, PROPFIND, GET, HEAD, PUT, DELETE, MKCOL, MOVE, COPY, LOCK, UNLOCK")
		w.WriteHeader(http.StatusNoContent)
	case "PROPFIND":
		s.handlePropfind(w, r)
	case http.MethodGet, http.MethodHead:
		s.handleGet(w, r)
	case http.MethodPut:
		if s.rejectReadOnly(w) {
			return
		}
		s.handlePut(w, r)
	case http.MethodDelete:
		if s.rejectReadOnly(w) {
			return
		}
		s.handleDelete(w, r)
	case "MKCOL":
		if s.rejectReadOnly(w) {
			return
		}
		s.handleMkcol(w, r)
	case "MOVE":
		if s.rejectReadOnly(w) {
			return
		}
		s.handleCopyMove(w, r, true)
	case "COPY":
		if s.rejectReadOnly(w) {
			return
		}
		s.handleCopyMove(w, r, false)
	case "LOCK":
		s.handleLock(w, r)
	case "UNLOCK":
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not implemented", http.StatusNotImplemented)
	}
}

func (s *Server) rejectReadOnly(w http.ResponseWriter) bool {
	if !s.ReadOnly {
		return false
	}
	http.Error(w, "this WebDAV view is read-only", http.StatusForbidden)
	return true
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	vp, err := s.requestVirtualPath(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	files, err := s.Vault.AllEntries()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if rec, ok := files[vp]; ok && !vault.IsInternalVirtualPath(vp) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", rec.Size))
		w.Header().Set("ETag", etagForRecord(vp, rec))
		if t, err := time.Parse(time.RFC3339Nano, rec.ModTime); err == nil {
			w.Header().Set("Last-Modified", t.UTC().Format(http.TimeFormat))
		}
		if r.Method == http.MethodHead {
			return
		}
		if err := s.Vault.WriteFileTo(vp, w); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	if vp == "" || directoryExists(files, vp) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.Method == http.MethodHead {
			return
		}
		_ = writeDirectoryHTML(w, s, files, vp)
		return
	}
	http.NotFound(w, r)
}

func (s *Server) handlePut(w http.ResponseWriter, r *http.Request) {
	vp, err := s.requestVirtualPath(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if vp == "" {
		http.Error(w, "cannot PUT to vault root", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, existed, _ := s.Vault.FileInfo(vp)
	size := r.ContentLength
	if size < 0 {
		size = -1
	}
	if _, err := s.Vault.PutReader(r.Body, vp, size, 0o600, time.Now().UTC()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if existed {
		w.WriteHeader(http.StatusNoContent)
	} else {
		w.WriteHeader(http.StatusCreated)
	}
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	vp, err := s.requestVirtualPath(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.Vault.RemovePath(vp); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMkcol(w http.ResponseWriter, r *http.Request) {
	vp, err := s.requestVirtualPath(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if vp == "" {
		http.Error(w, "root collection already exists; use content/ as the writable workspace", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exists, err := s.Vault.DirectoryExists(vp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if exists {
		http.Error(w, "collection already exists", http.StatusMethodNotAllowed)
		return
	}
	if err := s.Vault.EnsureDirectory(vp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) handleCopyMove(w http.ResponseWriter, r *http.Request, move bool) {
	src, err := s.requestVirtualPath(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	destination := strings.TrimSpace(r.Header.Get("Destination"))
	if destination == "" {
		http.Error(w, "Destination header is required", http.StatusBadRequest)
		return
	}
	dst, err := s.virtualPathFromDestination(destination)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if dst == "" || (move && src == "") {
		http.Error(w, "invalid source or destination", http.StatusBadRequest)
		return
	}
	if move && (dst == src || strings.HasPrefix(dst+"/", src+"/")) {
		http.Error(w, "cannot move a path into itself", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	copied, err := s.copyPath(src, dst)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if move {
		if _, err := s.Vault.RemovePath(src); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if copied == 0 {
		http.Error(w, "source path not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) copyPath(src, dst string) (int, error) {
	files, err := s.Vault.AllEntries()
	if err != nil {
		return 0, err
	}
	if vault.IsInternalVirtualPath(src) || vault.IsInternalVirtualPath(dst) {
		return 0, fmt.Errorf("reserved paths cannot be copied")
	}
	if rec, ok := files[src]; ok && !vault.IsInternalVirtualPath(src) {
		return 1, s.copyFile(src, dst, rec)
	}
	if !directoryExists(files, src) {
		return 0, fmt.Errorf("source path %q not found", src)
	}
	if err := s.Vault.EnsureDirectory(dst); err != nil {
		return 0, err
	}
	prefix := src
	if prefix != "" {
		prefix += "/"
	}
	count := 0
	keys := make([]string, 0, len(files))
	for p := range files {
		if prefix == "" || strings.HasPrefix(p, prefix) {
			keys = append(keys, p)
		}
	}
	sort.Strings(keys)
	for _, p := range keys {
		rel := p
		if prefix != "" {
			rel = strings.TrimPrefix(p, prefix)
		}
		if rel == "" {
			continue
		}
		if vault.IsDirectoryMarkerPath(p) {
			dirRel := strings.TrimSuffix(rel, "/"+vault.DirectoryMarkerName)
			if dirRel == vault.DirectoryMarkerName {
				dirRel = ""
			}
			if err := s.Vault.EnsureDirectory(path.Join(dst, dirRel)); err != nil {
				return count, err
			}
			continue
		}
		destPath := path.Join(dst, rel)
		if err := s.copyFile(p, destPath, files[p]); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

func (s *Server) copyFile(src, dst string, rec vault.FileRecord) error {
	pr, pw := io.Pipe()
	errc := make(chan error, 1)
	go func() {
		err := s.Vault.WriteFileTo(src, pw)
		_ = pw.CloseWithError(err)
		errc <- err
	}()
	modTime := time.Now().UTC()
	if t, err := time.Parse(time.RFC3339Nano, rec.ModTime); err == nil {
		modTime = t
	}
	_, putErr := s.Vault.PutReader(pr, dst, rec.Size, rec.Mode, modTime)
	writeErr := <-errc
	if putErr != nil {
		return putErr
	}
	return writeErr
}

func (s *Server) handleLock(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", `application/xml; charset="utf-8"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?><D:prop xmlns:D="DAV:"><D:lockdiscovery/></D:prop>`))
}

func (s *Server) handlePropfind(w http.ResponseWriter, r *http.Request) {
	vp, err := s.requestVirtualPath(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	depth := r.Header.Get("Depth")
	if depth == "" {
		depth = "1"
	}
	s.mu.Lock()
	files, err := s.Vault.AllEntries()
	s.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	responses, ok := propfindResponses(files, vp, depth, s.basePrefix())
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", `application/xml; charset="utf-8"`)
	w.WriteHeader(207)
	_, _ = w.Write([]byte(xml.Header))
	_, _ = w.Write([]byte(`<D:multistatus xmlns:D="DAV:">`))
	for _, resp := range responses {
		writeResponse(w, resp)
	}
	_, _ = w.Write([]byte(`</D:multistatus>`))
}

type responseInfo struct {
	Href    string
	IsDir   bool
	Size    int64
	ModTime string
	ETag    string
}

func propfindResponses(files map[string]vault.FileRecord, vp string, depth string, base string) ([]responseInfo, bool) {
	vp = strings.Trim(vp, "/")
	var out []responseInfo
	if rec, ok := files[vp]; ok && !vault.IsInternalVirtualPath(vp) {
		out = append(out, responseInfo{Href: href(base, vp, false), IsDir: false, Size: rec.Size, ModTime: rec.ModTime, ETag: etagForRecord(vp, rec)})
		return out, true
	}

	if !directoryExists(files, vp) {
		return nil, false
	}
	out = append(out, responseInfo{Href: href(base, vp, true), IsDir: true})
	if depth == "0" {
		return out, true
	}

	prefix := vp
	if prefix != "" {
		prefix += "/"
	}
	childDirs := map[string]bool{}
	var childFiles []responseInfo
	for p, rec := range files {
		if prefix != "" && !strings.HasPrefix(p, prefix) {
			continue
		}
		rest := p
		if prefix != "" {
			rest = strings.TrimPrefix(p, prefix)
		}
		if rest == "" {
			continue
		}
		if vault.IsDirectoryMarkerPath(p) {
			dirRest := strings.TrimSuffix(rest, "/"+vault.DirectoryMarkerName)
			if dirRest == vault.DirectoryMarkerName {
				continue
			}
			if dirRest != "" {
				first := dirRest
				if slash := strings.Index(first, "/"); slash >= 0 {
					first = first[:slash]
				}
				childDirs[path.Join(vp, first)] = true
			}
			continue
		}
		if vault.IsInternalVirtualPath(p) {
			continue
		}
		if slash := strings.Index(rest, "/"); slash >= 0 {
			childDirs[path.Join(vp, rest[:slash])] = true
			continue
		}
		childFiles = append(childFiles, responseInfo{Href: href(base, path.Join(vp, rest), false), IsDir: false, Size: rec.Size, ModTime: rec.ModTime, ETag: etagForRecord(path.Join(vp, rest), rec)})
	}
	var dirs []string
	for d := range childDirs {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	for _, d := range dirs {
		out = append(out, responseInfo{Href: href(base, d, true), IsDir: true})
	}
	sort.Slice(childFiles, func(i, j int) bool { return childFiles[i].Href < childFiles[j].Href })
	out = append(out, childFiles...)
	return out, true
}

func directoryExists(files map[string]vault.FileRecord, vp string) bool {
	if vp == "" {
		return true
	}
	if _, ok := files[path.Join(vp, vault.DirectoryMarkerName)]; ok {
		return true
	}
	prefix := strings.TrimSuffix(vp, "/") + "/"
	for p := range files {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

func (s *Server) requestVirtualPath(r *http.Request) (string, error) {
	p, err := url.PathUnescape(r.URL.Path)
	if err != nil {
		return "", err
	}
	base := s.basePrefix()
	if base != "" && strings.HasPrefix(p, base) {
		p = strings.TrimPrefix(p, base)
	}
	p = strings.TrimPrefix(p, "/")
	return cleanDAVVirtualPath(p)
}

func (s *Server) virtualPathFromDestination(destination string) (string, error) {
	p := destination
	if u, err := url.Parse(destination); err == nil && u.Path != "" {
		p = u.Path
	}
	p, err := url.PathUnescape(p)
	if err != nil {
		return "", err
	}
	base := s.basePrefix()
	if base != "" && strings.HasPrefix(p, base) {
		p = strings.TrimPrefix(p, base)
	}
	p = strings.TrimPrefix(p, "/")
	return cleanDAVVirtualPath(p)
}

func cleanDAVVirtualPath(input string) (string, error) {
	if strings.Trim(strings.ReplaceAll(input, "\\", "/"), "/ ") == "" {
		return "", nil
	}
	vp, err := vault.NormalizeContentPath(input)
	if err != nil {
		return "", err
	}
	if vault.IsInternalVirtualPath(vp) {
		return "", fmt.Errorf("reserved vault internals are not exposed through WebDAV")
	}
	return vp, nil
}

func (s *Server) basePrefix() string {
	p := strings.TrimSpace(s.Prefix)
	if p == "" || p == "/" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if !strings.HasSuffix(p, "/") {
		p += "/"
	}
	return p
}

func href(base, vp string, dir bool) string {
	base = strings.TrimSuffix(base, "/")
	if base == "" {
		base = ""
	}
	if vp == "" {
		if base == "" {
			return "/"
		}
		return base + "/"
	}
	h := "/" + url.PathEscape(vp)
	h = strings.ReplaceAll(h, "%2F", "/")
	if dir && !strings.HasSuffix(h, "/") {
		h += "/"
	}
	return base + h
}

func writeResponse(w http.ResponseWriter, ri responseInfo) {
	var b bytes.Buffer
	b.WriteString(`<D:response><D:href>`)
	xmlEscape(&b, ri.Href)
	b.WriteString(`</D:href><D:propstat><D:prop>`)
	if ri.IsDir {
		b.WriteString(`<D:resourcetype><D:collection/></D:resourcetype>`)
	} else {
		b.WriteString(`<D:resourcetype/>`)
		b.WriteString(`<D:getcontentlength>`)
		b.WriteString(fmt.Sprintf("%d", ri.Size))
		b.WriteString(`</D:getcontentlength>`)
		if ri.ETag != "" {
			b.WriteString(`<D:getetag>`)
			xmlEscape(&b, ri.ETag)
			b.WriteString(`</D:getetag>`)
		}
	}
	if ri.ModTime != "" {
		if t, err := time.Parse(time.RFC3339Nano, ri.ModTime); err == nil {
			b.WriteString(`<D:getlastmodified>`)
			b.WriteString(t.UTC().Format(http.TimeFormat))
			b.WriteString(`</D:getlastmodified>`)
		}
	}
	b.WriteString(`</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>`)
	_, _ = w.Write(b.Bytes())
}

func writeDirectoryHTML(w io.Writer, s *Server, files map[string]vault.FileRecord, vp string) error {
	items, ok := propfindResponses(files, vp, "1", s.basePrefix())
	if !ok {
		return fmt.Errorf("directory not found")
	}
	_, _ = io.WriteString(w, "<!doctype html><meta charset=\"utf-8\"><title>SeaVault WebDAV</title><h1>SeaVault WebDAV</h1><ul>")
	for _, item := range items {
		if item.Href == href(s.basePrefix(), vp, true) {
			continue
		}
		label := path.Base(strings.TrimSuffix(item.Href, "/"))
		if item.IsDir {
			label += "/"
		}
		_, _ = fmt.Fprintf(w, `<li><a href="%s">%s</a></li>`, htmlEscape(item.Href), htmlEscape(label))
	}
	_, _ = io.WriteString(w, "</ul>")
	return nil
}

func etagForRecord(vp string, rec vault.FileRecord) string {
	return fmt.Sprintf("\"%x-%x-%d\"", len(vp), rec.Generation, rec.Size)
}

func htmlEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func xmlEscape(b *bytes.Buffer, s string) {
	_ = xml.EscapeText(b, []byte(s))
}
