package localdav

import (
	"bytes"
	"encoding/xml"
	"fmt"
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
	Vault *vault.Vault
	mu    sync.Mutex
}

func New(v *vault.Vault) *Server {
	return &Server{Vault: v}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("DAV", "1")
	w.Header().Set("MS-Author-Via", "DAV")

	switch r.Method {
	case http.MethodOptions:
		w.Header().Set("Allow", "OPTIONS, PROPFIND, GET, HEAD, PUT, DELETE, MKCOL")
		w.WriteHeader(http.StatusNoContent)
	case "PROPFIND":
		s.handlePropfind(w, r)
	case http.MethodGet, http.MethodHead:
		s.handleGet(w, r)
	case http.MethodPut:
		s.handlePut(w, r)
	case http.MethodDelete:
		s.handleDelete(w, r)
	case "MKCOL":
		w.WriteHeader(http.StatusCreated)
	default:
		http.Error(w, "method not implemented", http.StatusNotImplemented)
	}
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	vp, err := requestVirtualPath(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok, err := s.Vault.FileInfo(vp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", rec.Size))
	if t, err := time.Parse(time.RFC3339Nano, rec.ModTime); err == nil {
		w.Header().Set("Last-Modified", t.UTC().Format(http.TimeFormat))
	}
	if r.Method == http.MethodHead {
		return
	}
	if err := s.Vault.WriteFileTo(vp, w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handlePut(w http.ResponseWriter, r *http.Request) {
	vp, err := requestVirtualPath(r)
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
	vp, err := requestVirtualPath(r)
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

func (s *Server) handlePropfind(w http.ResponseWriter, r *http.Request) {
	vp, err := requestVirtualPath(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	depth := r.Header.Get("Depth")
	if depth == "" {
		depth = "1"
	}
	s.mu.Lock()
	files, err := s.Vault.Files()
	s.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	responses, ok := propfindResponses(files, vp, depth)
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
}

func propfindResponses(files map[string]vault.FileRecord, vp string, depth string) ([]responseInfo, bool) {
	vp = strings.Trim(vp, "/")
	var out []responseInfo
	if rec, ok := files[vp]; ok {
		out = append(out, responseInfo{Href: href(vp, false), IsDir: false, Size: rec.Size, ModTime: rec.ModTime})
		return out, true
	}

	if !directoryExists(files, vp) {
		return nil, false
	}
	out = append(out, responseInfo{Href: href(vp, true), IsDir: true})
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
		if slash := strings.Index(rest, "/"); slash >= 0 {
			childDirs[path.Join(vp, rest[:slash])] = true
			continue
		}
		childFiles = append(childFiles, responseInfo{Href: href(path.Join(vp, rest), false), IsDir: false, Size: rec.Size, ModTime: rec.ModTime})
	}
	var dirs []string
	for d := range childDirs {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	for _, d := range dirs {
		out = append(out, responseInfo{Href: href(d, true), IsDir: true})
	}
	sort.Slice(childFiles, func(i, j int) bool { return childFiles[i].Href < childFiles[j].Href })
	out = append(out, childFiles...)
	return out, true
}

func directoryExists(files map[string]vault.FileRecord, vp string) bool {
	if vp == "" {
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

func requestVirtualPath(r *http.Request) (string, error) {
	p, err := url.PathUnescape(r.URL.Path)
	if err != nil {
		return "", err
	}
	p = strings.TrimPrefix(p, "/")
	return vault.CleanVirtualPath(p)
}

func href(vp string, dir bool) string {
	if vp == "" {
		return "/"
	}
	h := "/" + url.PathEscape(vp)
	h = strings.ReplaceAll(h, "%2F", "/")
	if dir && !strings.HasSuffix(h, "/") {
		h += "/"
	}
	return h
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

func xmlEscape(b *bytes.Buffer, s string) {
	_ = xml.EscapeText(b, []byte(s))
}
