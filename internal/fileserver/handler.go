package fileserver

import (
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"selective-repeat-implementation/internal/httpwire"
)

type Handler struct {
	root   string
	logger *log.Logger
}

func New(root string, logger *log.Logger) (*Handler, error) {
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve data directory: %w", err)
	}

	info, statErr := os.Stat(absoluteRoot)
	switch {
	case errors.Is(statErr, os.ErrNotExist):
		if err := os.MkdirAll(absoluteRoot, 0o755); err != nil {
			return nil, fmt.Errorf("create data directory: %w", err)
		}
	case statErr != nil:
		return nil, fmt.Errorf("stat data directory: %w", statErr)
	case !info.IsDir():
		return nil, fmt.Errorf("%s is not a directory", absoluteRoot)
	}

	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}

	return &Handler{
		root:   absoluteRoot,
		logger: logger,
	}, nil
}

func (h *Handler) Handle(requestBytes []byte) ([]byte, error) {
	request, err := httpwire.ParseRequest(requestBytes)
	if err != nil {
		return h.textResponse(http.StatusBadRequest, "bad request\n")
	}
	defer request.Body.Close()

	h.logger.Printf("%s %s", request.Method, request.URL.Path)

	switch request.Method {
	case http.MethodGet:
		return h.handleGet(request)
	case http.MethodPost:
		return h.handlePost(request)
	default:
		headers := make(http.Header)
		headers.Set("Allow", "GET, POST")
		return httpwire.BuildResponse(http.StatusMethodNotAllowed, headers, []byte("method not allowed\n"))
	}
}

func (h *Handler) handleGet(request *http.Request) ([]byte, error) {
	target, err := h.resolvePath(request.URL.Path)
	if err != nil {
		return h.textResponse(http.StatusForbidden, "path escapes data directory\n")
	}

	info, err := os.Stat(target)
	if err != nil {
		return h.responseFromFSError(err)
	}

	if info.IsDir() {
		return h.directoryListing(target)
	}

	data, err := os.ReadFile(target)
	if err != nil {
		return h.responseFromFSError(err)
	}

	headers := make(http.Header)
	headers.Set("Content-Type", detectContentType(target, data))

	return httpwire.BuildResponse(http.StatusOK, headers, data)
}

func (h *Handler) handlePost(request *http.Request) ([]byte, error) {
	if request.URL.Path == "" || request.URL.Path == "/" {
		return h.textResponse(http.StatusBadRequest, "POST requires a file path\n")
	}
	if strings.HasSuffix(request.URL.Path, "/") {
		return h.textResponse(http.StatusBadRequest, "POST target must be a file path\n")
	}

	target, err := h.resolvePath(request.URL.Path)
	if err != nil {
		return h.textResponse(http.StatusForbidden, "path escapes data directory\n")
	}

	body, err := io.ReadAll(request.Body)
	if err != nil {
		return h.textResponse(http.StatusBadRequest, "failed to read request body\n")
	}

	info, err := os.Stat(target)
	created := false
	switch {
	case err == nil && info.IsDir():
		return h.textResponse(http.StatusBadRequest, "cannot overwrite a directory\n")
	case errors.Is(err, os.ErrNotExist):
		created = true
	case err != nil:
		return h.responseFromFSError(err)
	}

	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return h.responseFromFSError(err)
	}

	if err := os.WriteFile(target, body, 0o644); err != nil {
		return h.responseFromFSError(err)
	}

	if created {
		return h.textResponse(http.StatusCreated, "file created successfully\n")
	}

	return h.textResponse(http.StatusOK, "file updated successfully\n")
}

func (h *Handler) directoryListing(target string) ([]byte, error) {
	entries, err := os.ReadDir(target)
	if err != nil {
		return h.responseFromFSError(err)
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			name += "/"
		}

		names = append(names, name)
	}
	sort.Strings(names)

	body := []byte(strings.Join(names, "\n"))
	if len(body) > 0 {
		body = append(body, '\n')
	}

	headers := make(http.Header)
	headers.Set("Content-Type", "text/plain; charset=utf-8")

	return httpwire.BuildResponse(http.StatusOK, headers, body)
}

func (h *Handler) resolvePath(requestPath string) (string, error) {
	cleanPath := path.Clean("/" + requestPath)
	relativePath := strings.TrimPrefix(cleanPath, "/")
	if relativePath == "." {
		relativePath = ""
	}

	target := filepath.Clean(filepath.Join(h.root, filepath.FromSlash(relativePath)))
	relativeTarget, err := filepath.Rel(h.root, target)
	if err != nil {
		return "", err
	}

	if relativeTarget == ".." || strings.HasPrefix(relativeTarget, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("path %q escapes %s", requestPath, h.root)
	}

	return target, nil
}

func (h *Handler) responseFromFSError(err error) ([]byte, error) {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return h.textResponse(http.StatusNotFound, "not found\n")
	case errors.Is(err, os.ErrPermission):
		return h.textResponse(http.StatusForbidden, "forbidden\n")
	default:
		return h.textResponse(http.StatusInternalServerError, "internal server error\n")
	}
}

func (h *Handler) textResponse(status int, message string) ([]byte, error) {
	headers := make(http.Header)
	headers.Set("Content-Type", "text/plain; charset=utf-8")
	return httpwire.BuildResponse(status, headers, []byte(message))
}

func detectContentType(filePath string, data []byte) string {
	if contentType := mime.TypeByExtension(filepath.Ext(filePath)); contentType != "" {
		return contentType
	}

	if len(data) == 0 {
		return "application/octet-stream"
	}

	return http.DetectContentType(data)
}
