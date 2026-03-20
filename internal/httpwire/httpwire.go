package httpwire

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

const UserAgent = "Concordia-HTTP/1.0"

func BuildRequest(method string, target *url.URL, headers http.Header, body []byte) ([]byte, *http.Request, error) {
	if target == nil {
		return nil, nil, fmt.Errorf("target URL is required")
	}

	normalized := *target
	if normalized.Scheme == "" {
		normalized.Scheme = "http"
	}
	if normalized.Path == "" {
		normalized.Path = "/"
	}

	request, err := http.NewRequest(method, normalized.String(), bytes.NewReader(body))
	if err != nil {
		return nil, nil, fmt.Errorf("build request: %w", err)
	}

	request.Proto = "HTTP/1.0"
	request.ProtoMajor = 1
	request.ProtoMinor = 0
	request.Close = true
	request.Host = normalized.Host
	request.Header = cloneHeader(headers)

	if host := request.Header.Get("Host"); host != "" {
		request.Host = host
		request.Header.Del("Host")
	}
	if request.Header.Get("User-Agent") == "" {
		request.Header.Set("User-Agent", UserAgent)
	}
	request.Header.Del("Connection")
	request.Header.Set("Connection", "close")

	var buffer bytes.Buffer
	if err := request.Write(&buffer); err != nil {
		return nil, nil, fmt.Errorf("serialize request: %w", err)
	}

	return buffer.Bytes(), request, nil
}

func ParseRequest(raw []byte) (*http.Request, error) {
	request, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return nil, fmt.Errorf("parse request: %w", err)
	}

	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, fmt.Errorf("read request body: %w", err)
	}

	request.Body.Close()
	request.Body = io.NopCloser(bytes.NewReader(body))
	request.ContentLength = int64(len(body))

	return request, nil
}

func BuildResponse(status int, headers http.Header, body []byte) ([]byte, error) {
	response := &http.Response{
		StatusCode:    status,
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Proto:         "HTTP/1.0",
		ProtoMajor:    1,
		ProtoMinor:    0,
		Header:        cloneHeader(headers),
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Close:         true,
	}

	if response.Header == nil {
		response.Header = make(http.Header)
	}
	if response.Header.Get("Content-Type") == "" {
		response.Header.Set("Content-Type", "text/plain; charset=utf-8")
	}

	response.Header.Del("Connection")
	response.Header.Set("Connection", "close")
	response.Header.Set("Content-Length", strconv.Itoa(len(body)))

	var buffer bytes.Buffer
	if err := response.Write(&buffer); err != nil {
		return nil, fmt.Errorf("serialize response: %w", err)
	}

	return buffer.Bytes(), nil
}

func ParseResponse(raw []byte, request *http.Request) (*http.Response, []byte, error) {
	response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), request)
	if err != nil {
		return nil, nil, fmt.Errorf("parse response: %w", err)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("read response body: %w", err)
	}

	response.Body.Close()
	response.Body = io.NopCloser(bytes.NewReader(body))
	response.ContentLength = int64(len(body))

	return response, body, nil
}

func RenderResponse(response *http.Response, body []byte, verbose bool) ([]byte, error) {
	if !verbose {
		return body, nil
	}

	var buffer bytes.Buffer
	fmt.Fprintf(&buffer, "%s %s\r\n", response.Proto, response.Status)
	if err := response.Header.Write(&buffer); err != nil {
		return nil, fmt.Errorf("render response headers: %w", err)
	}

	buffer.WriteString("\r\n")
	buffer.Write(body)

	return buffer.Bytes(), nil
}

func cloneHeader(headers http.Header) http.Header {
	if headers == nil {
		return make(http.Header)
	}

	cloned := make(http.Header, len(headers))
	for key, values := range headers {
		cloned[key] = append([]string(nil), values...)
	}

	return cloned
}
