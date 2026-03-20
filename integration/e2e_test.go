package integration_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"selective-repeat-implementation/internal/fileserver"
	"selective-repeat-implementation/internal/httpwire"
	"selective-repeat-implementation/internal/router"
	"selective-repeat-implementation/internal/transport"
)

func TestEndToEndWithGoRouter(t *testing.T) {
	root := t.TempDir()
	smallText := []byte("hello from the selective repeat test server\n")
	largeBinary := deterministicBytes(512 << 10)
	largeText := bytes.Repeat([]byte("selective repeat transport test line\n"), 4096)

	mustWriteFile(t, filepath.Join(root, "sample.txt"), smallText)
	mustWriteFile(t, filepath.Join(root, "large.bin"), largeBinary)
	mustWriteFile(t, filepath.Join(root, "large.txt"), largeText)

	handler, err := fileserver.New(root, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("fileserver.New() error = %v", err)
	}

	routerInstance, err := router.Listen(router.Config{Port: 0})
	if err != nil {
		t.Fatalf("router.Listen() error = %v", err)
	}
	defer routerInstance.Close()

	listener, shutdown := startTestServer(t, handler)
	defer shutdown()

	routerAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1).To4(), Port: routerInstance.Addr().Port}
	serverAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1).To4(), Port: listener.Addr().Port}

	t.Run("small get", func(t *testing.T) {
		body, err := executeRoundTrip(routerAddr, serverAddr, http.MethodGet, "/sample.txt", nil)
		if err != nil {
			t.Fatalf("executeRoundTrip() error = %v", err)
		}
		if !bytes.Equal(body, smallText) {
			t.Fatalf("GET body mismatch")
		}
	})

	t.Run("large post and verify", func(t *testing.T) {
		if _, err := executeRoundTrip(routerAddr, serverAddr, http.MethodPost, "/uploads/large-posted.bin", largeBinary); err != nil {
			t.Fatalf("POST executeRoundTrip() error = %v", err)
		}
		body, err := executeRoundTrip(routerAddr, serverAddr, http.MethodGet, "/uploads/large-posted.bin", nil)
		if err != nil {
			t.Fatalf("verify executeRoundTrip() error = %v", err)
		}
		if !bytes.Equal(body, largeBinary) {
			t.Fatalf("large POST round-trip mismatch")
		}
	})

	t.Run("concurrent large text get", func(t *testing.T) {
		var wg sync.WaitGroup
		errCh := make(chan error, 3)

		for index := 0; index < 3; index++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				body, err := executeRoundTrip(routerAddr, serverAddr, http.MethodGet, "/large.txt", nil)
				if err != nil {
					errCh <- err
					return
				}
				if !bytes.Equal(body, largeText) {
					errCh <- io.ErrUnexpectedEOF
				}
			}()
		}

		wg.Wait()
		close(errCh)

		for err := range errCh {
			if err != nil {
				t.Fatalf("concurrent GET error = %v", err)
			}
		}
	})
}

func startTestServer(t *testing.T, handler *fileserver.Handler) (*transport.Listener, func()) {
	t.Helper()

	listener, err := transport.Listen(0, transport.Config{
		WindowSize:     5,
		Timeout:        150 * time.Millisecond,
		MinTimeout:     50 * time.Millisecond,
		MaxTimeout:     2 * time.Second,
		MaxMessageSize: 8 << 20,
	})
	if err != nil {
		t.Fatalf("transport.Listen() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()

		for {
			session, err := listener.Accept(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				t.Errorf("listener.Accept() error = %v", err)
				return
			}

			wg.Add(1)
			go func(session *transport.Session) {
				defer wg.Done()
				defer session.Close()

				requestCtx, requestCancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer requestCancel()

				requestBytes, err := session.ReceiveMessage(requestCtx, 2)
				if err != nil {
					if isExpectedShutdownError(err) {
						return
					}
					t.Errorf("ReceiveMessage() error = %v", err)
					return
				}

				responseBytes, err := handler.Handle(requestBytes)
				if err != nil {
					t.Errorf("Handle() error = %v", err)
					return
				}

				if err := session.SendMessage(requestCtx, responseBytes, 1); err != nil {
					if isExpectedShutdownError(err) {
						return
					}
					t.Errorf("SendMessage() error = %v", err)
				}
			}(session)
		}
	}()

	return listener, func() {
		cancel()
		listener.Close()
		wg.Wait()
	}
}

func executeRoundTrip(routerAddr *net.UDPAddr, serverAddr *net.UDPAddr, method string, path string, body []byte) ([]byte, error) {
	target := &url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort("127.0.0.1", strconv.Itoa(serverAddr.Port)),
		Path:   path,
	}

	requestBytes, request, err := httpwire.BuildRequest(method, target, nil, body)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	session, err := transport.DialContext(ctx, routerAddr, serverAddr, transport.Config{
		WindowSize:     5,
		Timeout:        150 * time.Millisecond,
		MinTimeout:     50 * time.Millisecond,
		MaxTimeout:     2 * time.Second,
		MaxMessageSize: 8 << 20,
	})
	if err != nil {
		return nil, err
	}
	defer session.Close()

	if err := session.SendMessage(ctx, requestBytes, 2); err != nil {
		return nil, err
	}

	responseBytes, err := session.ReceiveMessage(ctx, 1)
	if err != nil {
		return nil, err
	}

	response, responseBody, err := httpwire.ParseResponse(responseBytes, request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode >= 400 {
		return nil, fmt.Errorf("unexpected HTTP status %d with body %q", response.StatusCode, responseBody)
	}

	return responseBody, nil
}

func mustWriteFile(t *testing.T, path string, data []byte) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}

func deterministicBytes(size int) []byte {
	data := make([]byte, size)
	for index := range data {
		data[index] = byte((index*31 + 17) % 251)
	}
	return data
}

func isExpectedShutdownError(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled)
}
