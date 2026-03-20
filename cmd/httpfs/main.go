package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"selective-repeat-implementation/internal/fileserver"
	"selective-repeat-implementation/internal/transport"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	var (
		port            int
		dataDir         string
		verbose         bool
		timeout         time.Duration
		sessionDeadline time.Duration
		windowSize      int
	)

	flags := flag.NewFlagSet("httpfs", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.IntVar(&port, "p", 8007, "UDP port to listen on.")
	flags.IntVar(&port, "port", 8007, "UDP port to listen on.")
	flags.StringVar(&dataDir, "d", ".", "Directory exposed by the file server.")
	flags.StringVar(&dataDir, "dir", ".", "Directory exposed by the file server.")
	flags.BoolVar(&verbose, "v", false, "Enable request logging.")
	flags.BoolVar(&verbose, "verbose", false, "Enable request logging.")
	flags.DurationVar(&timeout, "timeout", 2*time.Second, "Selective-repeat retransmission timeout.")
	flags.DurationVar(&sessionDeadline, "session-deadline", 30*time.Second, "Per-request deadline.")
	flags.IntVar(&windowSize, "window-size", 5, "Selective-repeat send window size.")
	flags.Usage = func() {
		printUsage(stderr)
	}

	if err := flags.Parse(args); err != nil {
		flags.Usage()
		return err
	}

	if flags.NArg() != 0 {
		flags.Usage()
		return fmt.Errorf("httpfs does not accept positional arguments")
	}

	logger := log.New(io.Discard, "", log.LstdFlags)
	if verbose {
		logger = log.New(stdout, "httpfs: ", log.LstdFlags)
	}

	handler, err := fileserver.New(dataDir, logger)
	if err != nil {
		return err
	}

	listener, err := transport.Listen(port, transport.Config{
		WindowSize: windowSize,
		Timeout:    timeout,
		Logger:     logger,
	})
	if err != nil {
		return err
	}
	defer listener.Close()

	logger.Printf("serving %s on UDP :%d", dataDir, port)

	for {
		session, err := listener.Accept(context.Background())
		if err != nil {
			return err
		}

		if err := serveSession(handler, session, sessionDeadline, logger); err != nil {
			logger.Printf("session error: %v", err)
		}
	}
}

func serveSession(handler *fileserver.Handler, session *transport.Session, deadline time.Duration, logger *log.Logger) error {
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	defer session.Close()

	logger.Printf("accepted %s", session.RemoteAddr())

	requestBytes, err := session.ReceiveMessage(ctx, 2)
	if err != nil {
		return fmt.Errorf("receive request: %w", err)
	}

	responseBytes, err := handler.Handle(requestBytes)
	if err != nil {
		return fmt.Errorf("handle request: %w", err)
	}

	if err := session.SendMessage(ctx, responseBytes, 1); err != nil {
		return fmt.Errorf("send response: %w", err)
	}

	return nil
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "httpfs serves files over HTTP/1.0 using the selective-repeat UDP transport.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  httpfs [options]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Options:")
	fmt.Fprintln(w, "  -p, --port             UDP port to listen on. Default: 8007.")
	fmt.Fprintln(w, "  -d, --dir              Directory exposed by the file server. Default: current directory.")
	fmt.Fprintln(w, "  -v, --verbose          Enable request logging.")
	fmt.Fprintln(w, "  --timeout              Retransmission timeout. Default: 2s.")
	fmt.Fprintln(w, "  --session-deadline     Per-request deadline. Default: 30s.")
	fmt.Fprintln(w, "  --window-size          Sliding window size. Default: 5.")
}
