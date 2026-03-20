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
		logTransport    bool
		timeout         time.Duration
		sessionDeadline time.Duration
		metricsInterval time.Duration
		windowSize      int
		maxMessageSize  int
	)

	flags := flag.NewFlagSet("httpfs", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.IntVar(&port, "p", 8007, "UDP port to listen on.")
	flags.IntVar(&port, "port", 8007, "UDP port to listen on.")
	flags.StringVar(&dataDir, "d", ".", "Directory exposed by the file server.")
	flags.StringVar(&dataDir, "dir", ".", "Directory exposed by the file server.")
	flags.BoolVar(&verbose, "v", false, "Enable request logging.")
	flags.BoolVar(&verbose, "verbose", false, "Enable request logging.")
	flags.BoolVar(&logTransport, "log-transport", false, "Enable transport session and RTO logging.")
	flags.DurationVar(&timeout, "timeout", 2*time.Second, "Initial retransmission timeout.")
	flags.DurationVar(&sessionDeadline, "session-deadline", 30*time.Second, "Per-request deadline.")
	flags.DurationVar(&metricsInterval, "metrics-interval", 0, "Periodic transport metrics logging interval. Set 0 to disable.")
	flags.IntVar(&windowSize, "window-size", 5, "Selective-repeat send window size.")
	flags.IntVar(&maxMessageSize, "max-message-size", 8<<20, "Maximum transport message size in bytes.")
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

	requestLogger := log.New(io.Discard, "", log.LstdFlags)
	if verbose {
		requestLogger = log.New(stdout, "httpfs: ", log.LstdFlags)
	}

	transportLogger := requestLogger
	if !verbose && (logTransport || metricsInterval > 0) {
		transportLogger = log.New(stdout, "httpfs: ", log.LstdFlags)
	}

	metrics := transport.NewMetrics()
	handler, err := fileserver.New(dataDir, requestLogger)
	if err != nil {
		return err
	}

	listener, err := transport.Listen(port, transport.Config{
		WindowSize:     windowSize,
		Timeout:        timeout,
		MaxMessageSize: maxMessageSize,
		LogEvents:      logTransport,
		Logger:         transportLogger,
		Metrics:        metrics,
	})
	if err != nil {
		return err
	}
	defer listener.Close()

	transportLogger.Printf("serving %s on UDP :%d", dataDir, port)

	if metricsInterval > 0 {
		metricsCtx, cancelMetrics := context.WithCancel(context.Background())
		defer cancelMetrics()
		go logMetricsLoop(metricsCtx, transportLogger, metrics, metricsInterval)
	}

	for {
		session, err := listener.Accept(context.Background())
		if err != nil {
			return err
		}

		go func(session *transport.Session) {
			if err := serveSession(handler, session, sessionDeadline); err != nil {
				transportLogger.Printf("session error remote=%s err=%v", session.RemoteAddr(), err)
			}
		}(session)
	}
}

func serveSession(handler *fileserver.Handler, session *transport.Session, deadline time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	defer session.Close()

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

func logMetricsLoop(ctx context.Context, logger *log.Logger, metrics *transport.Metrics, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			logger.Printf("metrics %s", metrics.Snapshot())
		}
	}
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
	fmt.Fprintln(w, "  --log-transport        Enable transport session and RTO logging.")
	fmt.Fprintln(w, "  --timeout              Initial retransmission timeout. Default: 2s.")
	fmt.Fprintln(w, "  --session-deadline     Per-request deadline. Default: 30s.")
	fmt.Fprintln(w, "  --metrics-interval     Periodic transport metrics logging interval. Default: 0 (disabled).")
	fmt.Fprintln(w, "  --window-size          Sliding window size. Default: 5.")
	fmt.Fprintln(w, "  --max-message-size     Maximum transport message size in bytes. Default: 8388608.")
}
