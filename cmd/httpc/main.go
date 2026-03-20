package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"selective-repeat-implementation/internal/httpwire"
	"selective-repeat-implementation/internal/transport"
)

type headerFlags []string

func (h *headerFlags) String() string {
	return strings.Join(*h, ", ")
}

func (h *headerFlags) Set(value string) error {
	if !strings.Contains(value, ":") {
		return fmt.Errorf("header must use key:value format")
	}

	*h = append(*h, value)
	return nil
}

func (h headerFlags) HTTPHeader() (http.Header, error) {
	headers := make(http.Header)

	for _, value := range h {
		parts := strings.SplitN(value, ":", 2)
		key := strings.TrimSpace(parts[0])
		headerValue := strings.TrimSpace(parts[1])

		if key == "" {
			return nil, fmt.Errorf("header key cannot be empty")
		}

		headers.Add(key, headerValue)
	}

	return headers, nil
}

type commonOptions struct {
	verbose    bool
	output     string
	routerHost string
	routerPort int
	serverPort int
	timeout    time.Duration
	deadline   time.Duration
	windowSize int
	legacyURL  string
	headers    headerFlags
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		printRootUsage(stderr)
		return fmt.Errorf("missing command")
	}

	switch args[0] {
	case "help":
		return runHelp(args[1:], stdout)
	case "get":
		return runGet(args[1:], stdout, stderr)
	case "post":
		return runPost(args[1:], stdout, stderr)
	default:
		printRootUsage(stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runHelp(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		printRootUsage(stdout)
		return nil
	}

	switch args[0] {
	case "get":
		printGetUsage(stdout)
	case "post":
		printPostUsage(stdout)
	default:
		return fmt.Errorf("unknown help topic %q", args[0])
	}

	return nil
}

func runGet(args []string, stdout, stderr io.Writer) error {
	var options commonOptions
	flags := newCommonFlagSet("get", &options)
	flags.Usage = func() {
		printGetUsage(stderr)
	}

	if err := flags.Parse(args); err != nil {
		flags.Usage()
		return err
	}

	if flags.NArg() > 1 {
		flags.Usage()
		return fmt.Errorf("get accepts exactly one URL")
	}

	target, serverHost, serverPort, err := resolveTarget(firstArg(flags.Args()), options.legacyURL, options.serverPort)
	if err != nil {
		return err
	}

	headers, err := options.headers.HTTPHeader()
	if err != nil {
		return err
	}

	requestBytes, request, err := httpwire.BuildRequest(http.MethodGet, target, headers, nil)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), options.deadline)
	defer cancel()

	responseBytes, err := exchange(ctx, options, serverHost, serverPort, requestBytes)
	if err != nil {
		return err
	}

	response, body, err := httpwire.ParseResponse(responseBytes, request)
	if err != nil {
		return err
	}

	output, err := httpwire.RenderResponse(response, body, options.verbose)
	if err != nil {
		return err
	}

	return writeOutput(stdout, options.output, output)
}

func runPost(args []string, stdout, stderr io.Writer) error {
	var options commonOptions
	var inlineData string
	var filePath string

	flags := newCommonFlagSet("post", &options)
	flags.StringVar(&inlineData, "d", "", "Inline request body.")
	flags.StringVar(&inlineData, "data", "", "Inline request body.")
	flags.StringVar(&filePath, "f", "", "Read the request body from a file.")
	flags.StringVar(&filePath, "file", "", "Read the request body from a file.")
	flags.Usage = func() {
		printPostUsage(stderr)
	}

	if err := flags.Parse(args); err != nil {
		flags.Usage()
		return err
	}

	if flags.NArg() > 1 {
		flags.Usage()
		return fmt.Errorf("post accepts exactly one URL")
	}

	if inlineData != "" && filePath != "" {
		return fmt.Errorf("-d and -f cannot be used together")
	}

	target, serverHost, serverPort, err := resolveTarget(firstArg(flags.Args()), options.legacyURL, options.serverPort)
	if err != nil {
		return err
	}

	headers, err := options.headers.HTTPHeader()
	if err != nil {
		return err
	}

	body, err := loadBody(inlineData, filePath)
	if err != nil {
		return err
	}

	requestBytes, request, err := httpwire.BuildRequest(http.MethodPost, target, headers, body)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), options.deadline)
	defer cancel()

	responseBytes, err := exchange(ctx, options, serverHost, serverPort, requestBytes)
	if err != nil {
		return err
	}

	response, responseBody, err := httpwire.ParseResponse(responseBytes, request)
	if err != nil {
		return err
	}

	output, err := httpwire.RenderResponse(response, responseBody, options.verbose)
	if err != nil {
		return err
	}

	return writeOutput(stdout, options.output, output)
}

func newCommonFlagSet(name string, options *commonOptions) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	flags.BoolVar(&options.verbose, "v", false, "Print response metadata and headers.")
	flags.BoolVar(&options.verbose, "verbose", false, "Print response metadata and headers.")
	flags.StringVar(&options.output, "o", "", "Write the response to a file instead of stdout.")
	flags.StringVar(&options.output, "output", "", "Write the response to a file instead of stdout.")
	flags.StringVar(&options.routerHost, "router-host", "localhost", "Router host.")
	flags.StringVar(&options.routerHost, "routerhost", "localhost", "Router host.")
	flags.IntVar(&options.routerPort, "router-port", 3000, "Router port.")
	flags.IntVar(&options.routerPort, "routerport", 3000, "Router port.")
	flags.IntVar(&options.serverPort, "server-port", 8007, "Default UDP server port when the URL omits one.")
	flags.IntVar(&options.serverPort, "serverport", 8007, "Default UDP server port when the URL omits one.")
	flags.DurationVar(&options.timeout, "timeout", 2*time.Second, "Selective-repeat retransmission timeout.")
	flags.DurationVar(&options.deadline, "deadline", 30*time.Second, "Overall request deadline.")
	flags.IntVar(&options.windowSize, "window-size", 5, "Selective-repeat send window size.")
	flags.StringVar(&options.legacyURL, "serverhost", "", "Legacy URL flag kept for backward compatibility.")
	flags.Var(&options.headers, "H", "Add a request header using key:value format.")
	flags.Var(&options.headers, "header", "Add a request header using key:value format.")

	return flags
}

func resolveTarget(positional string, legacyURL string, defaultPort int) (*url.URL, string, int, error) {
	target := strings.TrimSpace(positional)
	if target == "" {
		target = strings.TrimSpace(legacyURL)
	}

	if target == "" {
		return nil, "", 0, fmt.Errorf("missing URL")
	}

	if !strings.Contains(target, "://") {
		target = "http://" + target
	}

	parsed, err := url.Parse(target)
	if err != nil {
		return nil, "", 0, fmt.Errorf("parse URL: %w", err)
	}

	if parsed.Host == "" {
		return nil, "", 0, fmt.Errorf("URL must include a host")
	}

	host := parsed.Hostname()
	if host == "" {
		return nil, "", 0, fmt.Errorf("URL host cannot be empty")
	}

	port := defaultPort
	if parsed.Port() != "" {
		port, err = strconv.Atoi(parsed.Port())
		if err != nil {
			return nil, "", 0, fmt.Errorf("invalid port %q: %w", parsed.Port(), err)
		}
	}

	if parsed.Path == "" {
		parsed.Path = "/"
	}

	return parsed, host, port, nil
}

func exchange(ctx context.Context, options commonOptions, serverHost string, serverPort int, requestBytes []byte) ([]byte, error) {
	routerAddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(options.routerHost, strconv.Itoa(options.routerPort)))
	if err != nil {
		return nil, fmt.Errorf("resolve router address: %w", err)
	}

	serverAddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(serverHost, strconv.Itoa(serverPort)))
	if err != nil {
		return nil, fmt.Errorf("resolve server address: %w", err)
	}

	if serverAddr.IP == nil || serverAddr.IP.To4() == nil {
		return nil, fmt.Errorf("server host %q did not resolve to an IPv4 address", serverHost)
	}

	session, err := transport.DialContext(ctx, routerAddr, serverAddr, transport.Config{
		WindowSize: options.windowSize,
		Timeout:    options.timeout,
	})
	if err != nil {
		return nil, err
	}
	defer session.Close()

	if err := session.SendMessage(ctx, requestBytes, 2); err != nil {
		return nil, err
	}

	return session.ReceiveMessage(ctx, 1)
}

func loadBody(inlineData string, filePath string) ([]byte, error) {
	if filePath == "" {
		return []byte(inlineData), nil
	}

	body, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", filePath, err)
	}

	return body, nil
}

func writeOutput(stdout io.Writer, outputPath string, data []byte) error {
	if outputPath != "" {
		return os.WriteFile(outputPath, data, 0o644)
	}

	_, err := stdout.Write(data)
	return err
}

func firstArg(values []string) string {
	if len(values) == 0 {
		return ""
	}

	return values[0]
}

func printRootUsage(w io.Writer) {
	fmt.Fprintln(w, "httpc is a curl-like client that speaks HTTP/1.0 over the selective-repeat UDP transport.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  httpc <command> [options] URL")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  get     Execute an HTTP GET request.")
	fmt.Fprintln(w, "  post    Execute an HTTP POST request.")
	fmt.Fprintln(w, "  help    Show command help.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Use \"httpc help [command]\" for command-specific usage.")
}

func printGetUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  httpc get [options] URL")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Options:")
	fmt.Fprintln(w, "  -v, --verbose        Include the response status line and headers.")
	fmt.Fprintln(w, "  -H, --header         Add a request header using key:value format. Repeatable.")
	fmt.Fprintln(w, "  -o, --output         Write the response to a file.")
	fmt.Fprintln(w, "  --router-host        Router host. Default: localhost.")
	fmt.Fprintln(w, "  --router-port        Router port. Default: 3000.")
	fmt.Fprintln(w, "  --server-port        Default UDP server port when the URL omits a port. Default: 8007.")
	fmt.Fprintln(w, "  --timeout            Retransmission timeout. Default: 2s.")
	fmt.Fprintln(w, "  --deadline           Overall request deadline. Default: 30s.")
	fmt.Fprintln(w, "  --window-size        Sliding window size. Default: 5.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Legacy compatibility:")
	fmt.Fprintln(w, "  --serverhost         Legacy URL flag from the Python version.")
	fmt.Fprintln(w, "  --routerhost         Legacy alias for --router-host.")
	fmt.Fprintln(w, "  --routerport         Legacy alias for --router-port.")
	fmt.Fprintln(w, "  --serverport         Legacy alias for --server-port.")
}

func printPostUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  httpc post [options] [-d data | -f file] URL")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Options:")
	fmt.Fprintln(w, "  -d, --data           Inline request body.")
	fmt.Fprintln(w, "  -f, --file           Read the request body from a file.")
	fmt.Fprintln(w, "  -v, --verbose        Include the response status line and headers.")
	fmt.Fprintln(w, "  -H, --header         Add a request header using key:value format. Repeatable.")
	fmt.Fprintln(w, "  -o, --output         Write the response to a file.")
	fmt.Fprintln(w, "  --router-host        Router host. Default: localhost.")
	fmt.Fprintln(w, "  --router-port        Router port. Default: 3000.")
	fmt.Fprintln(w, "  --server-port        Default UDP server port when the URL omits a port. Default: 8007.")
	fmt.Fprintln(w, "  --timeout            Retransmission timeout. Default: 2s.")
	fmt.Fprintln(w, "  --deadline           Overall request deadline. Default: 30s.")
	fmt.Fprintln(w, "  --window-size        Sliding window size. Default: 5.")
}
