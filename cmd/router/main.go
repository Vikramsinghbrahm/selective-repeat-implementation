package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"selective-repeat-implementation/internal/router"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	var (
		port     int
		dropRate float64
		maxDelay time.Duration
		seed     int64
		verbose  bool
	)

	flags := flag.NewFlagSet("router", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.IntVar(&port, "port", 3000, "UDP port to listen on.")
	flags.Float64Var(&dropRate, "drop-rate", 0, "Packet drop probability from 0.0 to 1.0.")
	flags.DurationVar(&maxDelay, "max-delay", 0, "Maximum forwarding delay.")
	flags.Int64Var(&seed, "seed", 1, "Deterministic random seed. Set 0 to randomize.")
	flags.BoolVar(&verbose, "v", false, "Enable router logging.")
	flags.BoolVar(&verbose, "verbose", false, "Enable router logging.")
	flags.Usage = func() {
		printUsage(stderr)
	}

	if err := flags.Parse(args); err != nil {
		flags.Usage()
		return err
	}
	if flags.NArg() != 0 {
		flags.Usage()
		return fmt.Errorf("router does not accept positional arguments")
	}

	logger := log.New(io.Discard, "", log.LstdFlags)
	if verbose {
		logger = log.New(stdout, "router: ", log.LstdFlags)
	}

	instance, err := router.Listen(router.Config{
		Port:     port,
		DropRate: dropRate,
		MaxDelay: maxDelay,
		Seed:     seed,
		Logger:   logger,
	})
	if err != nil {
		return err
	}
	defer instance.Close()

	logger.Printf("listening on %s", instance.Addr())

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)

	select {
	case err := <-instance.Err():
		return err
	case <-signals:
		return nil
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "router forwards selective-repeat UDP packets based on the embedded peer address.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  router [options]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Options:")
	fmt.Fprintln(w, "  --port        UDP port to listen on. Default: 3000.")
	fmt.Fprintln(w, "  --drop-rate   Packet drop probability from 0.0 to 1.0. Default: 0.")
	fmt.Fprintln(w, "  --max-delay   Maximum forwarding delay. Default: 0s.")
	fmt.Fprintln(w, "  --seed        Deterministic random seed. Default: 1.")
	fmt.Fprintln(w, "  -v, --verbose Enable router logging.")
}
