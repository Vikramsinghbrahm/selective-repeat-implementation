package transport

import (
	"io"
	"log"
	"time"
)

type Config struct {
	WindowSize       int
	Timeout          time.Duration
	MinTimeout       time.Duration
	MaxTimeout       time.Duration
	MaxMessageSize   int
	SessionQueueSize int
	LogEvents        bool
	Logger           *log.Logger
	Metrics          *Metrics
}

func (c Config) normalized() Config {
	normalized := c

	if normalized.WindowSize <= 0 {
		normalized.WindowSize = 5
	}
	if normalized.Timeout <= 0 {
		normalized.Timeout = 2 * time.Second
	}
	if normalized.MinTimeout <= 0 {
		normalized.MinTimeout = 200 * time.Millisecond
	}
	if normalized.MaxTimeout <= 0 {
		normalized.MaxTimeout = 30 * time.Second
	}
	if normalized.MinTimeout > normalized.Timeout {
		normalized.MinTimeout = normalized.Timeout
	}
	if normalized.MaxTimeout < normalized.Timeout {
		normalized.MaxTimeout = normalized.Timeout
	}
	if normalized.MaxMessageSize <= 0 {
		normalized.MaxMessageSize = 8 << 20
	}
	if normalized.SessionQueueSize <= 0 {
		normalized.SessionQueueSize = 128
	}
	if normalized.Logger == nil {
		normalized.Logger = log.New(io.Discard, "", 0)
	}
	if normalized.Metrics == nil {
		normalized.Metrics = NewMetrics()
	}

	return normalized
}
