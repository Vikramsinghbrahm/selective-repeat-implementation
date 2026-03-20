package transport

import (
	"io"
	"log"
	"time"
)

type Config struct {
	WindowSize int
	Timeout    time.Duration
	Logger     *log.Logger
}

func (c Config) normalized() Config {
	normalized := c

	if normalized.WindowSize <= 0 {
		normalized.WindowSize = 5
	}
	if normalized.Timeout <= 0 {
		normalized.Timeout = 2 * time.Second
	}
	if normalized.Logger == nil {
		normalized.Logger = log.New(io.Discard, "", 0)
	}

	return normalized
}
