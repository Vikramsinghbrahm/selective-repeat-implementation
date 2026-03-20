package transport

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

func randomUint32NonZero() (uint32, error) {
	for {
		var buffer [4]byte
		if _, err := rand.Read(buffer[:]); err != nil {
			return 0, fmt.Errorf("read random uint32: %w", err)
		}

		value := binary.BigEndian.Uint32(buffer[:])
		if value != 0 {
			return value, nil
		}
	}
}

func randomUint64NonZero() (uint64, error) {
	for {
		var buffer [8]byte
		if _, err := rand.Read(buffer[:]); err != nil {
			return 0, fmt.Errorf("read random uint64: %w", err)
		}

		value := binary.BigEndian.Uint64(buffer[:])
		if value != 0 {
			return value, nil
		}
	}
}
