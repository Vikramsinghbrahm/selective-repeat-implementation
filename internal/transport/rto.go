package transport

import (
	"sync"
	"time"
)

type rtoEstimator struct {
	mu          sync.Mutex
	srtt        time.Duration
	rttvar      time.Duration
	rto         time.Duration
	min         time.Duration
	max         time.Duration
	initialized bool
}

func newRTOEstimator(initial, min, max time.Duration) *rtoEstimator {
	if min <= 0 {
		min = 200 * time.Millisecond
	}
	if max <= 0 {
		max = 30 * time.Second
	}
	if initial < min {
		initial = min
	}
	if initial > max {
		initial = max
	}

	return &rtoEstimator{
		rto: initial,
		min: min,
		max: max,
	}
}

func (e *rtoEstimator) Current() time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.rto
}

func (e *rtoEstimator) NoteSample(sample time.Duration) time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()

	if sample <= 0 {
		return e.rto
	}

	if !e.initialized {
		e.srtt = sample
		e.rttvar = sample / 2
		e.initialized = true
	} else {
		delta := e.srtt - sample
		if delta < 0 {
			delta = -delta
		}

		e.rttvar = (3*e.rttvar)/4 + delta/4
		e.srtt = (7*e.srtt)/8 + sample/8
	}

	const clockGranularity = 10 * time.Millisecond
	candidate := e.srtt + maxDuration(clockGranularity, 4*e.rttvar)
	e.rto = clampDuration(candidate, e.min, e.max)

	return e.rto
}

func (e *rtoEstimator) Backoff() time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()

	candidate := e.rto * 2
	e.rto = clampDuration(candidate, e.min, e.max)

	return e.rto
}

func clampDuration(value, min, max time.Duration) time.Duration {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func maxDuration(left, right time.Duration) time.Duration {
	if left > right {
		return left
	}
	return right
}
