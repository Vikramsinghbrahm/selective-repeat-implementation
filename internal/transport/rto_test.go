package transport

import (
	"testing"
	"time"
)

func TestRTOEstimatorInitializesFromSamples(t *testing.T) {
	estimator := newRTOEstimator(2*time.Second, 200*time.Millisecond, 30*time.Second)

	got := estimator.NoteSample(400 * time.Millisecond)

	want := 1200 * time.Millisecond
	if got != want {
		t.Fatalf("NoteSample() = %s, want %s", got, want)
	}
	if estimator.Current() != want {
		t.Fatalf("Current() = %s, want %s", estimator.Current(), want)
	}
}

func TestRTOEstimatorSmoothsAndClamps(t *testing.T) {
	estimator := newRTOEstimator(2*time.Second, 200*time.Millisecond, 1500*time.Millisecond)
	estimator.NoteSample(400 * time.Millisecond)

	got := estimator.NoteSample(100 * time.Millisecond)

	if got < 200*time.Millisecond {
		t.Fatalf("NoteSample() = %s, want at least %s", got, 200*time.Millisecond)
	}
	if got > 1500*time.Millisecond {
		t.Fatalf("NoteSample() = %s, want at most %s", got, 1500*time.Millisecond)
	}
}

func TestRTOEstimatorBackoffRespectsMaximum(t *testing.T) {
	estimator := newRTOEstimator(500*time.Millisecond, 200*time.Millisecond, 1500*time.Millisecond)

	if got := estimator.Backoff(); got != 1000*time.Millisecond {
		t.Fatalf("first Backoff() = %s, want %s", got, 1000*time.Millisecond)
	}
	if got := estimator.Backoff(); got != 1500*time.Millisecond {
		t.Fatalf("second Backoff() = %s, want %s", got, 1500*time.Millisecond)
	}
	if got := estimator.Backoff(); got != 1500*time.Millisecond {
		t.Fatalf("third Backoff() = %s, want %s", got, 1500*time.Millisecond)
	}
}
