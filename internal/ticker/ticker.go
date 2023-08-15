package ticker

import (
	"time"
)

type Ticker struct {
	ticker  *time.Ticker
	timeout time.Duration
	C       <-chan time.Time
}

func NewTicker(timeout time.Duration) *Ticker {
	var t Ticker
	t.ticker = time.NewTicker(timeout)
	t.timeout = timeout
	t.C = t.ticker.C
	return &t
}

func (t Ticker) Reset() {
	t.ticker.Reset(time.Millisecond)
	<-t.C
	t.ticker.Reset(t.timeout)
}

func (t Ticker) Stop() {
	t.ticker.Stop()
}
