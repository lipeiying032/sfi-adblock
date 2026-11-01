package mitm

import (
	rmetrics "runtime/metrics"
	"sync"
	"sync/atomic"
	"time"
)

// The network extension runs with a ~50 MiB budget. Decryption is dropped
// before the allocator gets close to the limit; connections then pass through
// untouched instead of failing.
const (
	memoryHighWatermark = int64(36 << 20)
	memoryLowWatermark  = int64(28 << 20)
)

var (
	memoryPressure    atomic.Bool
	memoryMonitorOnce sync.Once
)

func startMemoryMonitor() {
	memoryMonitorOnce.Do(func() {
		go func() {
			samples := []rmetrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
			for {
				rmetrics.Read(samples)
				if samples[0].Value.Kind() == rmetrics.KindUint64 {
					value := int64(samples[0].Value.Uint64())
					switch {
					case value >= memoryHighWatermark:
						memoryPressure.Store(true)
					case value <= memoryLowWatermark:
						memoryPressure.Store(false)
					}
				}
				time.Sleep(5 * time.Second)
			}
		}()
	})
}

func underMemoryPressure() bool {
	return memoryPressure.Load()
}
