//go:build linux

package agent

import (
	"context"
	"errors"
	"math"
	"time"
)

const maximumWorkerdObservationInterval = time.Minute

// WorkerdObservationSink consumes immutable generation-bound shard
// observations. The launcher calls it from a per-generation observer
// goroutine with no launcher, instance, cgroup, or process-identity locks
// held. The sink may synchronously reenter the launcher, including a
// Handle.Stop that drains the observed shard; stop epochs cancel the observer
// without joining it, so that reentrant stop completes and the sink call
// returns before the launcher's final observer join. A sink must eventually
// return for every delivery. ErrShardNotFound means the sink has not adopted
// the shard yet, and the observer retries on its next tick; any other error
// ends the observer for that generation.
type WorkerdObservationSink interface {
	Observe(ShardObservation) error
}

// Manager's fenced observation endpoint is the intended production sink.
var _ WorkerdObservationSink = (*Manager)(nil)

// workerdShardObserver owns the single serialized observation producer for
// one published shard generation.
type workerdShardObserver struct {
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
}

// nextWorkerdObservationSequence allocates the next generation-local
// observation sequence only after a fully formed sample. It fails closed at
// exhaustion: a sequence never wraps inside one generation.
func nextWorkerdObservationSequence(current uint64) (uint64, bool) {
	if current == math.MaxUint64 {
		return 0, false
	}
	return current + 1, true
}

func (instance *workerdInstance) cancelObserver() {
	instance.mu.Lock()
	observer := instance.observer
	instance.mu.Unlock()
	if observer != nil {
		observer.cancel()
	}
}

// runWorkerdObserver serializes complete cgroup and process-RSS samples into
// strictly increasing generation-local sequences and delivers them to the
// configured sink. Ending the producer disables OOM and RSS draining for the
// generation, so only failures that no later tick can recover end it: a
// cgroup lease that was released or poisoned, a process identity that was
// closed or recycled, sequence exhaustion, cancellation, and every sink error
// except ErrShardNotFound. A sample that fails for any other reason, and a
// delivery the sink rejects because it has not adopted the shard yet, are
// retried on the next tick, so the observation interval bounds the retry
// rate. A sample whose cancellation wins after I/O but before delivery is
// suppressed, leaving a sequence gap instead of a stale delivery.
func (launcher *WorkerdProcessLauncher) runWorkerdObserver(instance *workerdInstance, observer *workerdShardObserver) {
	defer func() {
		launcher.mu.Lock()
		delete(launcher.observers, observer)
		launcher.mu.Unlock()
		close(observer.done)
	}()
	ticker := time.NewTicker(launcher.observationInterval)
	defer ticker.Stop()
	sequence := uint64(0)
	for {
		select {
		case <-observer.ctx.Done():
			return
		case <-ticker.C:
		}
		cgroupSample, cgroupErr := instance.cgroup.sampleResources(observer.ctx)
		if cgroupErr != nil {
			if errors.Is(cgroupErr, errWorkerdCgroupLeaseUnavailable) || errors.Is(cgroupErr, errWorkerdCgroupPoisoned) ||
				errors.Is(cgroupErr, errInvalidWorkerdCgroupRequest) {
				return
			}
			continue
		}
		rssSample, rssErr := instance.processIdentity.sampleRSS(launcher.observationPageSize)
		if rssErr != nil {
			if errors.Is(rssErr, errWorkerdProcessIdentityUnavailable) || errors.Is(rssErr, errStaleWorkerdProcessIdentity) ||
				errors.Is(rssErr, errInvalidWorkerdProcessRequest) {
				return
			}
			continue
		}
		nextSequence, sequenceAvailable := nextWorkerdObservationSequence(sequence)
		if !sequenceAvailable {
			return
		}
		sequence = nextSequence
		if observer.ctx.Err() != nil {
			return
		}
		observation := ShardObservation{
			AgentInstanceID:     instance.key.agentInstanceID,
			ShardID:             instance.key.shardID,
			ShardGeneration:     instance.key.generation,
			ObservationSequence: sequence,
			RSSBytes:            rssSample.RSSBytes,
			OOMObserved: cgroupSample.MemoryEventsDelta.OOM > 0 ||
				cgroupSample.MemoryEventsDelta.OOMKill > 0 ||
				cgroupSample.MemoryEventsDelta.OOMGroupKill > 0,
			HeapPressure: cgroupSample.MemoryEventsDelta.High > 0 ||
				cgroupSample.MemoryEventsDelta.Max > 0,
			ObservedAt: time.Now(),
		}
		if sinkErr := launcher.observationSink.Observe(observation); sinkErr != nil && !errors.Is(sinkErr, ErrShardNotFound) {
			return
		}
	}
}
