//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// sessionSandbox is one chat session's sandbox: a sandbox id that stays fixed
// for the session and a generation counter that advances on every relaunch.
// Runs within a session are serialised (the engine runs one turn at a time),
// which also makes relaunching between runs trivially safe.
type sessionSandbox struct {
	key       string
	sessionID string
	sandboxID string

	mu         sync.Mutex // held for the whole of a run or a relaunch
	exec       *executor  // nil until the first run, after the instance died, or after a stop
	generation uint64
	created    time.Time
	launched   time.Time

	// busy and lastUsed are guarded by the pool mutex.
	busy     int
	lastUsed time.Time
}

type sessionInfo struct {
	Session    string `json:"session"`
	SandboxID  string `json:"sandboxId"`
	Generation uint64 `json:"generation"`
	Running    bool   `json:"running"`
	Busy       bool   `json:"busy"`
	KeyedRPCs  int    `json:"keyedRpcs"`
	IdleMs     int64  `json:"idleMs"`
	UptimeMs   int64  `json:"uptimeMs"`
}

// pool owns the per-session sandboxes: it creates them on first use, relaunches
// them when sandboxd exits or its idempotency ledger nears the cap, evicts the
// least recently used idle one when the session cap is reached, and reaps idle
// ones in the background.
type pool struct {
	plan   *launcherPlan
	budget int
	limit  int

	mu       sync.Mutex
	sessions map[string]*sessionSandbox
	closed   bool
}

func newPool(plan *launcherPlan) *pool {
	return &pool{
		plan:     plan,
		budget:   plan.options.ledgerBudget,
		limit:    plan.options.maxSessions,
		sessions: map[string]*sessionSandbox{},
	}
}

// run executes one request inside the session's own sandbox.
func (p *pool) run(ctx context.Context, request runRequest) (*runResult, error) {
	if err := validateRunRequest(request); err != nil {
		return nil, err // before a sandbox is launched for it
	}
	sb, err := p.acquire(safeDirectory(request.SessionID), request.SessionID)
	if err != nil {
		return nil, err
	}
	defer p.release(sb)
	sb.mu.Lock()
	defer sb.mu.Unlock()

	var note string
	exec, err := p.ensure(sb, &note)
	if err != nil {
		return nil, err
	}
	result, err := exec.run(ctx, request)
	if shouldRelaunch(err) && ctx.Err() == nil {
		// The ledger filled up ahead of our count, or sandboxd stopped
		// answering: relaunch (a sandbox that stays broken would otherwise
		// fail every call of this session for good). The run itself is only
		// repeated when sandboxd never accepted the spawn; once the process
		// may have started, running the script a second time is not ours to
		// decide (the python tool's replay policy is "never"), so the failure
		// is reported and the fresh sandbox waits for the next call.
		reason := "sandboxd did not serve the request: " + err.Error()
		if wasSpawned(err) {
			if _, relaunchErr := p.relaunch(sb, reason, &note); relaunchErr != nil {
				return nil, fmt.Errorf("%w (and relaunching the sandbox failed: %v)", err, relaunchErr)
			}
			return nil, fmt.Errorf("%w; the sandbox was relaunched (/workspace reset) but the script was not run again because it may already have run", err)
		}
		exec, err = p.relaunch(sb, reason, &note)
		if err != nil {
			return nil, err
		}
		result, err = exec.run(ctx, request)
	}
	if err != nil {
		return nil, err
	}
	result.SandboxID = sb.sandboxID
	result.Generation = sb.generation
	result.Note = note
	return result, nil
}

func (p *pool) acquire(key, sessionID string) (*sessionSandbox, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, errors.New("sandbox agent is shutting down")
	}
	sb := p.sessions[key]
	if sb == nil {
		if len(p.sessions) >= p.limit {
			victim := p.idleVictimLocked()
			if victim == nil {
				return nil, fmt.Errorf("too many concurrent sandbox sessions (%d busy); try again later", len(p.sessions))
			}
			delete(p.sessions, victim.key)
			go victim.stop("evicted: session cap reached")
		}
		sb = &sessionSandbox{key: key, sessionID: sessionID, sandboxID: newIdentity("sandbox"), created: time.Now()}
		p.sessions[key] = sb
	}
	sb.busy++
	sb.lastUsed = time.Now()
	return sb, nil
}

func (p *pool) release(sb *sessionSandbox) {
	p.mu.Lock()
	sb.busy--
	sb.lastUsed = time.Now()
	p.mu.Unlock()
}

// idleVictimLocked picks the least recently used session with no run in flight.
func (p *pool) idleVictimLocked() *sessionSandbox {
	var victim *sessionSandbox
	for _, sb := range p.sessions {
		if sb.busy == 0 && (victim == nil || sb.lastUsed.Before(victim.lastUsed)) {
			victim = sb
		}
	}
	return victim
}

// ensure returns a live executor for the session, launching or relaunching
// sandboxd as needed. The caller holds sb.mu.
func (p *pool) ensure(sb *sessionSandbox, note *string) (*executor, error) {
	if sb.exec != nil {
		if sb.exec.inst.exited() {
			logf("session %s: sandboxd %s gen %d exited (%v)", sb.sessionID, sb.sandboxID, sb.generation, sb.exec.inst.err)
			sb.exec.inst.cleanup()
			sb.exec = nil
			*note = fmt.Sprintf("the sandbox for this session had exited and was relaunched (generation %d); /workspace was reset", sb.generation+1)
			return p.launch(sb)
		}
		if sb.exec.keyed >= p.budget {
			return p.relaunch(sb, fmt.Sprintf("idempotency budget of %d keyed RPCs used", p.budget), note)
		}
		return sb.exec, nil
	}
	if sb.generation > 0 {
		*note = fmt.Sprintf("the sandbox for this session was relaunched (generation %d); /workspace was reset", sb.generation+1)
	}
	return p.launch(sb)
}

func (p *pool) relaunch(sb *sessionSandbox, reason string, note *string) (*executor, error) {
	logf("session %s: rotating sandboxd %s gen %d -> %d: %s", sb.sessionID, sb.sandboxID, sb.generation, sb.generation+1, reason)
	sb.exec.inst.stop()
	sb.exec = nil
	*note = fmt.Sprintf("the sandbox for this session was relaunched (generation %d; %s); /workspace was reset", sb.generation+1, reason)
	return p.launch(sb)
}

func (p *pool) launch(sb *sessionSandbox) (*executor, error) {
	sb.generation++ // a failed launch still spends the generation number
	inst, err := p.plan.launch(sb.sandboxID, sb.generation)
	if err != nil {
		return nil, fmt.Errorf("launch sandboxd for session %s: %w", sb.sessionID, err)
	}
	client := newSandboxClient(inst.SocketPath, inst.ServerUID, inst.ID, inst.Generation, inst.Nonce)
	for index := range inst.Nonce {
		inst.Nonce[index] = 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	err = client.handshake(ctx)
	cancel()
	if err != nil {
		inst.stop()
		return nil, fmt.Errorf("sandboxd handshake for session %s: %w", sb.sessionID, err)
	}
	sb.exec = newExecutor(client, inst, p.plan.Backend, p.plan.EnvironmentDigest)
	sb.launched = time.Now()
	logf("session %s: sandboxd %s gen %d ready (%s)", sb.sessionID, sb.sandboxID, sb.generation, p.plan.Launcher)
	return sb.exec, nil
}

// stop ends the session's sandboxd if one is running.
func (sb *sessionSandbox) stop(reason string) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	if sb.exec == nil {
		return
	}
	logf("session %s: stopping sandboxd %s gen %d (%s)", sb.sessionID, sb.sandboxID, sb.generation, reason)
	sb.exec.inst.stop()
	sb.exec = nil
}

// closeSession forgets the session and stops its sandbox in the background
// (a run in flight finishes first because stop waits for sb.mu).
func (p *pool) closeSession(key string) bool {
	p.mu.Lock()
	sb := p.sessions[key]
	delete(p.sessions, key)
	p.mu.Unlock()
	if sb == nil {
		return false
	}
	go sb.stop("session deleted")
	return true
}

// reap stops sandboxes that have been idle longer than `idle`.
func (p *pool) reap(idle time.Duration) {
	p.mu.Lock()
	var victims []*sessionSandbox
	for key, sb := range p.sessions {
		if sb.busy == 0 && time.Since(sb.lastUsed) > idle {
			delete(p.sessions, key)
			victims = append(victims, sb)
		}
	}
	p.mu.Unlock()
	for _, sb := range victims {
		sb.stop(fmt.Sprintf("idle for %s", idle))
	}
}

func (p *pool) runReaper(idle time.Duration, stop <-chan struct{}) {
	if idle <= 0 {
		return
	}
	interval := idle / 4
	if interval > 30*time.Second {
		interval = 30 * time.Second
	}
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			p.reap(idle)
		case <-stop:
			return
		}
	}
}

func (p *pool) list() []sessionInfo {
	p.mu.Lock()
	defer p.mu.Unlock()
	infos := make([]sessionInfo, 0, len(p.sessions))
	for _, sb := range p.sessions {
		info := sessionInfo{Session: sb.sessionID, SandboxID: sb.sandboxID, Busy: sb.busy > 0, IdleMs: time.Since(sb.lastUsed).Milliseconds()}
		// exec/generation are guarded by sb.mu; take a snapshot without blocking on a run.
		if sb.mu.TryLock() {
			info.Generation = sb.generation
			info.Running = sb.exec != nil && !sb.exec.inst.exited()
			if sb.exec != nil {
				info.KeyedRPCs = sb.exec.keyed
				info.UptimeMs = time.Since(sb.launched).Milliseconds()
			}
			sb.mu.Unlock()
		} else {
			info.Running = true
		}
		infos = append(infos, info)
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].Session < infos[j].Session })
	return infos
}

// close stops every sandbox; new runs are refused from now on.
func (p *pool) close() {
	p.mu.Lock()
	p.closed = true
	all := make([]*sessionSandbox, 0, len(p.sessions))
	for key, sb := range p.sessions {
		all = append(all, sb)
		delete(p.sessions, key)
	}
	p.mu.Unlock()
	var wg sync.WaitGroup
	for _, sb := range all {
		wg.Add(1)
		go func(sb *sessionSandbox) {
			defer wg.Done()
			sb.stop("agent shutdown")
		}(sb)
	}
	wg.Wait()
}

// probe launches a throwaway sandbox, runs a trivial script, and tears it down,
// so a broken launcher is discovered at startup rather than on the first call.
func (p *pool) probe(ctx context.Context) (time.Duration, error) {
	started := time.Now()
	sb := &sessionSandbox{key: "probe", sessionID: "probe", sandboxID: newIdentity("sandbox"), created: started}
	sb.mu.Lock()
	defer sb.mu.Unlock()
	exec, err := p.launch(sb)
	if err != nil {
		return 0, err
	}
	defer func() {
		exec.inst.stop()
		sb.exec = nil
	}()
	result, err := exec.run(ctx, runRequest{
		SessionID: "probe", TurnID: "turn_probe", ToolCallID: "call_probe", ReplayPolicy: "never",
		Code:      "import os\nprint('ok', os.getcwd())",
		TimeoutMs: 20_000,
	})
	if err != nil {
		return 0, fmt.Errorf("probe run: %w", err)
	}
	if result.ExitCode != 0 || result.Stdout != "ok /workspace\n" {
		return 0, fmt.Errorf("probe run misbehaved: exit %d, stdout %q, stderr %q", result.ExitCode, result.Stdout, result.Stderr)
	}
	return time.Since(started), nil
}
