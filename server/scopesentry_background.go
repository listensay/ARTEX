package server

import (
	"sync"
	"time"

	"github.com/Autumn-27/artex/agent"
)

type scopeSentryJob struct {
	mu      sync.Mutex
	running bool
	next    time.Time
}

// Optional remote recon never occupies the planner/worker critical path.
func (s *Server) queueScopeSentry(t *Task) {
	if s.ctx.Err() != nil || s.engine.IsDeleting(t.ID) || s.engine.IsPaused(t.ID) {
		return
	}
	state := t.lifecycleSnapshot()
	if state.Paused || state.Queued {
		return
	}
	value, _ := s.scopeSentryJobs.LoadOrStore(t.ID, &scopeSentryJob{})
	job := value.(*scopeSentryJob)
	job.mu.Lock()
	if job.running || time.Now().Before(job.next) {
		job.mu.Unlock()
		return
	}
	job.running = true
	job.mu.Unlock()
	s.scopeSentryInit.Do(func() { s.scopeSentrySlots = make(chan struct{}, 4) })
	finish := func() {
		job.mu.Lock()
		job.running, job.next = false, time.Now().Add(time.Minute)
		job.mu.Unlock()
	}
	if !s.startBackground(func() {
		defer finish()
		ctx := s.engine.execContextFor(s.ctx, t.ID)
		select {
		case s.scopeSentrySlots <- struct{}{}:
			defer func() { <-s.scopeSentrySlots }()
		case <-ctx.Done():
			return
		}
		// The execution context is task-scoped, not tied to a short-lived worker.
		_, _ = s.runScopeSentry(ctx, t, "system", false, false)
	}) {
		finish()
	}
}

func (t *Task) notifyScopeSentry(summary string) {
	t.trigMu.Lock()
	for i := range t.pendingTriggers {
		if t.pendingTriggers[i].Kind == "scopesentry" {
			t.pendingTriggers[i].Detail = summary
			t.trigMu.Unlock()
			t.Notify()
			return
		}
	}
	t.pendingTriggers = append(t.pendingTriggers, agent.TriggerEvent{Kind: "scopesentry", Detail: summary})
	t.trigMu.Unlock()
	t.Notify()
}

// Explicit refreshes still run synchronously in their own request context.
func (s *Server) resetScopeSentryRefresh(t *Task) {
	if value, ok := s.scopeSentryJobs.Load(t.ID); ok {
		job := value.(*scopeSentryJob)
		job.mu.Lock()
		job.next = time.Time{}
		job.mu.Unlock()
	}
}
