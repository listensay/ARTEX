package server

import (
	"context"
	"log"
	"time"
)

const (
	p0PriorityThreshold = 8
	p0ClaimTimeout      = 5 * time.Minute
	p0WatchInterval     = time.Minute
)

func (e *Engine) intentWatchdog(ctx context.Context, t *Task) {
	ticker := time.NewTicker(p0WatchInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.reportOverdueP0Intents(t)
		}
	}
}

func (e *Engine) reportOverdueP0Intents(t *Task) {
	if t == nil || t.Store == nil || e.IsPaused(t.ID) || e.isSettling(t.ID) {
		return
	}
	if e.m != nil && isTerminalStatus(e.m.TaskStatus(t.ID)) {
		return
	}
	if _, worker := e.snapshotFor(t); worker == nil {
		return
	}
	if !e.beginTaskOperation(t.ID) {
		return
	}
	defer e.decInflight(t.ID)
	if n, err := t.Store.ReportOverdueIntents(time.Now(), p0PriorityThreshold, p0ClaimTimeout); err != nil {
		log.Printf("[scheduler] task %s overdue-intent audit failed: %v", t.ID, err)
	} else if n > 0 {
		log.Printf("[scheduler] task %s wrote %d overdue-intent hints", t.ID, n)
	}
}
