package server

import (
	"context"
	"fmt"
	"log"
	"sync/atomic"
)

type taskWorker struct {
	name     string
	runtime  *taskRuntime
	retiring atomic.Bool
}

// syncTaskWorkersLocked requires deleteMu.RLock and runtimeMu. All goroutine
// registrations therefore happen before shutdown/deletion can start waiting.
func (e *Engine) syncTaskWorkersLocked(t *Task, rt *taskRuntime, count int) bool {
	if rt.ctx.Err() != nil {
		return false
	}
	rt.workerMu.Lock()
	defer rt.workerMu.Unlock()
	previous := len(rt.workers)
	for len(rt.workers) > count {
		last := len(rt.workers) - 1
		rt.workers[last].retiring.Store(true)
		rt.workers[last] = nil
		rt.workers = rt.workers[:last]
	}
	for len(rt.workers) < count {
		rt.nextWorker++
		slot := &taskWorker{name: fmt.Sprintf("work#%d", rt.nextWorker), runtime: rt}
		rt.workers = append(rt.workers, slot)
		rt.wg.Add(1)
		runTaskRoutine(rt, func(ctx context.Context) { e.workerLoop(ctx, t, slot) })
	}
	if previous != count {
		log.Printf("[workers] task %s 并发容量 %d → %d；缩容的 work 完成当前意图后退出", t.ID, previous, count)
	}
	return previous != count
}

// RefreshWorkers applies the persisted limit to existing task pools. Reading the
// setting under runtimeMu also keeps overlapping saves from applying stale counts.
func (e *Engine) RefreshWorkers() {
	e.deleteMu.RLock()
	defer e.deleteMu.RUnlock()
	if e.closed.Load() {
		return
	}
	e.runtimeMu.Lock()
	defer e.runtimeMu.Unlock()
	count := e.m.Workers()
	for taskID, rt := range e.runtimes {
		if !e.Started(taskID) || e.IsDeleting(taskID) {
			continue
		}
		if t, ok := e.m.Task(taskID); ok && !isTerminalStatus(t.lifecycleSnapshot().Status) {
			if e.syncTaskWorkersLocked(t, rt, count) {
				t.Notify()
			}
		}
	}
}

// WorkerLimit reports slots allowed to claim new work. Retiring slots may still
// be finishing an intent and remain tracked by the task runtime's WaitGroup.
func (e *Engine) WorkerLimit(taskID string) int {
	e.runtimeMu.Lock()
	defer e.runtimeMu.Unlock()
	if rt := e.runtimes[taskID]; rt != nil {
		rt.workerMu.Lock()
		defer rt.workerMu.Unlock()
		return len(rt.workers)
	}
	return 0
}
