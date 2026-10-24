package server

import (
	"context"
	"errors"
	"github.com/Autumn-27/artex/agent"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestFreezeDeadlinePersistsAndRejectsStaleGeneration(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	task, err := m.CreateTask("freeze fixture", "fixture", nil, 120, 600)
	if err != nil {
		t.Fatal(err)
	}
	defer m.pg.DeleteTask(stabilityTaskID(t, task.ID))
	old, err := m.StampTaskFirstRun(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(m)
	if err := e.extendDeadline(task, 65*time.Second); err != nil {
		t.Fatal(err)
	}
	if got := e.taskDeadline(task); got != old+65 {
		t.Fatalf("deadline=%d want=%d", got, old+65)
	}
	stored, err := m.pg.GetTask(stabilityTaskID(t, task.ID))
	if err != nil || stored.DeadlineAt == nil || stored.DeadlineAt.Unix() != old+65 {
		t.Fatalf("stored=%+v err=%v", stored, err)
	}
	// A separate Manager reloads the committed clock from PostgreSQL.
	m2, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer m2.Close()
	m2.LoadExisting()
	loaded, ok := m2.Task(task.ID)
	if !ok {
		t.Fatal("task missing after reload")
	}
	if loaded.lifecycleSnapshot().DeadlineAt != old+65 {
		t.Fatal("restart lost extension")
	}
	if dl, err := m.ExtendTaskDeadline(task.ID, old, 65); err != nil || dl != 0 {
		t.Fatalf("stale dl=%d err=%v", dl, err)
	}
	if _, err := m.SetTaskStatusGuarded(task.ID, "done"); err != nil {
		t.Fatal(err)
	}
	if dl, err := m.ExtendTaskDeadline(task.ID, old+65, 65); err != nil || dl != 0 {
		t.Fatalf("terminal dl=%d err=%v", dl, err)
	}
}

func TestFreezeConcurrentExtensionSingleGeneration(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	task, err := m.CreateTask("freeze race", "fixture", nil, 120, 600)
	if err != nil {
		t.Fatal(err)
	}
	defer m.pg.DeleteTask(stabilityTaskID(t, task.ID))
	old, err := m.StampTaskFirstRun(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := m.ExtendTaskDeadline(task.ID, old, 65)
			if err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if task.lifecycleSnapshot().DeadlineAt != old+65 {
		t.Fatal("duplicate extension")
	}
}

func TestPortAuditLifecycleAndActualPort(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	m.StartPortAudit(l.Addr())
	m.StartPortAudit(l.Addr())
	port := l.Addr().(*net.TCPAddr).Port
	if _, ok := m.managedPorts.Load(port); !ok {
		t.Fatalf("actual port %d not registered", port)
	}
	done := make(chan struct{})
	go func() { m.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("audit did not stop on Close")
	}
}

func TestMainAgentKillWorkNamedCause(t *testing.T) {
	e := NewEngine(nil)
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	e.work[7] = &workExecution{cancel: cancel}
	if err := e.KillWorkByMainAgent(7); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(context.Cause(ctx), agent.AbortKilledByMainAgent) {
		t.Fatalf("cause=%v", context.Cause(ctx))
	}
}

func stabilityTaskID(t *testing.T, id string) int64 {
	t.Helper()
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestFreezeIgnoresOldClockAfterReset(t *testing.T) {
	e := NewEngine(nil)
	task := &Task{ID: "fixture"}
	e.deadline.Store(task.ID, int64(123))
	if e.taskDeadline(task) != 0 {
		t.Fatal("old cached deadline resurrected after reset")
	}
	task.updateLifecycle(func(s *taskLifecycleState) { s.DeadlineAt = 456 })
	if err := e.extendDeadlineAt(task, time.Hour, 123); err != nil {
		t.Fatal(err)
	}
	if e.taskDeadline(task) != 456 {
		t.Fatal("old sleep extended a new generation")
	}
}
