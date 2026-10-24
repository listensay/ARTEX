package server

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestEngineCloseWaitsForTaskCleanup(t *testing.T) {
	e := NewEngine(&Manager{})
	e.deleteMu.RLock()
	rt := e.registerTaskRoutines(context.Background(), "fixture", 1)
	e.deleteMu.RUnlock()
	cleanup := make(chan struct{})
	release := make(chan struct{})
	var finished atomic.Bool
	runTaskRoutine(rt, func(ctx context.Context) {
		<-ctx.Done()
		close(cleanup)
		<-release
		finished.Store(true)
	})
	closed := make(chan struct{})
	go func() { e.Close(); close(closed) }()
	select {
	case <-cleanup:
	case <-time.After(5 * time.Second):
		t.Fatal("task was not cancelled")
	}
	select {
	case <-closed:
		t.Fatal("engine closed before task cleanup finished")
	default:
	}
	if e.beginTaskOperation("late-task") {
		t.Fatal("accepted a task operation during shutdown")
	}
	close(release)
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("engine did not finish closing")
	}
	if !finished.Load() {
		t.Fatal("task cleanup was lost")
	}
	e.Close()
}

func TestManagedShutdownDrainsBeforeDatabaseClose(t *testing.T) {
	fixture := securityServer(t)
	dir := t.TempDir()
	s := New(context.Background(), fixture.m, dir, dir, dir)
	cleanup := make(chan struct{})
	release := make(chan struct{})
	queryErr := make(chan error, 1)
	if !s.startBackground(func() {
		<-s.ctx.Done()
		var n int
		queryErr <- s.m.pg.QueryRow("SELECT 1").Scan(&n)
		close(cleanup)
		<-release
	}) {
		t.Fatal("background registration failed")
	}
	closed := make(chan error, 1)
	go func() { closed <- s.m.Close() }()
	select {
	case <-cleanup:
	case <-time.After(5 * time.Second):
		t.Fatal("manager did not cancel the server context")
	}
	if err := <-queryErr; err != nil {
		t.Errorf("database closed before background cleanup: %v", err)
	}
	select {
	case <-closed:
		t.Error("manager returned before background cleanup")
	default:
	}
	if s.startBackground(func() { t.Error("ran work after shutdown") }) {
		t.Error("registered background work after shutdown")
	}
	close(release)
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("manager did not finish closing")
	}
}
