package server

import (
	"log"
	"strconv"
	"time"
)

const freezeDetectThreshold = 60 * time.Second

func detectFreeze(planned, actual time.Duration) time.Duration {
	if extra := actual - planned; extra >= freezeDetectThreshold {
		return extra
	}
	return 0
}

func (m *Manager) ExtendTaskDeadline(id string, expected, seconds int64) (int64, error) {
	m.taskStateMu.Lock()
	defer m.taskStateMu.Unlock()
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return 0, err
	}
	deadline, err := m.pg.ExtendTaskDeadline(n, expected, seconds)
	if err != nil || deadline == nil {
		return 0, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if t := m.tasks[id]; t != nil {
		t.updateLifecycle(func(s *taskLifecycleState) { s.DeadlineAt = deadline.Unix() })
	}
	return deadline.Unix(), nil
}

func (e *Engine) extendDeadline(t *Task, shift time.Duration) error {
	return e.extendDeadlineAt(t, shift, e.taskDeadline(t))
}

func (e *Engine) extendDeadlineAt(t *Task, shift time.Duration, expected int64) error {
	if shift <= 0 || e.isSettling(t.ID) {
		return nil
	}
	if !e.beginTaskOperation(t.ID) {
		return nil
	}
	defer e.decInflight(t.ID)
	old := e.taskDeadline(t)
	if old <= 0 || old != expected {
		return nil
	}
	seconds := int64(shift / time.Second)
	if shift%time.Second != 0 {
		seconds++
	}
	deadline, err := e.m.ExtendTaskDeadline(t.ID, old, seconds)
	if err != nil {
		return err
	}
	if deadline > 0 {
		log.Printf("[deadline] task %s detected scheduler/wall-clock gap %s; persisted extension to %s", t.ID, shift.Round(time.Second), time.Unix(deadline, 0).Format(time.RFC3339))
	}
	return nil
}
