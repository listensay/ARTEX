package server

import (
	"log"
	"strconv"
)

// startBackground serializes goroutine registration with Manager.Close.
func (s *Server) startBackground(fn func()) bool {
	s.backgroundMu.Lock()
	defer s.backgroundMu.Unlock()
	if s.closing || s.ctx.Err() != nil {
		return false
	}
	s.backgroundWG.Add(1)
	go func() {
		defer s.backgroundWG.Done()
		fn()
	}()
	return true
}

// A handoff is only admitted by an explicit start. Admission persists running,
// so restarts can distinguish it from a newly created, unstarted handoff.
func (s *Server) awaitingHandoffStart(t *Task) bool {
	if t == nil || s.m == nil || s.m.pg == nil {
		return false
	}
	lifecycle := t.lifecycleSnapshot()
	if lifecycle.Status != "created" || lifecycle.Queued {
		return false
	}
	id, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil {
		return true
	}
	required, err := s.m.Assets().ScopeApprovalRequired(id)
	if err != nil {
		log.Printf("[handoff] task %s read admission marker: %v", t.ID, err)
		return true
	}
	return required
}
