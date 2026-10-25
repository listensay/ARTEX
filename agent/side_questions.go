package agent

import (
	"context"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/sidequestion"
	"github.com/Autumn-27/norma/agentcore"
)

func attachSideCapture(ctx context.Context, opts *agentcore.Options) context.Context {
	ri := RunInfoFrom(ctx)
	p := sidequestion.Parent{TaskID: ri.TaskID, ExplorationID: ri.ExplorationID, IntentID: ri.IntentID}
	if strings.HasPrefix(ri.SessionID, "conv-") {
		if id, err := strconv.ParseInt(strings.TrimPrefix(ri.SessionID, "conv-"), 10, 64); err == nil && id > 0 {
			// Finding checks retain task attribution in RunInfo for tools, but
			// their checkpoint belongs only to the conversation. Mixing both
			// parents violates the side-session constraint and blocks task drains.
			p = sidequestion.Parent{ConversationID: id}
		}
	}
	if p.ConversationID == 0 && (p.TaskID == 0 || p.ExplorationID == 0) {
		return ctx
	}
	ctx, opts.Deps = sidequestion.Attach(ctx, p, opts.Deps, opts.Provider)
	return ctx
}
