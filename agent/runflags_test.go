package agent

import (
	"testing"

	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
)

func asst(blocks ...llm.ContentBlock) llm.Message {
	return llm.Message{Role: llm.RoleAssistant, Content: blocks}
}

func toolUse(id, name string) llm.ContentBlock {
	return llm.ContentBlock{Type: llm.BlockToolUse, ID: id, Name: name}
}

func toolResult(id string) llm.Message {
	return llm.Message{Role: llm.RoleUser, Content: []llm.ContentBlock{
		{Type: llm.BlockToolResult, ToolUseID: id},
	}}
}

// A run that did real work (tool calls) but ended on a blank final turn is the
// upstream-empty-response signature — it must be flagged NoOutput even though the
// run made tool calls (this is exactly the case the earlier "zero tool calls" gate
// missed).
func TestRunFlagsBlankFinalTurnAfterWork(t *testing.T) {
	msgs := []llm.Message{
		asst(llm.ContentBlock{Type: llm.BlockThinking, Thinking: "thinking"}, toolUse("1", "Bash")),
		toolResult("1"),
		asst(llm.ContentBlock{Type: llm.BlockThinking, Thinking: "more thinking"}), // blank: no text, no tool
	}
	f := runFlags(msgs, harness.ReasonCompleted)
	if f.ToolCalls != 1 {
		t.Fatalf("ToolCalls = %d, want 1", f.ToolCalls)
	}
	if !f.NoOutput {
		t.Fatal("blank final turn should set NoOutput")
	}
	if !IsNoOutputRun(harness.ReasonCompleted, nil, f) {
		t.Fatal("blank-final-turn run should be a no-output run")
	}
}

// A run that ends with a real text summary is a normal completion, not NoOutput.
func TestRunFlagsTextSummaryIsNotNoOutput(t *testing.T) {
	msgs := []llm.Message{
		asst(toolUse("1", "Bash")),
		toolResult("1"),
		asst(llm.ContentBlock{Type: llm.BlockText, Text: "完成，写回 fact #66"}),
	}
	f := runFlags(msgs, harness.ReasonCompleted)
	if f.NoOutput {
		t.Fatal("a text summary must not be flagged NoOutput")
	}
	if IsNoOutputRun(harness.ReasonCompleted, nil, f) {
		t.Fatal("a text summary must not be a no-output run")
	}
}

// A run that never touched a tool and left nothing is also NoOutput.
func TestRunFlagsBlankFromStart(t *testing.T) {
	f := runFlags([]llm.Message{asst()}, harness.ReasonCompleted)
	if !f.NoOutput || f.ToolCalls != 0 {
		t.Fatalf("want blank NoOutput with 0 tool calls, got %+v", f)
	}
}

// NoOutput only applies to a natural end: an error or a budget terminal is not it.
func TestIsNoOutputRunGuards(t *testing.T) {
	f := RunFlags{ToolCalls: 0, NoOutput: true}
	if IsNoOutputRun(harness.ReasonModelError, nil, f) {
		t.Fatal("model_error must not be treated as no-output")
	}
	if IsNoOutputRun(harness.ReasonMaxTurns, nil, f) {
		t.Fatal("max_turns must not be treated as no-output")
	}
	if IsNoOutputRun(harness.ReasonCompleted, errFake, f) {
		t.Fatal("a non-nil error must not be treated as no-output")
	}
}

var errFake = &fakeErr{}

type fakeErr struct{}

func (*fakeErr) Error() string { return "boom" }
