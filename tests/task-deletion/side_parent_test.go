package taskdeletion_test

import (
	"testing"

	"github.com/Autumn-27/artex/sidequestion"
)

func TestSideParentCanonicalOwnership(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   sidequestion.Parent
		want sidequestion.Parent
	}{
		{name: "empty"},
		{name: "conversation", in: sidequestion.Parent{ConversationID: 7}, want: sidequestion.Parent{ConversationID: 7}},
		{name: "legacy conversation", in: sidequestion.Parent{ConversationID: 7, TaskID: 13, ExplorationID: 14, IntentID: 15}, want: sidequestion.Parent{ConversationID: 7}},
		{name: "task", in: sidequestion.Parent{TaskID: 13, ExplorationID: 14}, want: sidequestion.Parent{TaskID: 13, ExplorationID: 14}},
		{name: "worker", in: sidequestion.Parent{TaskID: 13, ExplorationID: 14, IntentID: 15}, want: sidequestion.Parent{TaskID: 13, ExplorationID: 14, IntentID: 15}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.in.Canonical()
			if got != tc.want || got.Canonical() != got || got.Key() != tc.in.Key() {
				t.Fatalf("canonical owner changed identity: got=%+v want=%+v", got, tc.want)
			}
		})
	}
}
