package agent

import (
	"context"
	"errors"
	"fmt"
	"github.com/Autumn-27/norma/llm"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCallTimeoutRealHTTPStall(t *testing.T) {
	for _, stream := range []bool{true, false} {
		t.Run(fmt.Sprint(stream), func(t *testing.T) {
			disconnected := make(chan struct{}, 1)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body)
				r.Body.Close()
				if stream {
					w.Header().Set("Content-Type", "text/event-stream")
					fmt.Fprint(w, "data: {\"id\":\"fixture\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"partial\"}}]}\n\n")
					w.(http.Flusher).Flush()
				}
				select {
				case <-r.Context().Done():
				case <-time.After(5 * time.Second):
				}
				select {
				case disconnected <- struct{}{}:
				default:
				}
			}))
			defer upstream.Close()
			t.Setenv("ARTEX_LLM_CALL_TIMEOUT", "0")
			c := ConfigFrom("openai", "fixture", upstream.URL, "fixture-key", "")
			c.Retry.ConnectAttempts = -1
			c.Retry.EmptyAttempts = -1
			inner, err := c.NewProvider()
			if err != nil {
				t.Fatal(err)
			}
			p := &callTimeoutProvider{inner: inner, timeout: 150 * time.Millisecond, provider: "openai", model: "fixture"}
			req := llm.CompletionRequest{Messages: []llm.Message{{Role: "user", Content: []llm.ContentBlock{{Type: "text", Text: "fixture"}}}}}
			var text string
			if stream {
				for ev, e := range p.Stream(context.Background(), req) {
					if ev.Type == llm.SETextDelta {
						text += ev.Text
					}
					if e != nil {
						err = e
					}
				}
			} else {
				_, _, _, err = p.Complete(context.Background(), req)
			}
			var timeout *CallTimeoutError
			if !errors.As(err, &timeout) {
				t.Fatalf("err=%v", err)
			}
			if stream && text != "partial" {
				t.Fatalf("lost partial stream: %q", text)
			}
			select {
			case <-disconnected:
			case <-time.After(time.Second):
				t.Fatal("HTTP request not cancelled")
			}
		})
	}
}

func TestCallTimeoutConsumerStopCancelsInner(t *testing.T) {
	var innerCtx context.Context
	inner := captureUsageProvider{stream: func(ctx context.Context, yield func(llm.StreamEvent, error) bool) {
		innerCtx = ctx
		yield(llm.StreamEvent{Type: llm.SETextDelta, Text: "partial"}, nil)
	}}
	p := &callTimeoutProvider{inner: inner, timeout: time.Hour}
	for range p.Stream(context.Background(), llm.CompletionRequest{}) {
		break
	}
	if innerCtx == nil || !errors.Is(innerCtx.Err(), context.Canceled) {
		t.Fatal("consumer stop leaked call context")
	}
}
