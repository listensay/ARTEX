package agent

import "context"

type workerConcurrencyKey struct{}

// WithWorkerConcurrency carries the actual task pool capacity into a planning
// round, independently of a shared Planner's configuration.
func WithWorkerConcurrency(ctx context.Context, count int) context.Context {
	return context.WithValue(ctx, workerConcurrencyKey{}, count)
}

func workerConcurrencyFrom(ctx context.Context) int {
	count, _ := ctx.Value(workerConcurrencyKey{}).(int)
	return max(0, count)
}
