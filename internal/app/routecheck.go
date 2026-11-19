package app

import (
	"context"

	"github.com/avazar/zaslon/internal/config"
	"github.com/avazar/zaslon/internal/guard"
	"github.com/avazar/zaslon/internal/netwatch"
)

// MeasureRoutes uses the regular probe worker with a private result channel.
// No diagnostic result is submitted to the guard or its scheduler.
func MeasureRoutes(ctx context.Context, cfg *config.Config, active map[string]bool) (guard.ProbeResult, error) {
	c := cfg.Clone()
	c.DNSCheck = "off"
	worker := Runner{ctx: ctx, results: make(chan guard.ProbeResult, 4), geo: netwatch.NewGeo()}
	stop := worker.probe(c, 0, guard.ProbePlan{General: true, Apps: active})
	defer stop()
	for {
		select {
		case <-ctx.Done():
			return guard.ProbeResult{}, ctx.Err()
		case result := <-worker.results:
			if result.Retry != nil {
				result.Retry <- false
			}
			if result.Part == guard.CompleteProbe {
				return result, nil
			}
		}
	}
}
