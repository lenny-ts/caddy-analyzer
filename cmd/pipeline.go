package cmd

import (
	"context"
	"runtime"
	"sync"

	"github.com/lenny-ts/caddy-analyzer/pkg/parser"
	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

type parsedResult struct {
	seq   uint64
	entry types.Entry
	err   error
}

// processParsedLines parses input concurrently and reduces results in input
// order. Keeping the reducer ordered preserves stateful detector semantics.
func processParsedLines(ctx context.Context, lines <-chan string, workers int, fn func(types.Entry, error)) {
	if workers <= 1 {
		for line := range lines {
			entry, err := parser.Parse(line)
			fn(entry, err)
		}
		return
	}

	type job struct {
		seq  uint64
		line string
	}
	jobs := make(chan job)
	results := make(chan parsedResult, workers*2)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				entry, err := parser.Parse(j.line)
				results <- parsedResult{seq: j.seq, entry: entry, err: err}
			}
		}()
	}

	go func() {
		seq := uint64(0)
		for line := range lines {
			select {
			case jobs <- job{seq: seq, line: line}:
				seq++
			case <-ctx.Done():
				close(jobs)
				wg.Wait()
				close(results)
				return
			}
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	pending := make(map[uint64]parsedResult)
	next := uint64(0)
	for result := range results {
		pending[result.seq] = result
		for {
			ready, ok := pending[next]
			if !ok {
				break
			}
			fn(ready.entry, ready.err)
			delete(pending, next)
			next++
		}
	}
}

func configuredWorkers() int {
	if flagWorkers == 0 {
		return runtime.GOMAXPROCS(0)
	}
	return flagWorkers
}
