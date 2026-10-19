package guardcore

// Mixed-fleet reader for the custom-pattern case of interop/run.py
// (guard-core 5.0.0 writes patterns:custom_list next to the legacy
// patterns:custom). run.py hands this file to `go test -overlay`, so nothing is
// written into the Go repo. It carries no build tag: the repo's interop-tagged
// runner does not compile at master (encodeCloudIPv2Payload returns one value
// where interop_runner_test.go expects two), and this probe needs none of it.
// The Go engine restores the custom patterns from the Redis prefix it is given
// and is held to what a real v4.4.0 Python engine restored from the same state:
// the same pattern set and the same verdicts.

import (
	"encoding/json"
	"os"
	"sort"
	"testing"
)

type mixedFleetCheck struct {
	Scenario  string `json:"scenario"`
	Direction string `json:"direction"`
	Name      string `json:"name"`
	Passed    bool   `json:"passed"`
	Detail    string `json:"detail"`
}

func TestMixedFleetCustomPatternsProbe(t *testing.T) {
	var incoming map[string]string
	if err := json.Unmarshal([]byte(os.Getenv("INTEROP_INPUT")), &incoming); err != nil {
		t.Fatalf("INTEROP_INPUT is not valid JSON: %v", err)
	}
	host, port := os.Getenv("REDIS_HOST"), os.Getenv("REDIS_PORT")
	if host == "" || port == "" {
		t.Fatal("REDIS_HOST and REDIS_PORT must be set")
	}
	redis := NewRedisManager(RedisConfig{
		URL:         "redis://" + host + ":" + port,
		Prefix:      incoming["prefix_root"] + "mf_go:",
		EnableRedis: true,
	})
	if err := redis.Initialize(); err != nil {
		t.Fatalf("redis initialize failed: %v", err)
	}
	defer func() { _ = redis.Close() }()

	manager := NewSusPatternsManager(nil)
	manager.InitializeRedis(redis)
	got := manager.GetCustomPatterns()
	sort.Strings(got)

	var want []string
	if err := json.Unmarshal([]byte(incoming["v440_patterns"]), &want); err != nil {
		t.Fatalf("v440_patterns is not a JSON list: %v", err)
	}
	var wantFlagged map[string]bool
	if err := json.Unmarshal([]byte(incoming["v440_flagged"]), &wantFlagged); err != nil {
		t.Fatalf("v440_flagged is not a JSON object: %v", err)
	}

	checks := []mixedFleetCheck{}
	record := func(name string, ok bool, detail string) {
		checks = append(checks, mixedFleetCheck{
			Scenario: "custom_patterns_port_read", Direction: "py:go", Name: name, Passed: ok, Detail: detail,
		})
	}
	gotJSON, _ := json.Marshal(got)
	wantJSON, _ := json.Marshal(want)
	record("go restores the same custom pattern set as v4.4.0 Python", string(gotJSON) == string(wantJSON), string(gotJSON))
	for path, wantThreat := range wantFlagged {
		verdict := manager.detect(path, "127.0.0.1", "request_path", "", false, nil)
		record("go flags "+path+" as v4.4.0 Python does", verdict.IsThreat == wantThreat, path)
	}

	passed, failed := 0, 0
	for _, c := range checks {
		if c.Passed {
			passed++
		} else {
			failed++
		}
		t.Logf("%v - [%s] %s (%s)", c.Passed, c.Scenario, c.Name, c.Detail)
	}
	report, _ := json.MarshalIndent(map[string]any{
		"participant": "go", "phase": "go_custom_patterns_read",
		"passed": passed, "failed": failed, "checks": checks,
		"artifacts": map[string]string{"go_patterns": string(gotJSON)},
	}, "", "  ")
	if err := os.WriteFile(os.Getenv("INTEROP_REPORT_FILE"), report, 0o644); err != nil {
		t.Fatalf("report write failed: %v", err)
	}
	if failed > 0 {
		t.Fatalf("%d custom-pattern checks failed", failed)
	}
}
