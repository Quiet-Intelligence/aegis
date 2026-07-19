package main

import (
	"os"
	"testing"

	"aegis/pkg/telemetry"
)

func TestNoContainerUsesDisabledScopeNotHostWide(t *testing.T) {
	t.Setenv("AEGIS_CONTAINER_NAME", "aegis-test-container-that-does-not-exist")
	old, had := os.LookupEnv("AEGIS_CGROUP_ID")
	os.Unsetenv("AEGIS_CGROUP_ID")
	t.Cleanup(func() {
		if had {
			os.Setenv("AEGIS_CGROUP_ID", old)
		} else {
			os.Unsetenv("AEGIS_CGROUP_ID")
		}
	})

	plan, err := resolveTargetPlan()
	if err != nil {
		t.Fatal(err)
	}
	if plan.initialID != telemetry.DisabledCgroupID || plan.hostWide || !plan.watchDocker {
		t.Fatalf("unexpected plan: %+v", plan)
	}
}

func TestExplicitZeroIsHostWide(t *testing.T) {
	t.Setenv("AEGIS_CGROUP_ID", "0")
	plan, err := resolveTargetPlan()
	if err != nil {
		t.Fatal(err)
	}
	if !plan.hostWide || plan.initialID != 0 || plan.watchDocker {
		t.Fatalf("unexpected plan: %+v", plan)
	}
}

func TestExplicitCgroupDoesNotWatchDocker(t *testing.T) {
	t.Setenv("AEGIS_CGROUP_ID", "12345")
	plan, err := resolveTargetPlan()
	if err != nil {
		t.Fatal(err)
	}
	if plan.hostWide || plan.initialID != 12345 || plan.watchDocker {
		t.Fatalf("unexpected plan: %+v", plan)
	}
}
