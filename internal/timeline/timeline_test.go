package timeline_test

import (
	"testing"
	"time"

	"github.com/klaudtrace/klaudtrace/internal/model"
	"github.com/klaudtrace/klaudtrace/internal/timeline"
)

func TestSortEvents_Deterministic(t *testing.T) {
	t1 := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 9, 15, 12, 5, 0, 0, time.UTC)

	events := []*model.NormalizedEvent{
		{ID: "e3", Timestamp: t2, SourceRef: model.EvidenceRef{RecordIndex: 2}},
		{ID: "e1", Timestamp: t1, SourceRef: model.EvidenceRef{RecordIndex: 0}},
		{ID: "e2", Timestamp: t1, SourceRef: model.EvidenceRef{RecordIndex: 1}},
	}

	sorted := timeline.SortEvents(events)

	if sorted[0].ID != "e1" || sorted[1].ID != "e2" || sorted[2].ID != "e3" {
		t.Fatalf("incorrect sort order: got %s, %s, %s", sorted[0].ID, sorted[1].ID, sorted[2].ID)
	}

	start, end := timeline.TimeWindow(sorted)
	if !start.Equal(t1) || !end.Equal(t2) {
		t.Errorf("unexpected time window: %v to %v", start, end)
	}
}
