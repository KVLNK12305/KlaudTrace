package timeline

import (
	"sort"
	"time"

	"github.com/klaudtrace/klaudtrace/internal/model"
)

// SortEvents sorts events deterministically in chronological order.
// Primary key: Timestamp
// Secondary key: RecordIndex
// Tertiary key: ID
func SortEvents(events []*model.NormalizedEvent) []*model.NormalizedEvent {
	sorted := make([]*model.NormalizedEvent, len(events))
	copy(sorted, events)

	sort.SliceStable(sorted, func(i, j int) bool {
		ei, ej := sorted[i], sorted[j]
		if !ei.Timestamp.Equal(ej.Timestamp) {
			return ei.Timestamp.Before(ej.Timestamp)
		}
		if ei.SourceRef.RecordIndex != ej.SourceRef.RecordIndex {
			return ei.SourceRef.RecordIndex < ej.SourceRef.RecordIndex
		}
		return ei.ID < ej.ID
	})

	return sorted
}

// TimeWindow returns the start and end timestamp of a sorted event slice.
func TimeWindow(events []*model.NormalizedEvent) (time.Time, time.Time) {
	if len(events) == 0 {
		return time.Time{}, time.Time{}
	}
	return events[0].Timestamp, events[len(events)-1].Timestamp
}

// Filter filters events using a custom predicate.
func Filter(events []*model.NormalizedEvent, fn func(*model.NormalizedEvent) bool) []*model.NormalizedEvent {
	var result []*model.NormalizedEvent
	for _, e := range events {
		if fn(e) {
			result = append(result, e)
		}
	}
	return result
}
