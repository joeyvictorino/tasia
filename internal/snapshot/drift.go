package snapshot

type DriftResult struct {
	BaseChecksum    string            `json:"base_checksum"`
	CurrentChecksum string            `json:"current_checksum"`
	NewFindings     []SnapshotFinding `json:"new_findings"`
	Resolved        []SnapshotFinding `json:"resolved_findings"`
	Unchanged       int               `json:"unchanged"`
	DriftScore      float64           `json:"drift_score"`
}

func ComputeDrift(base, current Snapshot) DriftResult {
	baseSet := map[string]SnapshotFinding{}
	for _, f := range base.Findings {
		baseSet[f.Hash] = f
	}
	currentSet := map[string]SnapshotFinding{}
	for _, f := range current.Findings {
		currentSet[f.Hash] = f
	}

	var newFindings []SnapshotFinding
	for hash, f := range currentSet {
		if _, ok := baseSet[hash]; !ok {
			newFindings = append(newFindings, f)
		}
	}

	var resolved []SnapshotFinding
	for hash, f := range baseSet {
		if _, ok := currentSet[hash]; !ok {
			resolved = append(resolved, f)
		}
	}

	unchanged := 0
	for hash := range currentSet {
		if _, ok := baseSet[hash]; ok {
			unchanged++
		}
	}

	total := len(base.Findings) + len(current.Findings)
	var driftScore float64
	if total > 0 {
		changed := len(newFindings) + len(resolved)
		driftScore = float64(changed) / float64(total)
		if driftScore > 1.0 {
			driftScore = 1.0
		}
	}

	return DriftResult{
		BaseChecksum:    base.Checksum,
		CurrentChecksum: current.Checksum,
		NewFindings:     newFindings,
		Resolved:        resolved,
		Unchanged:       unchanged,
		DriftScore:      driftScore,
	}
}
