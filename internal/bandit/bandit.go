package bandit

import (
	"fmt"
	"math/rand"
	"sync"
)

type Action string

const (
	ActionAutoAllow       Action = "auto_allow"
	ActionAutoDeny        Action = "auto_deny"
	ActionEscalateCheap   Action = "escalate_cheap"
	ActionEscalateFlagship Action = "escalate_flagship"
)

type EpisodicOutcome struct {
	IsMalicious   bool
	Decision      Action
	HumanRevoked  bool
}

type LinUCB struct {
	mu     sync.Mutex
	theta  map[Action]float64
	alpha  float64
}

func NewLinUCB(alpha float64) *LinUCB {
	return &LinUCB{
		theta: map[Action]float64{
			ActionAutoAllow:       0.0,
			ActionAutoDeny:        0.0,
			ActionEscalateCheap:   0.0,
			ActionEscalateFlagship: 0.0,
		},
		alpha: alpha,
	}
}

// Calculate Reward per RLE Reward Table
func (b *LinUCB) CalculateReward(outcome EpisodicOutcome) float64 {
	if outcome.HumanRevoked {
		return -2.0
	}

	switch outcome.Decision {
	case ActionAutoDeny:
		if outcome.IsMalicious {
			return 1.0 // Correctly auto-denied malicious
		}
		return -1.0 // False positive (auto-denied benign)
	case ActionAutoAllow:
		if !outcome.IsMalicious {
			return 0.5 // Correctly auto-allowed benign
		}
		return -5.0 // False negative (auto-allowed malicious)
	case ActionEscalateCheap, ActionEscalateFlagship:
		// Simulated outcome logic for escalations:
		if rand.Float32() > 0.1 {
			return 0.3 // Correct LLM-escalated decision
		}
		return -0.1 // Unnecessary LLM escalation
	}
	return 0.0
}

func (b *LinUCB) Train(episodes []EpisodicOutcome) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for _, ep := range episodes {
		r := b.CalculateReward(ep)
		// Simplified linear update for 1D feature context (bias only)
		b.theta[ep.Decision] = b.theta[ep.Decision] + b.alpha*(r-b.theta[ep.Decision])
	}
}

func (b *LinUCB) Propose() (float64, float64, string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Analyze weights to propose threshold adjustments
	// Simulated logic based on trained weights
	expectedImprovement := b.theta[ActionAutoDeny] - b.theta[ActionAutoAllow]
	
	proposedThreshold := 0.95
	proposedK := 5.0
	
	if expectedImprovement > 0 {
		proposedThreshold = 0.90 // Relax threshold if auto-deny is performing well
	}

	rationale := fmt.Sprintf("Expected reward delta: +%.2f. Recommend lowering AUTO_DECIDE_THRESHOLD to %.2f.", expectedImprovement, proposedThreshold)
	return proposedThreshold, proposedK, rationale
}
