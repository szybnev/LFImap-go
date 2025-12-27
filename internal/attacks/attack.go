package attacks

import (
	"github.com/hansmach1ne/lfimap/internal/config"
	lfihttp "github.com/hansmach1ne/lfimap/internal/http"
	"github.com/hansmach1ne/lfimap/internal/util"
)

// AttackContext holds context for attack execution
type AttackContext struct {
	Config     *config.Config
	HTTPCtx    *lfihttp.RequestContext
	Colors     *util.Colors
	Stats      *util.Stats
	Encodings  []string
	Verbose    bool
	Quick      bool
	NoStop     bool
}

// Attack is the interface for all attack types
type Attack interface {
	Name() string
	Test(ctx *AttackContext, url, postData string) bool
}

// AttackRegistry holds all registered attacks
type AttackRegistry struct {
	attacks map[string]Attack
}

// NewAttackRegistry creates a new attack registry
func NewAttackRegistry() *AttackRegistry {
	return &AttackRegistry{
		attacks: make(map[string]Attack),
	}
}

// Register registers an attack
func (r *AttackRegistry) Register(attack Attack) {
	r.attacks[attack.Name()] = attack
}

// Get returns an attack by name
func (r *AttackRegistry) Get(name string) (Attack, bool) {
	attack, ok := r.attacks[name]
	return attack, ok
}

// All returns all registered attacks
func (r *AttackRegistry) All() map[string]Attack {
	return r.attacks
}

// DefaultRegistry creates and populates the default attack registry
func DefaultRegistry() *AttackRegistry {
	reg := NewAttackRegistry()

	reg.Register(&FilterAttack{})
	reg.Register(&InputAttack{})
	reg.Register(&DataAttack{})
	reg.Register(&ExpectAttack{})
	reg.Register(&FileAttack{})
	reg.Register(&TruncAttack{})
	reg.Register(&RFIAttack{})
	reg.Register(&CMDIAttack{})
	reg.Register(&HeuristicsAttack{})

	return reg
}
