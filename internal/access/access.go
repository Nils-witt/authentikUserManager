// Package access decides which authentik users an operator may manage, based
// on the operator's groups and the groups of the target user.
package access

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"authentikManager/internal/authentik"
)

// Wildcard as a target group grants access to every user, including superusers.
const Wildcard = "*"

// HiddenAttribute is the authentik user attribute that, when true, hides the
// user from every operator but the access administrators, even from operators
// whose rules grant one of the user's groups or all users.
const HiddenAttribute = "authentik_manager_hidden"

// IsHidden reports whether u is hidden from operators who are not access administrators.
func IsHidden(u *authentik.User) bool {
	hidden, ok := u.Attributes[HiddenAttribute].(bool)
	return ok && hidden
}

// maxGroupNameLen bounds group names; authentik's own limit is lower.
const maxGroupNameLen = 255

// ErrRuleNotFound is returned when no rule exists for an operator group.
var ErrRuleNotFound = errors.New("access rule not found")

// Rule lets members of OperatorGroup manage members of TargetGroups.
type Rule struct {
	OperatorGroup string   `json:"operator_group"`
	TargetGroups  []string `json:"target_groups"`
}

// Normalize trims the group names, sorts the target groups and removes
// duplicates, then validates the rule. The returned errors are safe to show users.
func (r Rule) Normalize() (Rule, error) {
	out := Rule{OperatorGroup: strings.TrimSpace(r.OperatorGroup), TargetGroups: []string{}}
	var errs []error
	if out.OperatorGroup == "" {
		errs = append(errs, errors.New("operator group is required"))
	}
	if len(out.OperatorGroup) > maxGroupNameLen {
		errs = append(errs, fmt.Errorf("operator group must be at most %d characters", maxGroupNameLen))
	}
	for _, t := range r.TargetGroups {
		t = strings.TrimSpace(t)
		switch {
		case t == "":
			errs = append(errs, errors.New("target group names must not be empty"))
		case len(t) > maxGroupNameLen:
			errs = append(errs, fmt.Errorf("target group names must be at most %d characters", maxGroupNameLen))
		default:
			out.TargetGroups = append(out.TargetGroups, t)
		}
	}
	if len(r.TargetGroups) == 0 {
		errs = append(errs, errors.New("at least one target group is required"))
	}
	slices.Sort(out.TargetGroups)
	out.TargetGroups = slices.Compact(out.TargetGroups)
	if err := errors.Join(errs...); err != nil {
		return Rule{}, err
	}
	return out, nil
}

// Store returns the target groups granted to operator groups.
type Store interface {
	// TargetGroups returns the target groups of all rules for operatorGroups.
	TargetGroups(ctx context.Context, operatorGroups []string) ([]string, error)
}

// Policy resolves the scope of operators. Members of the admin groups always
// have full access, including to hidden users, and may edit the rules; everyone
// else is limited by the rules in the store, has no access without a matching
// rule and never has access to hidden users.
type Policy struct {
	adminGroups []string
	store       Store
}

// NewPolicy returns a Policy. adminGroups must not be empty, so that someone
// can always edit the rules.
func NewPolicy(adminGroups []string, store Store) (*Policy, error) {
	if len(adminGroups) == 0 {
		return nil, errors.New("access: at least one admin group is required")
	}
	return &Policy{adminGroups: slices.Clone(adminGroups), store: store}, nil
}

// IsAdmin reports whether a member of operatorGroups may edit the rules.
func (p *Policy) IsAdmin(operatorGroups []string) bool {
	return slices.ContainsFunc(operatorGroups, func(g string) bool {
		return slices.Contains(p.adminGroups, g)
	})
}

// ScopeFor returns the scope of an operator who is a member of operatorGroups.
func (p *Policy) ScopeFor(ctx context.Context, operatorGroups []string) (Scope, error) {
	if p.IsAdmin(operatorGroups) {
		return Scope{All: true, IncludesHidden: true, Groups: []string{}}, nil
	}
	if len(operatorGroups) == 0 {
		return Scope{Groups: []string{}}, nil
	}
	targets, err := p.store.TargetGroups(ctx, operatorGroups)
	if err != nil {
		return Scope{}, fmt.Errorf("loading access rules: %w", err)
	}
	if slices.Contains(targets, Wildcard) {
		return Scope{All: true, Groups: []string{}}, nil
	}
	groups := slices.Clone(targets)
	slices.Sort(groups)
	return Scope{Groups: slices.Compact(groups)}, nil
}

// Scope is the set of users one operator may manage.
type Scope struct {
	// All grants access to every user, including superusers.
	All bool `json:"all"`
	// Groups lists the target groups when All is false, sorted and without duplicates.
	Groups []string `json:"groups"`
	// IncludesHidden grants access to hidden users (see IsHidden) too, within
	// All or Groups. Only access administrators have it.
	IncludesHidden bool `json:"includes_hidden"`
}

// Empty reports whether the scope grants access to no user at all.
func (s Scope) Empty() bool {
	return !s.All && len(s.Groups) == 0
}

// HasGroup reports whether members of group are within the scope.
func (s Scope) HasGroup(group string) bool {
	return s.All || slices.Contains(s.Groups, group)
}

// Allows reports whether the operator may see and manage u. Superusers are
// only manageable with full access, so a restricted operator cannot take over
// an administrator account. Hidden users are only manageable with
// IncludesHidden, whatever their groups.
func (s Scope) Allows(u *authentik.User) bool {
	if IsHidden(u) && !s.IncludesHidden {
		return false
	}
	if s.All {
		return true
	}
	if u.IsSuperuser {
		return false
	}
	return slices.ContainsFunc(u.Groups, func(g authentik.UserGroup) bool {
		return slices.Contains(s.Groups, g.Name)
	})
}
