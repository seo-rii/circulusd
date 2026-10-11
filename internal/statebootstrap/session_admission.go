package statebootstrap

import (
	"context"

	"github.com/hancomac/circulusd/internal/dependency"
	"github.com/hancomac/circulusd/internal/sessionadmission"
	"github.com/hancomac/circulusd/internal/stateappadmission"
	"github.com/hancomac/circulusd/internal/stateappclient"
)

// SessionAdmission independently challenges the actual planning transport,
// planner, mutation transport and complete admitter before sealing their joint
// Session/event domain. Executable genesis has a separate qualified engine
// binding; no source is replaced by a local checkpoint constructor.
func (graph *graph) SessionAdmission(ctx context.Context, config stateappadmission.PlannerConfig) (dependency.Verified[sessionadmission.SessionTurnStore], error) {
	var empty dependency.Verified[sessionadmission.SessionTurnStore]
	if graph == nil || ctx == nil || graph.verifier == nil || graph.client == nil {
		return empty, ErrInvalidConfiguration
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if _, err := dependency.RequireAtomicDomain([]dependency.AtomicGroup{dependency.AtomicEngineGenesis}, config.Genesis); err != nil {
		return empty, err
	}
	if !graph.client.AdmissionConfigured() {
		return empty, stateappclient.ErrInvalidConfig
	}
	evidence := graph.evidence
	evidence.Descriptor.AtomicGroups = append([]dependency.AtomicGroup(nil), graph.evidence.Descriptor.AtomicGroups...)
	evidence.Signature = append([]byte(nil), graph.evidence.Signature...)
	requirements := graph.requirements
	requirements.RequiredAtomicGroups = append([]dependency.AtomicGroup(nil), graph.requirements.RequiredAtomicGroups...)
	query, err := dependency.VerifyDependency[stateappadmission.PlanningClient](ctx, graph.verifier, graph.client, evidence, requirements)
	if err != nil {
		return empty, err
	}
	planner, err := stateappadmission.NewPlanner(query, config)
	if err != nil {
		return empty, err
	}
	planning, err := dependency.VerifyDependency[stateappadmission.AdmissionPlanner](ctx, graph.verifier, planner, evidence, requirements)
	if err != nil {
		return empty, err
	}
	client, err := dependency.VerifyDependency[stateappadmission.AdmissionClient](ctx, graph.verifier, graph.client, evidence, requirements)
	if err != nil {
		return empty, err
	}
	admitter, err := stateappadmission.NewTurnAdmitter(client, planning)
	if err != nil {
		return empty, err
	}
	store, err := dependency.VerifyDependency[sessionadmission.SessionTurnStore](ctx, graph.verifier, admitter, evidence, requirements)
	if err != nil {
		return empty, err
	}
	if _, err := dependency.RequireAtomicDomain([]dependency.AtomicGroup{dependency.AtomicCommandReceipt, dependency.AtomicEffectLifecycle, dependency.AtomicPublicEvent},
		query, planning, client, store, graph.sessionEventReader); err != nil {
		return empty, err
	}
	return store, nil
}
