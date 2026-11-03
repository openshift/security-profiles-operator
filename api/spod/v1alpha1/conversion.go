/*
Copyright 2025 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"fmt"
	"math"
	"strings"

	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/conversion"

	spodv1 "sigs.k8s.io/security-profiles-operator/api/spod/v1"
)

// The v1alpha1 API uses the flat SPODSpec layout and upper case states of the
// v0.10.x releases, while v1 groups the spec into sub structs, uses three
// state booleans and title case states. Fields which only exist in v1
// (enableInsecureMetricsAccess, selinux.enableRawSelinuxProfiles,
// selinux.customTemplatesConfigMap, the SELinux allow/deny lists and the
// security regexps) have no v1alpha1 representation and are dropped when
// converting from v1.

var (
	stateToV1 = map[SPODState]spodv1.SPODState{
		"":                spodv1.SPODStatePending,
		SPODStatePending:  spodv1.SPODStatePending,
		SPODStateCreating: spodv1.SPODStateCreating,
		SPODStateUpdating: spodv1.SPODStateUpdating,
		SPODStateRunning:  spodv1.SPODStateRunning,
		SPODStateError:    spodv1.SPODStateError,
	}

	stateFromV1 = map[spodv1.SPODState]SPODState{
		"":                       SPODStatePending,
		spodv1.SPODStatePending:  SPODStatePending,
		spodv1.SPODStateCreating: SPODStateCreating,
		spodv1.SPODStateUpdating: SPODStateUpdating,
		spodv1.SPODStateRunning:  SPODStateRunning,
		spodv1.SPODStateError:    SPODStateError,
	}
)

// enricherSourceToV1 converts the free form v1alpha1 log enricher source into
// the v1 enum. Unknown values are passed through so that validation of the v1
// API can reject them.
func enricherSourceToV1(source string) spodv1.LogEnricherSource {
	switch strings.ToLower(source) {
	case "":
		return ""
	case "auditd":
		return spodv1.LogEnricherSourceAuditd
	case "bpf":
		return spodv1.LogEnricherSourceBpf
	default:
		return spodv1.LogEnricherSource(source)
	}
}

func enricherSourceFromV1(source spodv1.LogEnricherSource) string {
	switch source {
	case "":
		return ""
	case spodv1.LogEnricherSourceAuditd:
		return "auditd"
	case spodv1.LogEnricherSourceBpf:
		return "bpf"
	default:
		return string(source)
	}
}

// boolPtr converts a v1alpha1 boolean into the three state v1 boolean. A
// false value cannot be distinguished from an unset one in v1alpha1, so it
// maps to nil which keeps the v1 defaults.
func boolPtr(b bool) *bool {
	if !b {
		return nil
	}

	return new(true)
}

// ConvertTo converts this SecurityProfilesOperatorDaemon to the Hub version (v1).
func (src *SecurityProfilesOperatorDaemon) ConvertTo(dstRaw conversion.Hub) error {
	dst, ok := dstRaw.(*spodv1.SecurityProfilesOperatorDaemon)
	if !ok {
		return fmt.Errorf("expected *spodv1.SecurityProfilesOperatorDaemon, got %T", dstRaw)
	}

	dst.ObjectMeta = src.ObjectMeta

	if src.Spec.Verbosity > math.MaxInt32 {
		return fmt.Errorf("verbosity %d exceeds the maximum of %d", src.Spec.Verbosity, math.MaxInt32)
	}

	dst.Spec.Verbosity = int32(src.Spec.Verbosity)
	dst.Spec.EnableProfiling = boolPtr(src.Spec.EnableProfiling)
	dst.Spec.EnableMemoryOptimization = boolPtr(src.Spec.EnableMemoryOptimization)
	dst.Spec.EnableAppArmor = boolPtr(src.Spec.EnableAppArmor)
	dst.Spec.HostProcVolumePath = src.Spec.HostProcVolumePath
	dst.Spec.ImagePullSecrets = src.Spec.ImagePullSecrets
	dst.Spec.DaemonResourceRequirements = src.Spec.DaemonResourceRequirements

	// Selinux
	dst.Spec.Selinux.Enable = src.Spec.EnableSelinux
	dst.Spec.Selinux.TypeTag = src.Spec.SelinuxTypeTag
	dst.Spec.Selinux.Options.AllowedSystemProfiles = src.Spec.SelinuxOpts.AllowedSystemProfiles

	// Enricher
	dst.Spec.Enricher.EnableLogEnricher = boolPtr(src.Spec.EnableLogEnricher)
	dst.Spec.Enricher.LogEnricherFilters = src.Spec.LogEnricherFilters
	dst.Spec.Enricher.LogEnricherSource = enricherSourceToV1(src.Spec.LogEnricherSource)
	dst.Spec.Enricher.EnableJsonEnricher = boolPtr(src.Spec.EnableJsonEnricher)
	dst.Spec.Enricher.JsonEnricherFilters = src.Spec.JsonEnricherFilters
	dst.Spec.Enricher.EnableBpfRecorder = boolPtr(src.Spec.EnableBpfRecorder)

	if opts := src.Spec.JsonEnricherOpt; opts != nil {
		dst.Spec.Enricher.JsonEnricherOptions = &spodv1.JsonEnricherOptions{
			AuditLogPath:       opts.AuditLogPath,
			AuditLogMaxSize:    opts.AuditLogMaxSize,
			AuditLogMaxBackups: opts.AuditLogMaxBackups,
			AuditLogMaxAge:     opts.AuditLogMaxAge,
		}

		if opts.AuditLogIntervalSeconds != 0 {
			dst.Spec.Enricher.JsonEnricherOptions.AuditLogIntervalSeconds = new(opts.AuditLogIntervalSeconds)
		}
	}

	// Webhook
	dst.Spec.Webhook.StaticConfig = boolPtr(src.Spec.StaticWebhookConfig)

	if len(src.Spec.WebhookOpts) > 0 {
		dst.Spec.Webhook.Options = make([]spodv1.WebhookOptions, len(src.Spec.WebhookOpts))
		for i, o := range src.Spec.WebhookOpts {
			dst.Spec.Webhook.Options[i] = spodv1.WebhookOptions{
				Name:              o.Name,
				FailurePolicy:     o.FailurePolicy,
				NamespaceSelector: o.NamespaceSelector,
				ObjectSelector:    o.ObjectSelector,
			}
		}
	}

	// Scheduling
	dst.Spec.Scheduling.Tolerations = src.Spec.Tolerations
	dst.Spec.Scheduling.Affinity = src.Spec.Affinity
	dst.Spec.Scheduling.PriorityClassName = src.Spec.PriorityClassName

	// Security
	dst.Spec.Security.AllowedSyscalls = src.Spec.AllowedSyscalls
	dst.Spec.Security.AllowedSeccompActions = src.Spec.AllowedSeccompActions
	dst.Spec.Security.DisableOCIArtifactSignatureVerification = boolPtr(src.Spec.DisableOCIArtifactSignatureVerification)

	// Status
	dst.Status.ConditionedStatus = src.Status.ConditionedStatus

	if state, ok := stateToV1[src.Status.State]; ok {
		dst.Status.State = state
	} else {
		dst.Status.State = spodv1.SPODState(src.Status.State)
	}

	return nil
}

// ConvertFrom converts from the Hub version (v1) to this version.
func (dst *SecurityProfilesOperatorDaemon) ConvertFrom(srcRaw conversion.Hub) error {
	src, ok := srcRaw.(*spodv1.SecurityProfilesOperatorDaemon)
	if !ok {
		return fmt.Errorf("expected *spodv1.SecurityProfilesOperatorDaemon, got %T", srcRaw)
	}

	dst.ObjectMeta = src.ObjectMeta

	if src.Spec.Verbosity > 0 {
		dst.Spec.Verbosity = uint(src.Spec.Verbosity)
	}

	dst.Spec.EnableProfiling = ptr.Deref(src.Spec.EnableProfiling, false)
	dst.Spec.EnableMemoryOptimization = ptr.Deref(src.Spec.EnableMemoryOptimization, false)
	dst.Spec.EnableAppArmor = ptr.Deref(src.Spec.EnableAppArmor, false)
	dst.Spec.HostProcVolumePath = src.Spec.HostProcVolumePath
	dst.Spec.ImagePullSecrets = src.Spec.ImagePullSecrets
	dst.Spec.DaemonResourceRequirements = src.Spec.DaemonResourceRequirements

	// Selinux
	dst.Spec.EnableSelinux = src.Spec.Selinux.Enable
	dst.Spec.SelinuxTypeTag = src.Spec.Selinux.TypeTag
	dst.Spec.SelinuxOpts.AllowedSystemProfiles = src.Spec.Selinux.Options.AllowedSystemProfiles

	// Enricher
	dst.Spec.EnableLogEnricher = ptr.Deref(src.Spec.Enricher.EnableLogEnricher, false)
	dst.Spec.LogEnricherFilters = src.Spec.Enricher.LogEnricherFilters
	dst.Spec.LogEnricherSource = enricherSourceFromV1(src.Spec.Enricher.LogEnricherSource)
	dst.Spec.EnableJsonEnricher = ptr.Deref(src.Spec.Enricher.EnableJsonEnricher, false)
	dst.Spec.JsonEnricherFilters = src.Spec.Enricher.JsonEnricherFilters
	dst.Spec.EnableBpfRecorder = ptr.Deref(src.Spec.Enricher.EnableBpfRecorder, false)

	if opts := src.Spec.Enricher.JsonEnricherOptions; opts != nil {
		dst.Spec.JsonEnricherOpt = &JsonEnricherOptions{
			AuditLogIntervalSeconds: ptr.Deref(opts.AuditLogIntervalSeconds, 0),
			AuditLogPath:            opts.AuditLogPath,
			AuditLogMaxSize:         opts.AuditLogMaxSize,
			AuditLogMaxBackups:      opts.AuditLogMaxBackups,
			AuditLogMaxAge:          opts.AuditLogMaxAge,
		}
	}

	// Webhook
	dst.Spec.StaticWebhookConfig = ptr.Deref(src.Spec.Webhook.StaticConfig, false)

	if len(src.Spec.Webhook.Options) > 0 {
		dst.Spec.WebhookOpts = make([]WebhookOptions, len(src.Spec.Webhook.Options))
		for i, o := range src.Spec.Webhook.Options {
			dst.Spec.WebhookOpts[i] = WebhookOptions{
				Name:              o.Name,
				FailurePolicy:     o.FailurePolicy,
				NamespaceSelector: o.NamespaceSelector,
				ObjectSelector:    o.ObjectSelector,
			}
		}
	}

	// Scheduling
	dst.Spec.Tolerations = src.Spec.Scheduling.Tolerations
	dst.Spec.Affinity = src.Spec.Scheduling.Affinity
	dst.Spec.PriorityClassName = src.Spec.Scheduling.PriorityClassName

	// Security
	dst.Spec.AllowedSyscalls = src.Spec.Security.AllowedSyscalls
	dst.Spec.AllowedSeccompActions = src.Spec.Security.AllowedSeccompActions
	dst.Spec.DisableOCIArtifactSignatureVerification = ptr.Deref(
		src.Spec.Security.DisableOCIArtifactSignatureVerification, false,
	)

	// Status
	dst.Status.ConditionedStatus = src.Status.ConditionedStatus

	if state, ok := stateFromV1[src.Status.State]; ok {
		dst.Status.State = state
	} else {
		dst.Status.State = SPODState(src.Status.State)
	}

	return nil
}
