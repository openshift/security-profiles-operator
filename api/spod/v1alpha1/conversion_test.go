/*
Copyright 2026 The Kubernetes Authors.

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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	spodv1 "sigs.k8s.io/security-profiles-operator/api/spod/v1"
)

// legacySPOD is a SecurityProfilesOperatorDaemon as persisted by v0.10.x,
// which used v1alpha1 as the storage version.
const legacySPOD = `{
  "apiVersion": "security-profiles-operator.x-k8s.io/v1alpha1",
  "kind": "SecurityProfilesOperatorDaemon",
  "metadata": {"name": "spod", "namespace": "security-profiles-operator"},
  "spec": {
    "verbosity": 1,
    "enableProfiling": true,
    "enableMemoryOptimization": true,
    "enableSelinux": true,
    "selinuxTypeTag": "spc_t",
    "enableLogEnricher": true,
    "enableJsonEnricher": true,
    "jsonEnricherOptions": {
      "auditLogIntervalSeconds": 30, "auditLogPath": "/var/log/audit.json", "auditLogMaxSize": 10
    },
    "enableBpfRecorder": true,
    "enableAppArmor": false,
    "tolerations": [{"key": "node-role.kubernetes.io/master", "operator": "Exists", "effect": "NoSchedule"}],
    "selinuxOptions": {"allowedSystemProfiles": ["container", "net_container"]},
    "hostProcVolumePath": "/proc",
    "staticWebhookConfig": true,
    "webhookOptions": [{"name": "binding.spo.io", "failurePolicy": "Ignore"}],
    "allowedSyscalls": ["exit", "read"],
    "allowedSeccompActions": ["SCMP_ACT_ALLOW", "SCMP_ACT_LOG"],
    "priorityClassName": "system-node-critical",
    "disableOciArtifactSignatureVerification": true,
    "logEnricherFilters": "[{\"priority\":100}]",
    "logEnricherSource": "bpf",
    "jsonEnricherFilters": "[]",
    "daemonResourceRequirements": {"limits": {"memory": "512Mi"}}
  },
  "status": {"state": "RUNNING"}
}`

func TestConvertLegacyToV1(t *testing.T) {
	t.Parallel()

	src := &SecurityProfilesOperatorDaemon{}
	require.NoError(t, json.Unmarshal([]byte(legacySPOD), src))

	dst := &spodv1.SecurityProfilesOperatorDaemon{}
	require.NoError(t, src.ConvertTo(dst))

	require.Equal(t, "spod", dst.Name)
	require.Equal(t, int32(1), dst.Spec.Verbosity)
	require.Equal(t, new(true), dst.Spec.EnableProfiling)
	require.Equal(t, new(true), dst.Spec.EnableMemoryOptimization)
	require.Nil(t, dst.Spec.EnableAppArmor, "false booleans map to unset")
	require.Nil(t, dst.Spec.EnableInsecureMetricsAccess)
	require.Equal(t, "/proc", dst.Spec.HostProcVolumePath)
	require.NotNil(t, dst.Spec.DaemonResourceRequirements)

	require.Equal(t, new(true), dst.Spec.Selinux.Enable)
	require.Equal(t, "spc_t", dst.Spec.Selinux.TypeTag)
	require.Equal(t, []string{"container", "net_container"}, dst.Spec.Selinux.Options.AllowedSystemProfiles)

	require.Equal(t, new(true), dst.Spec.Enricher.EnableLogEnricher)
	require.Equal(t, new(true), dst.Spec.Enricher.EnableJsonEnricher)
	require.Equal(t, new(true), dst.Spec.Enricher.EnableBpfRecorder)
	require.Equal(t, spodv1.LogEnricherSourceBpf, dst.Spec.Enricher.LogEnricherSource)
	require.Equal(t, `[{"priority":100}]`, dst.Spec.Enricher.LogEnricherFilters)
	require.Equal(t, "[]", dst.Spec.Enricher.JsonEnricherFilters)
	require.NotNil(t, dst.Spec.Enricher.JsonEnricherOptions)
	require.Equal(t, new(int32(30)), dst.Spec.Enricher.JsonEnricherOptions.AuditLogIntervalSeconds)
	require.Equal(t, new("/var/log/audit.json"), dst.Spec.Enricher.JsonEnricherOptions.AuditLogPath)
	require.Equal(t, new(int32(10)), dst.Spec.Enricher.JsonEnricherOptions.AuditLogMaxSize)

	require.Equal(t, new(true), dst.Spec.Webhook.StaticConfig)
	require.Len(t, dst.Spec.Webhook.Options, 1)
	require.Equal(t, "binding.spo.io", dst.Spec.Webhook.Options[0].Name)

	require.Len(t, dst.Spec.Scheduling.Tolerations, 1)
	require.Equal(t, "system-node-critical", dst.Spec.Scheduling.PriorityClassName)

	require.Equal(t, []string{"exit", "read"}, dst.Spec.Security.AllowedSyscalls)
	require.Len(t, dst.Spec.Security.AllowedSeccompActions, 2)
	require.Equal(t, new(true), dst.Spec.Security.DisableOCIArtifactSignatureVerification)

	require.Equal(t, spodv1.SPODStateRunning, dst.Status.State)
}

func TestConvertRoundTrip(t *testing.T) {
	t.Parallel()

	src := &SecurityProfilesOperatorDaemon{}
	require.NoError(t, json.Unmarshal([]byte(legacySPOD), src))

	hub := &spodv1.SecurityProfilesOperatorDaemon{}
	require.NoError(t, src.ConvertTo(hub))

	back := &SecurityProfilesOperatorDaemon{}
	require.NoError(t, back.ConvertFrom(hub))

	require.Equal(t, src.Spec, back.Spec)
	require.Equal(t, src.Status.State, back.Status.State)
}

func TestConvertEmptyObjects(t *testing.T) {
	t.Parallel()

	hub := &spodv1.SecurityProfilesOperatorDaemon{}
	require.NoError(t, (&SecurityProfilesOperatorDaemon{}).ConvertTo(hub))
	require.Equal(t, spodv1.SPODSpec{}, hub.Spec)
	require.Equal(t, spodv1.SPODStatePending, hub.Status.State)

	legacy := &SecurityProfilesOperatorDaemon{}
	require.NoError(t, legacy.ConvertFrom(&spodv1.SecurityProfilesOperatorDaemon{}))
	require.Equal(t, SPODSpec{}, legacy.Spec)
	require.Equal(t, SPODStatePending, legacy.Status.State)
}

func TestConvertFromV1DropsV1OnlyFields(t *testing.T) {
	t.Parallel()

	hub := &spodv1.SecurityProfilesOperatorDaemon{
		Spec: spodv1.SPODSpec{
			EnableInsecureMetricsAccess: new(true),
			Selinux: spodv1.SPODSelinuxConfig{
				Enable:                   new(true),
				EnableRawSelinuxProfiles: new(true),
				CustomTemplatesConfigMap: "templates",
			},
			Enricher: spodv1.SPODEnricherConfig{
				EnableLogEnricher: new(true),
				LogEnricherSource: spodv1.LogEnricherSourceAuditd,
			},
		},
		Status: spodv1.SPODStatus{State: spodv1.SPODStateError},
	}

	legacy := &SecurityProfilesOperatorDaemon{}
	require.NoError(t, legacy.ConvertFrom(hub))

	require.Equal(t, new(true), legacy.Spec.EnableSelinux)
	require.True(t, legacy.Spec.EnableLogEnricher)
	require.Equal(t, "auditd", legacy.Spec.LogEnricherSource)
	require.Equal(t, SPODStateError, legacy.Status.State)
}

func TestConvertWrongHubType(t *testing.T) {
	t.Parallel()

	require.Error(t, (&SecurityProfilesOperatorDaemon{}).ConvertTo(nil))
	require.Error(t, (&SecurityProfilesOperatorDaemon{}).ConvertFrom(nil))
}
