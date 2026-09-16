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

package v1alpha2

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	profilebasev1 "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	selinuxprofilev1 "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
)

func TestConvertLegacyPermissiveDisabledSelinuxProfile(t *testing.T) {
	t.Parallel()

	src := &SelinuxProfile{}
	require.NoError(t, json.Unmarshal([]byte(`{
	  "apiVersion": "security-profiles-operator.x-k8s.io/v1alpha2", "kind": "SelinuxProfile",
	  "metadata": {"name": "permissive"},
	  "spec": {"disabled": true, "permissive": true, "inherit": [{"name": "container"}],
	           "allow": {"var_log_t": {"file": ["read"]}}}}`), src))
	require.True(t, src.Spec.Permissive)
	require.True(t, src.Spec.Disabled)

	dst := &selinuxprofilev1.SelinuxProfile{}
	require.NoError(t, src.ConvertTo(dst))
	require.Equal(t, profilebasev1.SpecStateDisabled, dst.Spec.State)
	require.Equal(t, selinuxprofilev1.SelinuxModePermissive, dst.Spec.Mode)
	require.Len(t, dst.Spec.Inherit, 1)

	back := &SelinuxProfile{}
	require.NoError(t, back.ConvertFrom(dst))
	require.True(t, back.Spec.Permissive)
	require.True(t, back.Spec.Disabled)

	enforcing := &SelinuxProfile{}
	require.NoError(t, enforcing.ConvertFrom(&selinuxprofilev1.SelinuxProfile{
		Spec: selinuxprofilev1.SelinuxProfileSpec{Mode: selinuxprofilev1.SelinuxModeEnforcing},
	}))
	require.False(t, enforcing.Spec.Permissive)
	require.False(t, enforcing.Spec.Disabled)
}

func TestConvertLegacyDisabledRawSelinuxProfile(t *testing.T) {
	t.Parallel()

	src := &RawSelinuxProfile{}
	require.NoError(t, json.Unmarshal([]byte(`{
	  "apiVersion": "security-profiles-operator.x-k8s.io/v1alpha2", "kind": "RawSelinuxProfile",
	  "metadata": {"name": "raw"}, "spec": {"disabled": true, "policy": "(blockinherit container)"}}`), src))

	dst := &selinuxprofilev1.RawSelinuxProfile{}
	require.NoError(t, src.ConvertTo(dst))
	require.Equal(t, profilebasev1.SpecStateDisabled, dst.Spec.State)
	require.Equal(t, "(blockinherit container)", dst.Spec.Policy)

	back := &RawSelinuxProfile{}
	require.NoError(t, back.ConvertFrom(dst))
	require.True(t, back.Spec.Disabled)
}
