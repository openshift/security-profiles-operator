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

	apparmorprofilev1 "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	profilebasev1 "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
)

func TestConvertLegacyComplainDisabledAppArmorProfile(t *testing.T) {
	t.Parallel()

	src := &AppArmorProfile{}
	require.NoError(t, json.Unmarshal([]byte(`{
	  "apiVersion": "security-profiles-operator.x-k8s.io/v1alpha1", "kind": "AppArmorProfile",
	  "metadata": {"name": "complain"},
	  "spec": {"disabled": true, "complainMode": true,
	           "abstract": {"executable": {"allowedExecutables": ["/bin/true"]}}}}`), src))
	require.True(t, src.Spec.ComplainMode)
	require.True(t, src.Spec.Disabled)

	dst := &apparmorprofilev1.AppArmorProfile{}
	require.NoError(t, src.ConvertTo(dst))
	require.Equal(t, profilebasev1.SpecStateDisabled, dst.Spec.State)
	require.Equal(t, apparmorprofilev1.AppArmorModeComplain, dst.Spec.Mode)
	require.Equal(t, []string{"/bin/true"}, dst.Spec.Abstract.Executable.AllowedExecutables)

	back := &AppArmorProfile{}
	require.NoError(t, back.ConvertFrom(dst))
	require.True(t, back.Spec.ComplainMode)
	require.True(t, back.Spec.Disabled)

	enforce := &AppArmorProfile{}
	require.NoError(t, enforce.ConvertFrom(&apparmorprofilev1.AppArmorProfile{
		Spec: apparmorprofilev1.AppArmorProfileSpec{Mode: apparmorprofilev1.AppArmorModeEnforce},
	}))
	require.False(t, enforce.Spec.ComplainMode)
}
