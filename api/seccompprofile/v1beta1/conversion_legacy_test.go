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

package v1beta1

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	profilebasev1 "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	seccompprofilev1 "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
)

func TestConvertLegacyDisabledSeccompProfile(t *testing.T) {
	t.Parallel()

	src := &SeccompProfile{}
	require.NoError(t, json.Unmarshal([]byte(`{
	  "apiVersion": "security-profiles-operator.x-k8s.io/v1beta1", "kind": "SeccompProfile",
	  "metadata": {"name": "disabled"},
	  "spec": {"disabled": true, "defaultAction": "SCMP_ACT_LOG"}}`), src))
	require.True(t, src.Spec.Disabled)
	require.True(t, src.IsDisabled())

	dst := &seccompprofilev1.SeccompProfile{}
	require.NoError(t, src.ConvertTo(dst))
	require.Equal(t, profilebasev1.SpecStateDisabled, dst.Spec.State)
	require.True(t, dst.IsDisabled())

	back := &SeccompProfile{}
	require.NoError(t, back.ConvertFrom(dst))
	require.True(t, back.Spec.Disabled)

	enabled := &SeccompProfile{}
	require.NoError(t, enabled.ConvertFrom(&seccompprofilev1.SeccompProfile{}))
	require.False(t, enabled.Spec.Disabled)
}
