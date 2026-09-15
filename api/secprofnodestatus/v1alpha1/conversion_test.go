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

	secprofnodestatusv1 "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
)

// legacyNodeStatus is a SecurityProfileNodeStatus as persisted by v0.10.x.
const legacyNodeStatus = `{
  "apiVersion": "security-profiles-operator.x-k8s.io/v1alpha1",
  "kind": "SecurityProfileNodeStatus",
  "metadata": {
    "name": "profile-node1",
    "labels": {"spo.x-k8s.io/node-name": "node1", "spo.x-k8s.io/profile-id": "SeccompProfile-profile"}
  },
  "nodeName": "node1",
  "status": "Installed"
}`

func TestConvertLegacyNodeStatusToV1(t *testing.T) {
	t.Parallel()

	src := &SecurityProfileNodeStatus{}
	require.NoError(t, json.Unmarshal([]byte(legacyNodeStatus), src))
	require.Equal(t, "node1", src.NodeName)
	require.Equal(t, ProfileStateInstalled, src.Status)

	dst := &secprofnodestatusv1.SecurityProfileNodeStatus{}
	require.NoError(t, src.ConvertTo(dst))

	require.Equal(t, "profile-node1", dst.Name)
	require.Equal(t, "node1", dst.Labels["spo.x-k8s.io/node-name"])
	require.Equal(t, "node1", dst.Spec.NodeName)
	require.Equal(t, secprofnodestatusv1.ProfileStateInstalled, dst.Status.Status)
}

func TestConvertNodeStatusRoundTrip(t *testing.T) {
	t.Parallel()

	src := &SecurityProfileNodeStatus{}
	require.NoError(t, json.Unmarshal([]byte(legacyNodeStatus), src))

	hub := &secprofnodestatusv1.SecurityProfileNodeStatus{}
	require.NoError(t, src.ConvertTo(hub))

	back := &SecurityProfileNodeStatus{}
	require.NoError(t, back.ConvertFrom(hub))

	require.Equal(t, src.NodeName, back.NodeName)
	require.Equal(t, src.Status, back.Status)
	require.Equal(t, src.ObjectMeta, back.ObjectMeta)
}

func TestConvertNodeStatusWrongHubType(t *testing.T) {
	t.Parallel()

	require.Error(t, (&SecurityProfileNodeStatus{}).ConvertTo(nil))
	require.Error(t, (&SecurityProfileNodeStatus{}).ConvertFrom(nil))
}
