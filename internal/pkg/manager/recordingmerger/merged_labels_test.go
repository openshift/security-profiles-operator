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

package recordingmerger

import (
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	profilebase "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
)

func TestSetMergedLabelsDropsPartial(t *testing.T) {
	t.Parallel()

	recording := &profilerecordingapi.ProfileRecording{
		ObjectMeta: metav1.ObjectMeta{Name: "rec", Namespace: "ns"},
	}

	// A partial profile recorded by a previous version reusing the merged name.
	meta := &metav1.ObjectMeta{
		Name: "rec-nginx",
		Labels: map[string]string{
			profilebase.ProfilePartialLabel:             "true",
			profilerecordingapi.ProfileToRecordingLabel: "rec",
			"custom": "kept",
		},
	}

	setMergedLabels(meta, recording)

	require.NotContains(t, meta.Labels, profilebase.ProfilePartialLabel)
	require.Equal(t, "rec", meta.Labels[profilerecordingapi.ProfileToRecordingLabel])
	require.Equal(t, "ns", meta.Labels[profilerecordingapi.ProfileToRecordingNamespaceLabel])
	require.Equal(t, "kept", meta.Labels["custom"])

	empty := &metav1.ObjectMeta{}
	setMergedLabels(empty, recording)
	require.Equal(t, "rec", empty.Labels[profilerecordingapi.ProfileToRecordingLabel])
}
