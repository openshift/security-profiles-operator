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
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	profilebase "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	seccompprofile "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
)

const (
	legacyRecording = "test-recording"
	legacyNamespace = "test-ns"
)

func legacyTestRecording(namespace string, deleted bool) *profilerecordingapi.ProfileRecording {
	r := &profilerecordingapi.ProfileRecording{
		ObjectMeta: metav1.ObjectMeta{
			Name:       legacyRecording,
			Namespace:  namespace,
			Finalizers: []string{profilerecordingapi.RecordingHasUnmergedProfiles},
		},
		Spec: profilerecordingapi.ProfileRecordingSpec{
			Kind:          profilerecordingapi.ProfileRecordingKindSeccompProfile,
			MergeStrategy: profilerecordingapi.ProfileMergeContainers,
		},
	}

	if deleted {
		now := metav1.NewTime(time.Now())
		r.DeletionTimestamp = &now
	}

	return r
}

// legacyPartialSeccomp is a partial profile as recorded before 1.0, which only
// labeled recorded profiles with the recording name.
func legacyPartialSeccomp(name, recording string, syscalls ...string) *seccompprofile.SeccompProfile {
	return &seccompprofile.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				profilerecordingapi.ProfileToRecordingLabel: recording,
				profilerecordingapi.ProfileToContainerLabel: "nginx",
				profilebase.ProfilePartialLabel:             "true",
			},
		},
		Spec: seccompprofile.SeccompProfileSpec{
			DefaultAction: seccompprofile.ActErrno,
			Syscalls: []seccompprofile.Syscall{{
				Action: seccompprofile.ActAllow,
				Names:  syscalls,
			}},
		},
	}
}

func newLegacyTestReconciler(t *testing.T, objs ...client.Object) *PolicyMergeReconciler {
	t.Helper()

	scheme := coverageTestScheme(t)
	require.NoError(t, profilerecordingapi.AddToScheme(scheme))

	return &PolicyMergeReconciler{
		client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build(),
		log:    logr.Discard(),
		record: record.NewFakeRecorder(20),
	}
}

func reconcileLegacyRecording(t *testing.T, r *PolicyMergeReconciler) reconcile.Result {
	t.Helper()

	res, err := r.Reconcile(t.Context(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: legacyRecording, Namespace: legacyNamespace},
	})
	require.NoError(t, err)

	return res
}

func requireNoRecordingNamespace(t *testing.T, r *PolicyMergeReconciler, name string) {
	t.Helper()

	prf := &seccompprofile.SeccompProfile{}
	require.NoError(t, r.client.Get(t.Context(), types.NamespacedName{Name: name}, prf))
	require.NotContains(t, prf.GetLabels(), profilerecordingapi.ProfileToRecordingNamespaceLabel)
}

// Partial profiles recorded before an upgrade to 1.0 have no recording
// namespace label, which the merge selects on. Without adopting them, the
// recording would never merge them and never be released.
func TestAdoptLegacyProfiles(t *testing.T) {
	t.Parallel()

	t.Run("profiles recorded before 1.0 get labeled and then merged", func(t *testing.T) {
		t.Parallel()

		r := newLegacyTestReconciler(t,
			legacyTestRecording(legacyNamespace, true),
			legacyPartialSeccomp("partial-a", legacyRecording, "read"),
			legacyPartialSeccomp("partial-b", legacyRecording, "write"),
		)

		// First pass: label the profiles and come back once the cache has them.
		require.Equal(t,
			reconcile.Result{RequeueAfter: adoptRequeueDelay},
			reconcileLegacyRecording(t, r))

		for _, name := range []string{"partial-a", "partial-b"} {
			prf := &seccompprofile.SeccompProfile{}
			require.NoError(t, r.client.Get(t.Context(), types.NamespacedName{Name: name}, prf))
			require.Equal(t, legacyNamespace,
				prf.GetLabels()[profilerecordingapi.ProfileToRecordingNamespaceLabel])
		}

		// Second pass: the labeled profiles are merged like any other.
		require.Equal(t, reconcile.Result{}, reconcileLegacyRecording(t, r))

		merged := &seccompprofile.SeccompProfile{}
		require.NoError(t, r.client.Get(t.Context(),
			types.NamespacedName{Name: legacyRecording + "-nginx"}, merged))
		require.NotContains(t, merged.GetLabels(), profilebase.ProfilePartialLabel)

		names := make([]string, 0, len(merged.Spec.Syscalls))
		for _, s := range merged.Spec.Syscalls {
			names = append(names, s.Names...)
		}

		require.ElementsMatch(t, []string{"read", "write"}, names)
	})

	t.Run("profiles are left alone when the recording name is ambiguous", func(t *testing.T) {
		t.Parallel()

		r := newLegacyTestReconciler(t,
			legacyTestRecording(legacyNamespace, true),
			legacyTestRecording("other-ns", false),
			legacyPartialSeccomp("partial-a", legacyRecording, "read"),
		)

		require.Equal(t, reconcile.Result{}, reconcileLegacyRecording(t, r))
		requireNoRecordingNamespace(t, r, "partial-a")

		rec, ok := r.record.(*record.FakeRecorder)
		require.True(t, ok)

		found := false

		for len(rec.Events) > 0 {
			if e := <-rec.Events; strings.Contains(e, reasonAmbiguousLegacy) {
				found = true
			}
		}

		require.True(t, found, "expected a %s event", reasonAmbiguousLegacy)
	})

	t.Run("profiles of another recording are not adopted", func(t *testing.T) {
		t.Parallel()

		r := newLegacyTestReconciler(t,
			legacyTestRecording(legacyNamespace, true),
			legacyPartialSeccomp("partial-other", "other-recording", "read"),
		)

		require.Equal(t, reconcile.Result{}, reconcileLegacyRecording(t, r))
		requireNoRecordingNamespace(t, r, "partial-other")
	})
}
