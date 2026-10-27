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
	kerrors "k8s.io/apimachinery/pkg/api/errors"
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
	legacyTestRecording  = "test-recording"
	legacyTestNamespace  = "test-ns"
	legacyOtherNamespace = "other-ns"
)

// legacyEpoch is the creation time of the first object in the legacy tests.
var legacyEpoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func createdAt(minutes int) metav1.Time {
	return metav1.NewTime(legacyEpoch.Add(time.Duration(minutes) * time.Minute))
}

// legacyRecording is a recording created at the given minute.
func legacyRecording(namespace string, minute int, deleted bool) *profilerecordingapi.ProfileRecording {
	r := &profilerecordingapi.ProfileRecording{
		ObjectMeta: metav1.ObjectMeta{
			Name:              legacyTestRecording,
			Namespace:         namespace,
			CreationTimestamp: createdAt(minute),
			Finalizers:        []string{profilerecordingapi.RecordingHasUnmergedProfiles},
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

// legacyPartial is a partial profile recorded before 1.0, which only carries
// the recording name, created at the given minute.
func legacyPartial(name string, minute int, syscalls ...string) *seccompprofile.SeccompProfile {
	return &seccompprofile.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			CreationTimestamp: createdAt(minute),
			Labels: map[string]string{
				profilerecordingapi.ProfileToRecordingLabel: legacyTestRecording,
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

// legacyMerged is a profile merged before 1.0: it carries the recording name
// but is not partial.
func legacyMerged(name string, minute int) *seccompprofile.SeccompProfile {
	prf := legacyPartial(name, minute, "read")
	delete(prf.Labels, profilebase.ProfilePartialLabel)

	return prf
}

func newLegacyReconciler(t *testing.T, objs ...client.Object) *PolicyMergeReconciler {
	t.Helper()

	scheme := coverageTestScheme(t)
	require.NoError(t, profilerecordingapi.AddToScheme(scheme))

	return &PolicyMergeReconciler{
		client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build(),
		log:    logr.Discard(),
		record: record.NewFakeRecorder(20),
	}
}

func startLegacyAdopter(t *testing.T, r *PolicyMergeReconciler) {
	t.Helper()

	r.legacyAdoptionPending.Store(true)
	require.NoError(t, (&legacyAdopter{r: r}).Start(t.Context()))
	require.False(t, r.legacyAdoptionPending.Load())
}

func recordingNamespaceOf(t *testing.T, r *PolicyMergeReconciler, name string) string {
	t.Helper()

	prf := &seccompprofile.SeccompProfile{}
	require.NoError(t, r.client.Get(t.Context(), types.NamespacedName{Name: name}, prf))

	return prf.GetLabels()[profilerecordingapi.ProfileToRecordingNamespaceLabel]
}

func reconcileLegacyRecording(t *testing.T, r *PolicyMergeReconciler) reconcile.Result {
	t.Helper()

	res, err := r.Reconcile(t.Context(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: legacyTestRecording, Namespace: legacyTestNamespace},
	})
	require.NoError(t, err)

	return res
}

func requireLegacyEvent(t *testing.T, r *PolicyMergeReconciler, reason string) {
	t.Helper()

	rec, ok := r.record.(*record.FakeRecorder)
	require.True(t, ok)

	for len(rec.Events) > 0 {
		if strings.Contains(<-rec.Events, reason) {
			return
		}
	}

	require.Failf(t, "missing event", "expected a %s event", reason)
}

// requireMerged checks the merged profile of the recording and that the
// partial profiles are gone, after which the daemon releases the recording.
func requireMerged(t *testing.T, r *PolicyMergeReconciler, syscalls []string, partials ...string) {
	t.Helper()

	merged := &seccompprofile.SeccompProfile{}
	require.NoError(t, r.client.Get(t.Context(),
		types.NamespacedName{Name: legacyTestRecording + "-nginx"}, merged))
	require.NotContains(t, merged.GetLabels(), profilebase.ProfilePartialLabel)

	names := make([]string, 0, len(syscalls))
	for _, s := range merged.Spec.Syscalls {
		names = append(names, s.Names...)
	}

	require.ElementsMatch(t, syscalls, names)

	for _, name := range partials {
		err := r.client.Get(t.Context(), types.NamespacedName{Name: name}, &seccompprofile.SeccompProfile{})
		require.True(t, kerrors.IsNotFound(err), "partial profile %s should be deleted", name)
	}
}

func requireNotMerged(t *testing.T, r *PolicyMergeReconciler, partial string) {
	t.Helper()

	require.NoError(t, r.client.Get(t.Context(), types.NamespacedName{Name: partial},
		&seccompprofile.SeccompProfile{}))

	err := r.client.Get(t.Context(), types.NamespacedName{Name: legacyTestRecording + "-nginx"},
		&seccompprofile.SeccompProfile{})
	require.True(t, kerrors.IsNotFound(err), "nothing should be merged")
}

func TestLegacyPartialProfileSelector(t *testing.T) {
	t.Parallel()

	namespaced := legacyPartial("namespaced", 1, "read")
	namespaced.Labels[profilerecordingapi.ProfileToRecordingNamespaceLabel] = legacyTestNamespace

	r := newLegacyReconciler(t,
		legacyPartial("legacy", 1, "read"),
		legacyMerged("legacy-merged", 1),
		namespaced,
	)

	profiles, err := listLegacyPartialProfiles(t.Context(), r.client, legacyTestRecording)
	require.NoError(t, err)
	require.Len(t, profiles, 1)
	require.Equal(t, "legacy", profiles[0].GetName())
}

// The adoption at startup labels each partial profile recorded before 1.0
// with the namespace of the only recording which may have recorded it.
func TestLegacyAdopter(t *testing.T) {
	t.Parallel()

	t.Run("a single recording which may own them adopts them", func(t *testing.T) {
		t.Parallel()

		r := newLegacyReconciler(t,
			legacyRecording(legacyTestNamespace, 0, false),
			legacyPartial("partial-a", 1, "read"),
			legacyPartial("partial-b", 1, "write"),
		)

		startLegacyAdopter(t, r)

		require.Equal(t, legacyTestNamespace, recordingNamespaceOf(t, r, "partial-a"))
		require.Equal(t, legacyTestNamespace, recordingNamespaceOf(t, r, "partial-b"))
	})

	t.Run("a profile merged before 1.0 is not adopted", func(t *testing.T) {
		t.Parallel()

		r := newLegacyReconciler(t,
			legacyRecording(legacyTestNamespace, 0, false),
			legacyMerged("merged", 1),
		)

		startLegacyAdopter(t, r)

		// Recordings with this name in any namespace may still merge into it.
		require.Empty(t, recordingNamespaceOf(t, r, "merged"))
	})

	t.Run("a recording created after the profiles does not adopt them", func(t *testing.T) {
		t.Parallel()

		r := newLegacyReconciler(t,
			legacyPartial("stale", 0, "read"),
			legacyRecording(legacyTestNamespace, 1, false),
		)

		startLegacyAdopter(t, r)

		require.Empty(t, recordingNamespaceOf(t, r, "stale"))
	})

	t.Run("the creation time tells which recording recorded them", func(t *testing.T) {
		t.Parallel()

		r := newLegacyReconciler(t,
			legacyRecording(legacyOtherNamespace, 0, false),
			legacyPartial("partial", 1, "read"),
			legacyRecording(legacyTestNamespace, 2, false),
		)

		startLegacyAdopter(t, r)

		require.Equal(t, legacyOtherNamespace, recordingNamespaceOf(t, r, "partial"))
	})

	t.Run("profiles which may belong to several recordings are not adopted", func(t *testing.T) {
		t.Parallel()

		r := newLegacyReconciler(t,
			legacyRecording(legacyTestNamespace, 0, false),
			legacyRecording(legacyOtherNamespace, 0, false),
			legacyPartial("partial", 1, "read"),
		)

		startLegacyAdopter(t, r)

		require.Empty(t, recordingNamespaceOf(t, r, "partial"))
		requireLegacyEvent(t, r, reasonAmbiguousLegacy)
	})

	t.Run("recordings outside of the cache are counted", func(t *testing.T) {
		t.Parallel()

		partial := legacyPartial("partial", 1, "read")
		own := legacyRecording(legacyTestNamespace, 0, false)

		// The cache only covers the watched namespace, the API server shows
		// the recording with the same name in another namespace too.
		r := newLegacyReconciler(t, own, partial)
		r.reader = fake.NewClientBuilder().
			WithScheme(r.client.Scheme()).
			WithObjects(own.DeepCopy(), legacyRecording(legacyOtherNamespace, 0, false), partial.DeepCopy()).
			Build()

		startLegacyAdopter(t, r)

		require.Empty(t, recordingNamespaceOf(t, r, "partial"))
	})
}

// A deleted recording waits for the adoption at startup, and is not merged as
// long as partial profiles recorded before 1.0 exist which it may own.
func TestLegacyHold(t *testing.T) {
	t.Parallel()

	t.Run("a deleted recording waits for the adoption at startup", func(t *testing.T) {
		t.Parallel()

		partial := legacyPartial("partial", 1, "read")
		partial.Labels[profilerecordingapi.ProfileToRecordingNamespaceLabel] = legacyTestNamespace

		r := newLegacyReconciler(t, legacyRecording(legacyTestNamespace, 0, true), partial)
		r.legacyAdoptionPending.Store(true)

		require.Equal(t, reconcile.Result{RequeueAfter: legacyAdoptionWait}, reconcileLegacyRecording(t, r))
		requireNotMerged(t, r, "partial")
	})

	t.Run("adopted profiles are merged when their recording is deleted", func(t *testing.T) {
		t.Parallel()

		r := newLegacyReconciler(t,
			legacyRecording(legacyTestNamespace, 0, true),
			legacyPartial("partial-a", 1, "read"),
			legacyPartial("partial-b", 1, "write"),
		)

		startLegacyAdopter(t, r)

		require.Equal(t, reconcile.Result{}, reconcileLegacyRecording(t, r))
		requireMerged(t, r, []string{"read", "write"}, "partial-a", "partial-b")
	})

	t.Run("a recording created after stale profiles is not held", func(t *testing.T) {
		t.Parallel()

		r := newLegacyReconciler(t,
			legacyPartial("stale", 0, "read"),
			legacyRecording(legacyTestNamespace, 1, true),
		)

		startLegacyAdopter(t, r)

		require.Equal(t, reconcile.Result{}, reconcileLegacyRecording(t, r))

		// The stale profile is neither adopted nor merged.
		require.Empty(t, recordingNamespaceOf(t, r, "stale"))
		requireNotMerged(t, r, "stale")
	})

	t.Run("profiles which may belong to several recordings hold them until labeled", func(t *testing.T) {
		t.Parallel()

		r := newLegacyReconciler(t,
			legacyRecording(legacyTestNamespace, 0, true),
			legacyRecording(legacyOtherNamespace, 0, false),
			legacyPartial("partial", 1, "read"),
		)

		startLegacyAdopter(t, r)

		// Merging the profile could merge the syscalls of the other recording,
		// and the recording keeps its finalizer as long as it is not merged.
		require.Equal(t, reconcile.Result{RequeueAfter: legacyHoldWait}, reconcileLegacyRecording(t, r))
		requireLegacyEvent(t, r, reasonHeldForLegacy)
		requireNotMerged(t, r, "partial")

		// Once the profile is attributed, it is merged like any other.
		prf := &seccompprofile.SeccompProfile{}
		require.NoError(t, r.client.Get(t.Context(), types.NamespacedName{Name: "partial"}, prf))
		prf.Labels[profilerecordingapi.ProfileToRecordingNamespaceLabel] = legacyTestNamespace
		require.NoError(t, r.client.Update(t.Context(), prf))

		require.Equal(t, reconcile.Result{}, reconcileLegacyRecording(t, r))
		requireMerged(t, r, []string{"read"}, "partial")
	})
}
