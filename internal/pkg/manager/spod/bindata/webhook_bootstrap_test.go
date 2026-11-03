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

package bindata

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

const testNamespace = "spo-test"

func deployment(name, image string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:            name,
						Image:           image,
						ImagePullPolicy: corev1.PullAlways,
					}},
				},
			},
		},
	}
}

func newFakeClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, appsv1.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))

	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
}

func webhookImage(t *testing.T, c client.Client) string {
	t.Helper()

	webhook := &appsv1.Deployment{}
	require.NoError(t, c.Get(context.Background(),
		types.NamespacedName{Name: webhookName, Namespace: testNamespace}, webhook))

	return webhook.Spec.Template.Spec.Containers[0].Image
}

func TestEnsureWebhookImageUpdatesOutdatedImage(t *testing.T) {
	t.Parallel()

	c := newFakeClient(t,
		deployment(config.OperatorName, "operator:new"),
		deployment(webhookName, "operator:old"),
	)

	require.NoError(t, EnsureWebhookImage(context.Background(), logr.Discard(), c, c, testNamespace))

	webhook := &appsv1.Deployment{}
	require.NoError(t, c.Get(context.Background(),
		types.NamespacedName{Name: webhookName, Namespace: testNamespace}, webhook))
	require.Equal(t, "operator:new", webhook.Spec.Template.Spec.Containers[0].Image)
	require.Equal(t, corev1.PullAlways, webhook.Spec.Template.Spec.Containers[0].ImagePullPolicy)
}

func TestEnsureWebhookImageNoopWhenUpToDate(t *testing.T) {
	t.Parallel()

	c := newFakeClient(t,
		deployment(config.OperatorName, "operator:new"),
		deployment(webhookName, "operator:new"),
	)

	before := &appsv1.Deployment{}
	require.NoError(t, c.Get(context.Background(),
		types.NamespacedName{Name: webhookName, Namespace: testNamespace}, before))

	require.NoError(t, EnsureWebhookImage(context.Background(), logr.Discard(), c, c, testNamespace))

	after := &appsv1.Deployment{}
	require.NoError(t, c.Get(context.Background(),
		types.NamespacedName{Name: webhookName, Namespace: testNamespace}, after))
	require.Equal(t, before.ResourceVersion, after.ResourceVersion)
}

func TestEnsureWebhookImageNoopWhenWebhookMissing(t *testing.T) {
	t.Parallel()

	c := newFakeClient(t, deployment(config.OperatorName, "operator:new"))

	require.NoError(t, EnsureWebhookImage(context.Background(), logr.Discard(), c, c, testNamespace))
}

func TestEnsureWebhookImageNoopWhenOperatorMissing(t *testing.T) {
	t.Parallel()

	c := newFakeClient(t, deployment(webhookName, "operator:old"))

	require.NoError(t, EnsureWebhookImage(context.Background(), logr.Discard(), c, c, testNamespace))
	require.Equal(t, "operator:old", webhookImage(t, c))
}

// flakyClient fails the first reads and succeeds afterwards.
type flakyClient struct {
	client.Client

	failures atomic.Int32
}

func (f *flakyClient) Get(
	ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption,
) error {
	if f.failures.Add(-1) >= 0 {
		return errors.New("transient error")
	}

	return f.Client.Get(ctx, key, obj, opts...)
}

//nolint:paralleltest // mutates the package level bootstrap timeouts
func TestEnsureWebhookImageWithRetryRecovers(t *testing.T) {
	webhookBootstrapInterval = 10 * time.Millisecond
	webhookBootstrapTimeout = 2 * time.Second

	c := &flakyClient{Client: newFakeClient(t,
		deployment(config.OperatorName, "operator:new"),
		deployment(webhookName, "operator:old"),
	)}
	c.failures.Store(2)

	require.NoError(t, EnsureWebhookImageWithRetry(context.Background(), logr.Discard(), c, testNamespace))
	require.Equal(t, "operator:new", webhookImage(t, c.Client))
}

//nolint:paralleltest // mutates the package level bootstrap timeouts
func TestEnsureWebhookImageWithRetryTimesOut(t *testing.T) {
	webhookBootstrapInterval = 10 * time.Millisecond
	webhookBootstrapTimeout = 100 * time.Millisecond

	c := &flakyClient{Client: newFakeClient(t,
		deployment(config.OperatorName, "operator:new"),
		deployment(webhookName, "operator:old"),
	)}
	c.failures.Store(1000)

	require.Error(t, EnsureWebhookImageWithRetry(context.Background(), logr.Discard(), c, testNamespace))
}
