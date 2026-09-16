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
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestWebhookUpdateCreatesMissingObjects(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, appsv1.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, admissionregv1.AddToScheme(scheme))

	webhook := GetWebhook(
		logr.Discard(), testNamespace, nil, "operator:new", corev1.PullAlways,
		CAInjectTypeCertManager, nil, nil, false,
	)

	// Simulate an upgrade from a version which did not ship the validating
	// webhook configuration: everything but the validating config exists.
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		webhook.deployment.DeepCopy(),
		webhook.config.DeepCopy(),
		webhook.service.DeepCopy(),
	).Build()

	require.NoError(t, webhook.Update(context.Background(), c))

	validating := &admissionregv1.ValidatingWebhookConfiguration{}
	require.NoError(t, c.Get(context.Background(),
		client.ObjectKeyFromObject(webhook.validatingConfig), validating))
	require.Len(t, validating.Webhooks, len(webhook.validatingConfig.Webhooks))

	deployment := &appsv1.Deployment{}
	require.NoError(t, c.Get(context.Background(),
		client.ObjectKeyFromObject(webhook.deployment), deployment))
	require.Equal(t, "operator:new", deployment.Spec.Template.Spec.Containers[0].Image)
}
