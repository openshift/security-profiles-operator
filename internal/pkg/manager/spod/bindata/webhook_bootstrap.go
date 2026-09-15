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
	"fmt"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

// WebhookImageBootstrapper is a manager runnable which aligns the image of the
// operator managed webhook deployment with the image of the running operator
// before any controller starts to reconcile.
//
// The CRD conversion webhook (/convert) is served by the webhook deployment
// only. During an upgrade the CRDs are replaced first, so the new operator
// needs a working conversion webhook to read resources which are still
// stored in a previous API version (for example the SPOD configuration).
// The webhook deployment is normally updated by the SPOD controller, which in
// turn needs to read the SPOD configuration. Without this bootstrap the old
// webhook deployment would stay in place forever and the operator would be
// stuck on conversion errors.
//
// The bootstrap only uses core and apps/v1 resources so it never depends on a
// conversion webhook itself.
type WebhookImageBootstrapper struct {
	log       logr.Logger
	reader    client.Reader
	writer    client.Writer
	namespace string
}

// NewWebhookImageBootstrapper creates a new WebhookImageBootstrapper. The
// reader should not depend on a synced cache (for example the manager API
// reader).
func NewWebhookImageBootstrapper(
	log logr.Logger, reader client.Reader, writer client.Writer, namespace string,
) *WebhookImageBootstrapper {
	return &WebhookImageBootstrapper{
		log:       log,
		reader:    reader,
		writer:    writer,
		namespace: namespace,
	}
}

// Start implements manager.Runnable. It returns after the bootstrap has been
// executed once.
func (b *WebhookImageBootstrapper) Start(ctx context.Context) error {
	if err := EnsureWebhookImage(ctx, b.log, b.reader, b.writer, b.namespace); err != nil {
		// Do not fail the manager, the SPOD controller will retry to
		// reconcile the webhook anyway.
		b.log.Error(err, "Unable to bootstrap the webhook deployment image")
	}

	return nil
}

// NeedLeaderElection implements manager.LeaderElectionRunnable so that only
// the leading operator instance mutates the webhook deployment.
func (b *WebhookImageBootstrapper) NeedLeaderElection() bool {
	return true
}

// EnsureWebhookImage updates the container images of the webhook deployment
// to the image of the operator deployment if they differ. It is a no-op if
// either deployment does not exist.
func EnsureWebhookImage(
	ctx context.Context,
	log logr.Logger,
	reader client.Reader,
	writer client.Writer,
	namespace string,
) error {
	operatorDeployment := &appsv1.Deployment{}
	if err := reader.Get(ctx, types.NamespacedName{
		Name:      config.OperatorName,
		Namespace: namespace,
	}, operatorDeployment); err != nil {
		if errors.IsNotFound(err) {
			return nil
		}

		return fmt.Errorf("get operator deployment: %w", err)
	}

	if len(operatorDeployment.Spec.Template.Spec.Containers) == 0 {
		return nil
	}

	image := operatorDeployment.Spec.Template.Spec.Containers[0].Image
	pullPolicy := operatorDeployment.Spec.Template.Spec.Containers[0].ImagePullPolicy

	webhookDeployment := &appsv1.Deployment{}
	if err := reader.Get(ctx, types.NamespacedName{
		Name:      webhookName,
		Namespace: namespace,
	}, webhookDeployment); err != nil {
		if errors.IsNotFound(err) {
			// Fresh installation, the SPOD controller will create it.
			return nil
		}

		return fmt.Errorf("get webhook deployment: %w", err)
	}

	updated := false

	for i := range webhookDeployment.Spec.Template.Spec.Containers {
		ctr := &webhookDeployment.Spec.Template.Spec.Containers[i]
		if ctr.Image == image {
			continue
		}

		log.Info("Bootstrapping webhook deployment image",
			"container", ctr.Name, "from", ctr.Image, "to", image)

		ctr.Image = image
		ctr.ImagePullPolicy = pullPolicy
		updated = true
	}

	if !updated {
		return nil
	}

	if err := writer.Update(ctx, webhookDeployment); err != nil {
		return fmt.Errorf("update webhook deployment image: %w", err)
	}

	return nil
}
