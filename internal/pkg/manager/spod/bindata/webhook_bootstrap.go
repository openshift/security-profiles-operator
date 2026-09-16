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
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

var (
	// webhookBootstrapInterval is the retry interval of EnsureWebhookImageWithRetry.
	webhookBootstrapInterval = 5 * time.Second
	// webhookBootstrapTimeout is the overall timeout of EnsureWebhookImageWithRetry.
	webhookBootstrapTimeout = 2 * time.Minute
)

// EnsureWebhookImageWithRetry calls EnsureWebhookImage until it succeeds or
// the bootstrap timeout expires.
//
// The CRD conversion webhook (/convert) is served by the operator managed
// webhook deployment only. During an upgrade the CRDs are replaced first,
// so the new operator needs a working conversion webhook before its caches
// can sync: the field indexers register informers for the profile APIs
// before the manager starts, and listing them requires converting objects
// which are still stored in a previous API version. The webhook deployment
// is normally updated by the SPOD controller, which only runs after the
// caches synced. Without this bootstrap the old webhook deployment would
// stay in place forever and the manager would never start.
//
// This has to run before the manager is started and must only use core and
// apps/v1 resources so that it never depends on a conversion webhook itself.
func EnsureWebhookImageWithRetry(
	ctx context.Context, log logr.Logger, c client.Client, namespace string,
) error {
	return wait.PollUntilContextTimeout(ctx, webhookBootstrapInterval, webhookBootstrapTimeout, true,
		func(ctx context.Context) (bool, error) {
			if err := EnsureWebhookImage(ctx, log, c, c, namespace); err != nil {
				log.Info("Retrying to bootstrap the webhook deployment image", "error", err.Error())

				return false, nil
			}

			return true, nil
		})
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
