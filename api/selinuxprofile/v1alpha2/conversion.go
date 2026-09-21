/*
Copyright 2025 The Kubernetes Authors.

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

package v1alpha2

import (
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/conversion"

	profilebasev1 "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	secprofnodestatusv1 "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	secprofnodestatusv1alpha1 "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1alpha1"
	selinuxprofilev1 "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
)

func (src *SelinuxProfile) ConvertTo(dstRaw conversion.Hub) error {
	dst, ok := dstRaw.(*selinuxprofilev1.SelinuxProfile)
	if !ok {
		return fmt.Errorf("expected *selinuxprofilev1.SelinuxProfile, got %T", dstRaw)
	}

	dst.ObjectMeta = src.ObjectMeta

	// Spec
	dst.Spec.State = stateToV1(src.Spec.Disabled)
	dst.Spec.Mode = modeToV1(src.Spec.Permissive)

	dst.Spec.Inherit = make([]selinuxprofilev1.PolicyRef, len(src.Spec.Inherit))
	for i, p := range src.Spec.Inherit {
		dst.Spec.Inherit[i] = selinuxprofilev1.PolicyRef{
			Kind: p.Kind,
			Name: p.Name,
		}
	}

	if src.Spec.Allow != nil {
		dst.Spec.Allow = make(selinuxprofilev1.Allow, len(src.Spec.Allow))

		for lk, ockMap := range src.Spec.Allow {
			dstOckMap := make(map[selinuxprofilev1.ObjectClassKey]selinuxprofilev1.PermissionSet, len(ockMap))
			for ock, ps := range ockMap {
				dstOckMap[selinuxprofilev1.ObjectClassKey(ock)] = selinuxprofilev1.PermissionSet(ps)
			}

			dst.Spec.Allow[selinuxprofilev1.LabelKey(lk)] = dstOckMap
		}
	}

	// Status
	dst.Status.ConditionedStatus = src.Status.ConditionedStatus
	dst.Status.Status = secprofnodestatusv1.ProfileState(src.Status.Status)
	dst.Status.Usage = src.Status.Usage
	dst.Status.ActiveWorkloads = src.Status.ActiveWorkloads

	return nil
}

func (dst *SelinuxProfile) ConvertFrom(srcRaw conversion.Hub) error {
	src, ok := srcRaw.(*selinuxprofilev1.SelinuxProfile)
	if !ok {
		return fmt.Errorf("expected *selinuxprofilev1.SelinuxProfile, got %T", srcRaw)
	}

	dst.ObjectMeta = src.ObjectMeta

	// Spec
	dst.Spec.Disabled = src.Spec.State == profilebasev1.SpecStateDisabled
	dst.Spec.Permissive = src.Spec.Mode == selinuxprofilev1.SelinuxModePermissive

	dst.Spec.Inherit = make([]PolicyRef, len(src.Spec.Inherit))
	for i, p := range src.Spec.Inherit {
		dst.Spec.Inherit[i] = PolicyRef{
			Kind: p.Kind,
			Name: p.Name,
		}
	}

	if src.Spec.Allow != nil {
		dst.Spec.Allow = make(Allow, len(src.Spec.Allow))

		for lk, ockMap := range src.Spec.Allow {
			dstOckMap := make(map[ObjectClassKey]PermissionSet, len(ockMap))
			for ock, ps := range ockMap {
				dstOckMap[ObjectClassKey(ock)] = PermissionSet(ps)
			}

			dst.Spec.Allow[LabelKey(lk)] = dstOckMap
		}
	}

	// Status
	dst.Status.ConditionedStatus = src.Status.ConditionedStatus
	dst.Status.Status = secprofnodestatusv1alpha1.ProfileState(src.Status.Status)
	dst.Status.Usage = src.Status.Usage
	dst.Status.ActiveWorkloads = src.Status.ActiveWorkloads

	return nil
}

func (src *RawSelinuxProfile) ConvertTo(dstRaw conversion.Hub) error {
	dst, ok := dstRaw.(*selinuxprofilev1.RawSelinuxProfile)
	if !ok {
		return fmt.Errorf("expected *selinuxprofilev1.RawSelinuxProfile, got %T", dstRaw)
	}

	dst.ObjectMeta = src.ObjectMeta

	dst.Spec.State = stateToV1(src.Spec.Disabled)
	dst.Spec.Policy = src.Spec.Policy

	dst.Status.ConditionedStatus = src.Status.ConditionedStatus
	dst.Status.Status = secprofnodestatusv1.ProfileState(src.Status.Status)
	dst.Status.Usage = src.Status.Usage
	dst.Status.ActiveWorkloads = src.Status.ActiveWorkloads

	return nil
}

func (dst *RawSelinuxProfile) ConvertFrom(srcRaw conversion.Hub) error {
	src, ok := srcRaw.(*selinuxprofilev1.RawSelinuxProfile)
	if !ok {
		return fmt.Errorf("expected *selinuxprofilev1.RawSelinuxProfile, got %T", srcRaw)
	}

	dst.ObjectMeta = src.ObjectMeta

	dst.Spec.Disabled = src.Spec.State == profilebasev1.SpecStateDisabled
	dst.Spec.Policy = src.Spec.Policy

	dst.Status.ConditionedStatus = src.Status.ConditionedStatus
	dst.Status.Status = secprofnodestatusv1alpha1.ProfileState(src.Status.Status)
	dst.Status.Usage = src.Status.Usage
	dst.Status.ActiveWorkloads = src.Status.ActiveWorkloads

	return nil
}

// stateToV1 converts the v1alpha2 disabled boolean into the v1 state enum.
func stateToV1(disabled bool) profilebasev1.SpecState {
	if disabled {
		return profilebasev1.SpecStateDisabled
	}

	return ""
}

// modeToV1 converts the v1alpha2 permissive boolean into the v1 mode enum.
func modeToV1(permissive bool) selinuxprofilev1.SelinuxMode {
	if permissive {
		return selinuxprofilev1.SelinuxModePermissive
	}

	return ""
}
