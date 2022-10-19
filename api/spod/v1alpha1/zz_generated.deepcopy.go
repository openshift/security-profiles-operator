//go:build !ignore_autogenerated
// +build !ignore_autogenerated

/*
Copyright 2022 The Kubernetes Authors.

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

// Code generated by controller-gen. DO NOT EDIT.

package v1alpha1

import (
	"github.com/containers/common/pkg/seccomp"
	"k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SPODSpec) DeepCopyInto(out *SPODSpec) {
	*out = *in
	if in.EnableSelinux != nil {
		in, out := &in.EnableSelinux, &out.EnableSelinux
		*out = new(bool)
		**out = **in
	}
	if in.Tolerations != nil {
		in, out := &in.Tolerations, &out.Tolerations
		*out = make([]corev1.Toleration, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	in.SelinuxOpts.DeepCopyInto(&out.SelinuxOpts)
	if in.WebhookOpts != nil {
		in, out := &in.WebhookOpts, &out.WebhookOpts
		*out = make([]WebhookOptions, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.AllowedSyscalls != nil {
		in, out := &in.AllowedSyscalls, &out.AllowedSyscalls
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.AllowedSeccompActions != nil {
		in, out := &in.AllowedSeccompActions, &out.AllowedSeccompActions
		*out = make([]seccomp.Action, len(*in))
		copy(*out, *in)
	}
	if in.Affinity != nil {
		in, out := &in.Affinity, &out.Affinity
		*out = new(corev1.Affinity)
		(*in).DeepCopyInto(*out)
	}
	if in.ImagePullSecrets != nil {
		in, out := &in.ImagePullSecrets, &out.ImagePullSecrets
		*out = make([]corev1.LocalObjectReference, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SPODSpec.
func (in *SPODSpec) DeepCopy() *SPODSpec {
	if in == nil {
		return nil
	}
	out := new(SPODSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SPODStatus) DeepCopyInto(out *SPODStatus) {
	*out = *in
	in.ConditionedStatus.DeepCopyInto(&out.ConditionedStatus)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SPODStatus.
func (in *SPODStatus) DeepCopy() *SPODStatus {
	if in == nil {
		return nil
	}
	out := new(SPODStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SecurityProfilesOperatorDaemon) DeepCopyInto(out *SecurityProfilesOperatorDaemon) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SecurityProfilesOperatorDaemon.
func (in *SecurityProfilesOperatorDaemon) DeepCopy() *SecurityProfilesOperatorDaemon {
	if in == nil {
		return nil
	}
	out := new(SecurityProfilesOperatorDaemon)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *SecurityProfilesOperatorDaemon) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SecurityProfilesOperatorDaemonList) DeepCopyInto(out *SecurityProfilesOperatorDaemonList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]SecurityProfilesOperatorDaemon, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SecurityProfilesOperatorDaemonList.
func (in *SecurityProfilesOperatorDaemonList) DeepCopy() *SecurityProfilesOperatorDaemonList {
	if in == nil {
		return nil
	}
	out := new(SecurityProfilesOperatorDaemonList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *SecurityProfilesOperatorDaemonList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SelinuxOptions) DeepCopyInto(out *SelinuxOptions) {
	*out = *in
	if in.AllowedSystemProfiles != nil {
		in, out := &in.AllowedSystemProfiles, &out.AllowedSystemProfiles
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SelinuxOptions.
func (in *SelinuxOptions) DeepCopy() *SelinuxOptions {
	if in == nil {
		return nil
	}
	out := new(SelinuxOptions)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *WebhookOptions) DeepCopyInto(out *WebhookOptions) {
	*out = *in
	if in.FailurePolicy != nil {
		in, out := &in.FailurePolicy, &out.FailurePolicy
		*out = new(v1.FailurePolicyType)
		**out = **in
	}
	if in.NamespaceSelector != nil {
		in, out := &in.NamespaceSelector, &out.NamespaceSelector
		*out = new(metav1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	if in.ObjectSelector != nil {
		in, out := &in.ObjectSelector, &out.ObjectSelector
		*out = new(metav1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WebhookOptions.
func (in *WebhookOptions) DeepCopy() *WebhookOptions {
	if in == nil {
		return nil
	}
	out := new(WebhookOptions)
	in.DeepCopyInto(out)
	return out
}
