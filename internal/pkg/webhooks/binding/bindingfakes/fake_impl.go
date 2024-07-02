/*
Copyright The Kubernetes Authors.

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

// Code generated by counterfeiter. DO NOT EDIT.
package bindingfakes

import (
	"context"
	"sync"

	"github.com/go-logr/logr"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
	"sigs.k8s.io/security-profiles-operator/api/profilebinding/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
	"sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1alpha2"
)

type FakeImpl struct {
	DecodePodStub        func(admission.Request) (*v1.Pod, error)
	decodePodMutex       sync.RWMutex
	decodePodArgsForCall []struct {
		arg1 admission.Request
	}
	decodePodReturns struct {
		result1 *v1.Pod
		result2 error
	}
	decodePodReturnsOnCall map[int]struct {
		result1 *v1.Pod
		result2 error
	}
	GetSeccompProfileStub        func(context.Context, types.NamespacedName) (*v1beta1.SeccompProfile, error)
	getSeccompProfileMutex       sync.RWMutex
	getSeccompProfileArgsForCall []struct {
		arg1 context.Context
		arg2 types.NamespacedName
	}
	getSeccompProfileReturns struct {
		result1 *v1beta1.SeccompProfile
		result2 error
	}
	getSeccompProfileReturnsOnCall map[int]struct {
		result1 *v1beta1.SeccompProfile
		result2 error
	}
	GetSelinuxProfileStub        func(context.Context, types.NamespacedName) (*v1alpha2.SelinuxProfile, error)
	getSelinuxProfileMutex       sync.RWMutex
	getSelinuxProfileArgsForCall []struct {
		arg1 context.Context
		arg2 types.NamespacedName
	}
	getSelinuxProfileReturns struct {
		result1 *v1alpha2.SelinuxProfile
		result2 error
	}
	getSelinuxProfileReturnsOnCall map[int]struct {
		result1 *v1alpha2.SelinuxProfile
		result2 error
	}
	ListProfileBindingsStub        func(context.Context, ...client.ListOption) (*v1alpha1.ProfileBindingList, error)
	listProfileBindingsMutex       sync.RWMutex
	listProfileBindingsArgsForCall []struct {
		arg1 context.Context
		arg2 []client.ListOption
	}
	listProfileBindingsReturns struct {
		result1 *v1alpha1.ProfileBindingList
		result2 error
	}
	listProfileBindingsReturnsOnCall map[int]struct {
		result1 *v1alpha1.ProfileBindingList
		result2 error
	}
	UpdateResourceStub        func(context.Context, logr.Logger, client.Object, string) error
	updateResourceMutex       sync.RWMutex
	updateResourceArgsForCall []struct {
		arg1 context.Context
		arg2 logr.Logger
		arg3 client.Object
		arg4 string
	}
	updateResourceReturns struct {
		result1 error
	}
	updateResourceReturnsOnCall map[int]struct {
		result1 error
	}
	UpdateResourceStatusStub        func(context.Context, logr.Logger, client.Object, string) error
	updateResourceStatusMutex       sync.RWMutex
	updateResourceStatusArgsForCall []struct {
		arg1 context.Context
		arg2 logr.Logger
		arg3 client.Object
		arg4 string
	}
	updateResourceStatusReturns struct {
		result1 error
	}
	updateResourceStatusReturnsOnCall map[int]struct {
		result1 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeImpl) DecodePod(arg1 admission.Request) (*v1.Pod, error) {
	fake.decodePodMutex.Lock()
	ret, specificReturn := fake.decodePodReturnsOnCall[len(fake.decodePodArgsForCall)]
	fake.decodePodArgsForCall = append(fake.decodePodArgsForCall, struct {
		arg1 admission.Request
	}{arg1})
	stub := fake.DecodePodStub
	fakeReturns := fake.decodePodReturns
	fake.recordInvocation("DecodePod", []interface{}{arg1})
	fake.decodePodMutex.Unlock()
	if stub != nil {
		return stub(arg1)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *FakeImpl) DecodePodCallCount() int {
	fake.decodePodMutex.RLock()
	defer fake.decodePodMutex.RUnlock()
	return len(fake.decodePodArgsForCall)
}

func (fake *FakeImpl) DecodePodCalls(stub func(admission.Request) (*v1.Pod, error)) {
	fake.decodePodMutex.Lock()
	defer fake.decodePodMutex.Unlock()
	fake.DecodePodStub = stub
}

func (fake *FakeImpl) DecodePodArgsForCall(i int) admission.Request {
	fake.decodePodMutex.RLock()
	defer fake.decodePodMutex.RUnlock()
	argsForCall := fake.decodePodArgsForCall[i]
	return argsForCall.arg1
}

func (fake *FakeImpl) DecodePodReturns(result1 *v1.Pod, result2 error) {
	fake.decodePodMutex.Lock()
	defer fake.decodePodMutex.Unlock()
	fake.DecodePodStub = nil
	fake.decodePodReturns = struct {
		result1 *v1.Pod
		result2 error
	}{result1, result2}
}

func (fake *FakeImpl) DecodePodReturnsOnCall(i int, result1 *v1.Pod, result2 error) {
	fake.decodePodMutex.Lock()
	defer fake.decodePodMutex.Unlock()
	fake.DecodePodStub = nil
	if fake.decodePodReturnsOnCall == nil {
		fake.decodePodReturnsOnCall = make(map[int]struct {
			result1 *v1.Pod
			result2 error
		})
	}
	fake.decodePodReturnsOnCall[i] = struct {
		result1 *v1.Pod
		result2 error
	}{result1, result2}
}

func (fake *FakeImpl) GetSeccompProfile(arg1 context.Context, arg2 types.NamespacedName) (*v1beta1.SeccompProfile, error) {
	fake.getSeccompProfileMutex.Lock()
	ret, specificReturn := fake.getSeccompProfileReturnsOnCall[len(fake.getSeccompProfileArgsForCall)]
	fake.getSeccompProfileArgsForCall = append(fake.getSeccompProfileArgsForCall, struct {
		arg1 context.Context
		arg2 types.NamespacedName
	}{arg1, arg2})
	stub := fake.GetSeccompProfileStub
	fakeReturns := fake.getSeccompProfileReturns
	fake.recordInvocation("GetSeccompProfile", []interface{}{arg1, arg2})
	fake.getSeccompProfileMutex.Unlock()
	if stub != nil {
		return stub(arg1, arg2)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *FakeImpl) GetSeccompProfileCallCount() int {
	fake.getSeccompProfileMutex.RLock()
	defer fake.getSeccompProfileMutex.RUnlock()
	return len(fake.getSeccompProfileArgsForCall)
}

func (fake *FakeImpl) GetSeccompProfileCalls(stub func(context.Context, types.NamespacedName) (*v1beta1.SeccompProfile, error)) {
	fake.getSeccompProfileMutex.Lock()
	defer fake.getSeccompProfileMutex.Unlock()
	fake.GetSeccompProfileStub = stub
}

func (fake *FakeImpl) GetSeccompProfileArgsForCall(i int) (context.Context, types.NamespacedName) {
	fake.getSeccompProfileMutex.RLock()
	defer fake.getSeccompProfileMutex.RUnlock()
	argsForCall := fake.getSeccompProfileArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2
}

func (fake *FakeImpl) GetSeccompProfileReturns(result1 *v1beta1.SeccompProfile, result2 error) {
	fake.getSeccompProfileMutex.Lock()
	defer fake.getSeccompProfileMutex.Unlock()
	fake.GetSeccompProfileStub = nil
	fake.getSeccompProfileReturns = struct {
		result1 *v1beta1.SeccompProfile
		result2 error
	}{result1, result2}
}

func (fake *FakeImpl) GetSeccompProfileReturnsOnCall(i int, result1 *v1beta1.SeccompProfile, result2 error) {
	fake.getSeccompProfileMutex.Lock()
	defer fake.getSeccompProfileMutex.Unlock()
	fake.GetSeccompProfileStub = nil
	if fake.getSeccompProfileReturnsOnCall == nil {
		fake.getSeccompProfileReturnsOnCall = make(map[int]struct {
			result1 *v1beta1.SeccompProfile
			result2 error
		})
	}
	fake.getSeccompProfileReturnsOnCall[i] = struct {
		result1 *v1beta1.SeccompProfile
		result2 error
	}{result1, result2}
}

func (fake *FakeImpl) GetSelinuxProfile(arg1 context.Context, arg2 types.NamespacedName) (*v1alpha2.SelinuxProfile, error) {
	fake.getSelinuxProfileMutex.Lock()
	ret, specificReturn := fake.getSelinuxProfileReturnsOnCall[len(fake.getSelinuxProfileArgsForCall)]
	fake.getSelinuxProfileArgsForCall = append(fake.getSelinuxProfileArgsForCall, struct {
		arg1 context.Context
		arg2 types.NamespacedName
	}{arg1, arg2})
	stub := fake.GetSelinuxProfileStub
	fakeReturns := fake.getSelinuxProfileReturns
	fake.recordInvocation("GetSelinuxProfile", []interface{}{arg1, arg2})
	fake.getSelinuxProfileMutex.Unlock()
	if stub != nil {
		return stub(arg1, arg2)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *FakeImpl) GetSelinuxProfileCallCount() int {
	fake.getSelinuxProfileMutex.RLock()
	defer fake.getSelinuxProfileMutex.RUnlock()
	return len(fake.getSelinuxProfileArgsForCall)
}

func (fake *FakeImpl) GetSelinuxProfileCalls(stub func(context.Context, types.NamespacedName) (*v1alpha2.SelinuxProfile, error)) {
	fake.getSelinuxProfileMutex.Lock()
	defer fake.getSelinuxProfileMutex.Unlock()
	fake.GetSelinuxProfileStub = stub
}

func (fake *FakeImpl) GetSelinuxProfileArgsForCall(i int) (context.Context, types.NamespacedName) {
	fake.getSelinuxProfileMutex.RLock()
	defer fake.getSelinuxProfileMutex.RUnlock()
	argsForCall := fake.getSelinuxProfileArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2
}

func (fake *FakeImpl) GetSelinuxProfileReturns(result1 *v1alpha2.SelinuxProfile, result2 error) {
	fake.getSelinuxProfileMutex.Lock()
	defer fake.getSelinuxProfileMutex.Unlock()
	fake.GetSelinuxProfileStub = nil
	fake.getSelinuxProfileReturns = struct {
		result1 *v1alpha2.SelinuxProfile
		result2 error
	}{result1, result2}
}

func (fake *FakeImpl) GetSelinuxProfileReturnsOnCall(i int, result1 *v1alpha2.SelinuxProfile, result2 error) {
	fake.getSelinuxProfileMutex.Lock()
	defer fake.getSelinuxProfileMutex.Unlock()
	fake.GetSelinuxProfileStub = nil
	if fake.getSelinuxProfileReturnsOnCall == nil {
		fake.getSelinuxProfileReturnsOnCall = make(map[int]struct {
			result1 *v1alpha2.SelinuxProfile
			result2 error
		})
	}
	fake.getSelinuxProfileReturnsOnCall[i] = struct {
		result1 *v1alpha2.SelinuxProfile
		result2 error
	}{result1, result2}
}

func (fake *FakeImpl) ListProfileBindings(arg1 context.Context, arg2 ...client.ListOption) (*v1alpha1.ProfileBindingList, error) {
	fake.listProfileBindingsMutex.Lock()
	ret, specificReturn := fake.listProfileBindingsReturnsOnCall[len(fake.listProfileBindingsArgsForCall)]
	fake.listProfileBindingsArgsForCall = append(fake.listProfileBindingsArgsForCall, struct {
		arg1 context.Context
		arg2 []client.ListOption
	}{arg1, arg2})
	stub := fake.ListProfileBindingsStub
	fakeReturns := fake.listProfileBindingsReturns
	fake.recordInvocation("ListProfileBindings", []interface{}{arg1, arg2})
	fake.listProfileBindingsMutex.Unlock()
	if stub != nil {
		return stub(arg1, arg2...)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *FakeImpl) ListProfileBindingsCallCount() int {
	fake.listProfileBindingsMutex.RLock()
	defer fake.listProfileBindingsMutex.RUnlock()
	return len(fake.listProfileBindingsArgsForCall)
}

func (fake *FakeImpl) ListProfileBindingsCalls(stub func(context.Context, ...client.ListOption) (*v1alpha1.ProfileBindingList, error)) {
	fake.listProfileBindingsMutex.Lock()
	defer fake.listProfileBindingsMutex.Unlock()
	fake.ListProfileBindingsStub = stub
}

func (fake *FakeImpl) ListProfileBindingsArgsForCall(i int) (context.Context, []client.ListOption) {
	fake.listProfileBindingsMutex.RLock()
	defer fake.listProfileBindingsMutex.RUnlock()
	argsForCall := fake.listProfileBindingsArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2
}

func (fake *FakeImpl) ListProfileBindingsReturns(result1 *v1alpha1.ProfileBindingList, result2 error) {
	fake.listProfileBindingsMutex.Lock()
	defer fake.listProfileBindingsMutex.Unlock()
	fake.ListProfileBindingsStub = nil
	fake.listProfileBindingsReturns = struct {
		result1 *v1alpha1.ProfileBindingList
		result2 error
	}{result1, result2}
}

func (fake *FakeImpl) ListProfileBindingsReturnsOnCall(i int, result1 *v1alpha1.ProfileBindingList, result2 error) {
	fake.listProfileBindingsMutex.Lock()
	defer fake.listProfileBindingsMutex.Unlock()
	fake.ListProfileBindingsStub = nil
	if fake.listProfileBindingsReturnsOnCall == nil {
		fake.listProfileBindingsReturnsOnCall = make(map[int]struct {
			result1 *v1alpha1.ProfileBindingList
			result2 error
		})
	}
	fake.listProfileBindingsReturnsOnCall[i] = struct {
		result1 *v1alpha1.ProfileBindingList
		result2 error
	}{result1, result2}
}

func (fake *FakeImpl) UpdateResource(arg1 context.Context, arg2 logr.Logger, arg3 client.Object, arg4 string) error {
	fake.updateResourceMutex.Lock()
	ret, specificReturn := fake.updateResourceReturnsOnCall[len(fake.updateResourceArgsForCall)]
	fake.updateResourceArgsForCall = append(fake.updateResourceArgsForCall, struct {
		arg1 context.Context
		arg2 logr.Logger
		arg3 client.Object
		arg4 string
	}{arg1, arg2, arg3, arg4})
	stub := fake.UpdateResourceStub
	fakeReturns := fake.updateResourceReturns
	fake.recordInvocation("UpdateResource", []interface{}{arg1, arg2, arg3, arg4})
	fake.updateResourceMutex.Unlock()
	if stub != nil {
		return stub(arg1, arg2, arg3, arg4)
	}
	if specificReturn {
		return ret.result1
	}
	return fakeReturns.result1
}

func (fake *FakeImpl) UpdateResourceCallCount() int {
	fake.updateResourceMutex.RLock()
	defer fake.updateResourceMutex.RUnlock()
	return len(fake.updateResourceArgsForCall)
}

func (fake *FakeImpl) UpdateResourceCalls(stub func(context.Context, logr.Logger, client.Object, string) error) {
	fake.updateResourceMutex.Lock()
	defer fake.updateResourceMutex.Unlock()
	fake.UpdateResourceStub = stub
}

func (fake *FakeImpl) UpdateResourceArgsForCall(i int) (context.Context, logr.Logger, client.Object, string) {
	fake.updateResourceMutex.RLock()
	defer fake.updateResourceMutex.RUnlock()
	argsForCall := fake.updateResourceArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2, argsForCall.arg3, argsForCall.arg4
}

func (fake *FakeImpl) UpdateResourceReturns(result1 error) {
	fake.updateResourceMutex.Lock()
	defer fake.updateResourceMutex.Unlock()
	fake.UpdateResourceStub = nil
	fake.updateResourceReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeImpl) UpdateResourceReturnsOnCall(i int, result1 error) {
	fake.updateResourceMutex.Lock()
	defer fake.updateResourceMutex.Unlock()
	fake.UpdateResourceStub = nil
	if fake.updateResourceReturnsOnCall == nil {
		fake.updateResourceReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.updateResourceReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *FakeImpl) UpdateResourceStatus(arg1 context.Context, arg2 logr.Logger, arg3 client.Object, arg4 string) error {
	fake.updateResourceStatusMutex.Lock()
	ret, specificReturn := fake.updateResourceStatusReturnsOnCall[len(fake.updateResourceStatusArgsForCall)]
	fake.updateResourceStatusArgsForCall = append(fake.updateResourceStatusArgsForCall, struct {
		arg1 context.Context
		arg2 logr.Logger
		arg3 client.Object
		arg4 string
	}{arg1, arg2, arg3, arg4})
	stub := fake.UpdateResourceStatusStub
	fakeReturns := fake.updateResourceStatusReturns
	fake.recordInvocation("UpdateResourceStatus", []interface{}{arg1, arg2, arg3, arg4})
	fake.updateResourceStatusMutex.Unlock()
	if stub != nil {
		return stub(arg1, arg2, arg3, arg4)
	}
	if specificReturn {
		return ret.result1
	}
	return fakeReturns.result1
}

func (fake *FakeImpl) UpdateResourceStatusCallCount() int {
	fake.updateResourceStatusMutex.RLock()
	defer fake.updateResourceStatusMutex.RUnlock()
	return len(fake.updateResourceStatusArgsForCall)
}

func (fake *FakeImpl) UpdateResourceStatusCalls(stub func(context.Context, logr.Logger, client.Object, string) error) {
	fake.updateResourceStatusMutex.Lock()
	defer fake.updateResourceStatusMutex.Unlock()
	fake.UpdateResourceStatusStub = stub
}

func (fake *FakeImpl) UpdateResourceStatusArgsForCall(i int) (context.Context, logr.Logger, client.Object, string) {
	fake.updateResourceStatusMutex.RLock()
	defer fake.updateResourceStatusMutex.RUnlock()
	argsForCall := fake.updateResourceStatusArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2, argsForCall.arg3, argsForCall.arg4
}

func (fake *FakeImpl) UpdateResourceStatusReturns(result1 error) {
	fake.updateResourceStatusMutex.Lock()
	defer fake.updateResourceStatusMutex.Unlock()
	fake.UpdateResourceStatusStub = nil
	fake.updateResourceStatusReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeImpl) UpdateResourceStatusReturnsOnCall(i int, result1 error) {
	fake.updateResourceStatusMutex.Lock()
	defer fake.updateResourceStatusMutex.Unlock()
	fake.UpdateResourceStatusStub = nil
	if fake.updateResourceStatusReturnsOnCall == nil {
		fake.updateResourceStatusReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.updateResourceStatusReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *FakeImpl) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.decodePodMutex.RLock()
	defer fake.decodePodMutex.RUnlock()
	fake.getSeccompProfileMutex.RLock()
	defer fake.getSeccompProfileMutex.RUnlock()
	fake.getSelinuxProfileMutex.RLock()
	defer fake.getSelinuxProfileMutex.RUnlock()
	fake.listProfileBindingsMutex.RLock()
	defer fake.listProfileBindingsMutex.RUnlock()
	fake.updateResourceMutex.RLock()
	defer fake.updateResourceMutex.RUnlock()
	fake.updateResourceStatusMutex.RLock()
	defer fake.updateResourceStatusMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *FakeImpl) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}
