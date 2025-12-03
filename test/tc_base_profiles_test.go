/*
Copyright 2020 The Kubernetes Authors.

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

package e2e_test

import (
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	baseProfileNameRunc = "runc-v1.3.0"
	baseProfileNameCrun = "crun-v1.22"
)

func (e *e2e) testCaseBaseProfile([]string) {
	e.seccompOnlyTestCase()

	baseProfilePath := "examples/baseprofile-runc.yaml"
	baseProfileName := baseProfileNameRunc

	if clusterType == clusterTypeVanilla && e.containerRuntime != containerRuntimeDocker {
		baseProfilePath = "examples/baseprofile-crun.yaml"
		baseProfileName = baseProfileNameCrun
	}

	helloProfile := fmt.Sprintf(`
apiVersion: security-profiles-operator.x-k8s.io/v1beta1
kind: SeccompProfile
metadata:
  name: hello
spec:
  defaultAction: SCMP_ACT_ERRNO
  baseProfileName: %s
  syscalls:
  - action: SCMP_ACT_ALLOW
    names:
    - arch_prctl
    - set_tid_address
    - exit_group
`, baseProfileName)

	e.kubectl("create", "-f", baseProfilePath)

	defer e.kubectl("delete", "-f", baseProfilePath)

	e.logf("Creating hello profile")

	helloProfileFile, err := os.CreateTemp("", "hello-profile*.yaml")
	e.Nil(err)

	defer os.Remove(helloProfileFile.Name())

	_, err = helloProfileFile.WriteString(helloProfile)
	e.Nil(err)
	err = helloProfileFile.Close()
	e.Nil(err)
	e.kubectl("create", "-f", helloProfileFile.Name())

	defer e.kubectl("delete", "-f", helloProfileFile.Name())

	e.logf("Waiting for profile to be reconciled")
	e.waitForProfile("hello")

	// Get the profile to check the actual localhostProfile path
	profile := e.getSeccompProfile("hello")
	localhostProfile := profile.Status.LocalhostProfile
	e.logf("Profile status localhostProfile: %s", localhostProfile)

	// Fail if localhostProfile is empty - this indicates the profile was not properly reconciled
	if localhostProfile == "" {
		e.logf("Profile localhostProfile is empty, gathering debug information")
		e.kubectlOperatorNS("logs", "-l", "name=spod")
		profileYAML := e.kubectl("get", "sp", "hello", "-o", "yaml")
		e.logf("Profile YAML:\n%s", profileYAML)
		e.FailNowf("Profile localhostProfile is empty - profile was not properly reconciled", "Profile YAML:\n%s", profileYAML)
	}

	// Update pod YAML with the correct localhostProfile path
	helloPodWithPath := fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: hello
spec:
  containers:
  - image: quay.io/security-profiles-operator/test-hello-world:latest
    name: hello
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: %s
  restartPolicy: OnFailure
`, localhostProfile)

	e.logf("Creating hello-world pod with localhostProfile: %s", localhostProfile)

	helloPodFile, err := os.CreateTemp("", "hello-pod*.yaml")
	e.Nil(err)

	defer os.Remove(helloPodFile.Name())

	_, err = helloPodFile.WriteString(helloPodWithPath)
	e.Nil(err)
	err = helloPodFile.Close()
	e.Nil(err)
	e.kubectl("create", "-f", helloPodFile.Name())

	defer e.kubectl("delete", "pod", "hello")

	e.logf("Waiting for test pod to be initialized")
	e.waitFor("condition=initialized", "pod", "hello")

	e.logf("Waiting for pod to be completed")

	for range 20 {
		output := e.kubectl("get", "pod", "hello")
		if strings.Contains(output, "Completed") {
			break
		}

		if strings.Contains(output, "CreateContainerError") {
			e.logf("Container creation failed, gathering debug information")
			e.kubectlOperatorNS("logs", "-l", "name=spod")
			e.kubectl("get", "sp", "hello", "-o", "yaml")
			podDescribe := e.kubectl("describe", "pod", "hello")
			e.logf("Pod describe output:\n%s", podDescribe)
			e.FailNowf("Unable to create container", podDescribe)
		}

		time.Sleep(time.Second)
	}

	e.logf("Testing that container ran successfully")
	output := e.kubectl("logs", "hello")
	e.Contains(output, "Hello from Docker!")
}
