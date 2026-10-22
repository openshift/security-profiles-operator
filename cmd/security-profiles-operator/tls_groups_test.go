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

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

// fakeOpenShiftAPIServer serves the discovery documents and the two
// config.openshift.io objects fetchTLSOptions reads: the openshift-apiserver
// ClusterOperator, which marks the cluster as OpenShift, and apiServer.
func fakeOpenShiftAPIServer(t *testing.T, apiServer *configv1.APIServer) *httptest.Server {
	t.Helper()

	gv := configv1.GroupVersion.String()
	objects := map[string]any{
		"/api": &metav1.APIVersions{
			TypeMeta: metav1.TypeMeta{Kind: "APIVersions"},
			Versions: []string{"v1"},
		},
		"/apis": &metav1.APIGroupList{
			TypeMeta: metav1.TypeMeta{Kind: "APIGroupList", APIVersion: "v1"},
			Groups: []metav1.APIGroup{{
				Name:             configv1.GroupName,
				Versions:         []metav1.GroupVersionForDiscovery{{GroupVersion: gv, Version: "v1"}},
				PreferredVersion: metav1.GroupVersionForDiscovery{GroupVersion: gv, Version: "v1"},
			}},
		},
		"/apis/" + gv: &metav1.APIResourceList{
			TypeMeta:     metav1.TypeMeta{Kind: "APIResourceList", APIVersion: "v1"},
			GroupVersion: gv,
			APIResources: []metav1.APIResource{
				{Name: "apiservers", Kind: "APIServer", Verbs: metav1.Verbs{"get", "list", "watch"}},
				{Name: "clusteroperators", Kind: "ClusterOperator", Verbs: metav1.Verbs{"get", "list", "watch"}},
			},
		},
		"/apis/" + gv + "/clusteroperators/openshift-apiserver": &configv1.ClusterOperator{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterOperator", APIVersion: gv},
			ObjectMeta: metav1.ObjectMeta{Name: "openshift-apiserver"},
		},
		"/apis/" + gv + "/apiservers/cluster": apiServer,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		obj, ok := objects[r.URL.Path]
		if !ok {
			http.NotFound(w, r)

			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(obj); err != nil {
			t.Errorf("encode %s: %v", r.URL.Path, err)
		}
	}))
	t.Cleanup(srv.Close)

	return srv
}

// TestFetchTLSOptionsAppliesProfileGroups checks that the groups of the
// cluster TLS profile end up in the TLS options of the operator, daemon and
// webhook servers.
func TestFetchTLSOptionsAppliesProfileGroups(t *testing.T) {
	t.Parallel()

	nistOnly := *configv1.TLSProfiles[configv1.TLSProfileIntermediateType]
	nistOnly.Groups = []configv1.TLSGroup{configv1.TLSGroupSecP256r1, configv1.TLSGroupSecP384r1}

	for _, tc := range []struct {
		name       string
		adherence  configv1.TLSAdherencePolicy
		wantCurves []tls.CurveID
	}{
		{
			name:       "strict adherence applies the cluster profile's groups",
			adherence:  configv1.TLSAdherencePolicyStrictAllComponents,
			wantCurves: []tls.CurveID{tls.CurveP256, tls.CurveP384},
		},
		{
			// Without strict adherence the OpenShift Intermediate profile
			// applies, groups included.
			name:      "no opinion applies the Intermediate profile's groups",
			adherence: configv1.TLSAdherencePolicyNoOpinion,
			wantCurves: []tls.CurveID{
				tls.X25519MLKEM768, tls.X25519, tls.CurveP256, tls.CurveP384,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := fakeOpenShiftAPIServer(t, &configv1.APIServer{
				TypeMeta:   metav1.TypeMeta{Kind: "APIServer", APIVersion: configv1.GroupVersion.String()},
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: configv1.APIServerSpec{
					TLSSecurityProfile: &configv1.TLSSecurityProfile{
						Type:   configv1.TLSProfileCustomType,
						Custom: &configv1.CustomTLSProfile{TLSProfileSpec: nistOnly},
					},
					TLSAdherence: tc.adherence,
				},
			})

			tlsOpts, profile, adherence, isOpenShift, err := fetchTLSOptions(
				context.Background(), &rest.Config{Host: srv.URL},
			)
			require.NoError(t, err)
			require.True(t, isOpenShift)
			require.Equal(t, tc.adherence, adherence)
			require.Equal(t, nistOnly.Groups, profile.Groups)

			cfg := &tls.Config{} //nolint:gosec // the options under test set the minimum version
			for _, opt := range tlsOpts {
				opt(cfg)
			}

			require.Equal(t, tc.wantCurves, cfg.CurvePreferences)
			require.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
			require.Equal(t, []string{"http/1.1"}, cfg.NextProtos)
		})
	}
}
