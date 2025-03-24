package armometadata

import (
	"fmt"
	"os"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/aws/smithy-go/ptr"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	rbac "k8s.io/api/rbac/v1"
)

func TestImageTagToImageInfo(t *testing.T) {
	tests := []struct {
		imageTag    string
		expected    *ImageInfo
		expectedErr error
	}{
		{
			imageTag: "myregistry/myimage:latest",
			expected: &ImageInfo{
				Registry:     "myregistry",
				VersionImage: "myimage:latest",
			},
			expectedErr: nil,
		},
		{
			imageTag: "myregistry/myimage",
			expected: &ImageInfo{
				Registry:     "myregistry",
				VersionImage: "myimage",
			},
			expectedErr: nil,
		},
		{
			imageTag: "myimage:latest",
			expected: &ImageInfo{
				Registry:     "",
				VersionImage: "myimage:latest",
			},
			expectedErr: nil,
		},
	}

	for _, test := range tests {
		result, err := ImageTagToImageInfo(test.imageTag)
		if (err == nil && test.expectedErr != nil) || (err != nil && test.expectedErr == nil) {
			t.Errorf("For input %v, expected error %v but got %v", test.imageTag, test.expectedErr, err)
		} else if err != nil && test.expectedErr != nil && err.Error() != test.expectedErr.Error() {
			t.Errorf("For input %v, expected error %v but got %v", test.imageTag, test.expectedErr, err)
		} else if result != nil && test.expected != nil {
			if result.Registry != test.expected.Registry {
				t.Errorf("For input %v, expected registry %v but got %v", test.imageTag, test.expected.Registry, result.Registry)
			}
			if result.VersionImage != test.expected.VersionImage {
				t.Errorf("For input %v, expected versionImage %v but got %v", test.imageTag, test.expected.VersionImage, result.VersionImage)
			}
		}
	}
}

func TestLoadClusterConfig(t *testing.T) {
	type args struct {
		path string
	}
	tests := []struct {
		name    string
		args    args
		want    *ClusterConfig
		wantErr bool
	}{
		{
			name: "TestLoadClusterConfig",
			args: args{
				path: "testdata/clusterData.json",
			},
			want: &ClusterConfig{
				ClusterName:         "gke_armo-test-clusters_us-central1-c_matthias",
				AccountID:           "ed1e102b-13eb-4d25-b078-e10386305b26",
				GatewayWebsocketURL: "gateway:8001",
				GatewayRestURL:      "gateway:8002",
				KubevulnURL:         "kubevuln:8080",
				KubescapeURL:        "kubescape:8080",
				InstallationData: armotypes.InstallationData{
					Namespace:                                 "kubescape",
					ImageVulnerabilitiesScanningEnabled:       ptr.Bool(true),
					PostureScanEnabled:                        ptr.Bool(true),
					OtelCollectorEnabled:                      ptr.Bool(true),
					ClusterProvider:                           "aws",
					ClusterShortName:                          "ccc",
					StorageEnabled:                            ptr.Bool(true),
					RelevantImageVulnerabilitiesConfiguration: "detect",
					RelevantImageVulnerabilitiesEnabled:       ptr.Bool(false),
				},
			},
		},
		{
			name: "empty arg does not cause panic",
			args: args{
				path: "",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()
			got, err := LoadConfig(tt.args.path)

			if tt.wantErr {
				assert.Errorf(t, err, "LoadClusterConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			} else {
				assert.NoErrorf(t, err, "LoadClusterConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestExtractMetadataFromJsonBytes(t *testing.T) {
	tests := []struct {
		name                  string
		wantErr               error
		annotations           map[string]string
		namespace             string
		labels                map[string]string
		ownerReferences       map[string]string
		creationTs            string
		resourceVersion       string
		kind                  string
		apiVersion            string
		netpolMatchLabels     map[string]string
		podSpecLabels         map[string]string
		serviceSelectorLabels map[string]string
		subjects              []rbac.Subject
		roleRef               *rbac.RoleRef
	}{
		{
			name:      "rolebinding",
			namespace: "kubescape",
			annotations: map[string]string{
				"meta.helm.sh/release-name":      "kubescape",
				"meta.helm.sh/release-namespace": "kubescape",
			},
			labels: map[string]string{
				"app":                          "synchronizer",
				"app.kubernetes.io/component":  "synchronizer",
				"app.kubernetes.io/instance":   "kubescape",
				"app.kubernetes.io/managed-by": "Helm",
				"app.kubernetes.io/name":       "kubescape-operator",
				"app.kubernetes.io/version":    "1.26.0",
				"helm.sh/chart":                "kubescape-operator-1.26.0",
				"kubescape.io/ignore":          "true",
				"tier":                         "ks-control-plane",
			},
			ownerReferences:       map[string]string{},
			creationTs:            "",
			resourceVersion:       "1082880679",
			kind:                  "RoleBinding",
			apiVersion:            "rbac.authorization.k8s.io/v1",
			netpolMatchLabels:     map[string]string{},
			podSpecLabels:         map[string]string{},
			serviceSelectorLabels: map[string]string{},
			subjects: []rbac.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      "synchronizer",
					Namespace: "kubescape",
				},
				{
					Kind:      "ServiceAccount",
					Name:      "operator",
					Namespace: "kubescape",
				},
			},
			roleRef: &rbac.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "Role",
				Name:     "synchronizer-role",
			},
		},
		{
			name:        "testcronjob",
			annotations: map[string]string{},
			labels: map[string]string{
				"app":         "backup-system",
				"team":        "platform",
				"cost-center": "platform-123",
			},
			ownerReferences:   map[string]string{},
			creationTs:        "",
			resourceVersion:   "",
			kind:              "CronJob",
			apiVersion:        "batch/v1",
			netpolMatchLabels: map[string]string{},
			podSpecLabels: map[string]string{
				"app":         "backup-job",
				"type":        "scheduled-backup",
				"environment": "prod",
				"component":   "database",
				"version":     "v1.2",
			},
			serviceSelectorLabels: map[string]string{},
		},
		{
			name:      "testdeployment",
			namespace: "default",
			annotations: map[string]string{
				"deployment.kubernetes.io/revision": "1",
			},
			labels: map[string]string{
				"label-key-1": "label-value-1",
			},
			ownerReferences:   map[string]string{},
			creationTs:        "2024-07-18T19:58:44Z",
			resourceVersion:   "6486",
			kind:              "Deployment",
			apiVersion:        "apps/v1",
			netpolMatchLabels: map[string]string{},
			podSpecLabels: map[string]string{
				"app":           "emailservice",
				"pod_label_key": "pod_label_value",
			},
			serviceSelectorLabels: map[string]string{},
		},
		{
			name:                  "networkpolicy_withoutmatching_labels",
			namespace:             "default",
			annotations:           map[string]string{},
			labels:                map[string]string{},
			ownerReferences:       map[string]string{},
			creationTs:            "2023-11-16T10:12:35Z",
			resourceVersion:       "",
			kind:                  "NetworkPolicy",
			apiVersion:            "networking.k8s.io/v1",
			netpolMatchLabels:     map[string]string{},
			podSpecLabels:         map[string]string{},
			serviceSelectorLabels: map[string]string{},
		},
		{
			name:            "networkpolicy_withmatching_labels",
			namespace:       "default",
			annotations:     map[string]string{},
			labels:          map[string]string{},
			ownerReferences: map[string]string{},
			creationTs:      "2023-11-16T10:12:35Z",
			resourceVersion: "",
			kind:            "NetworkPolicy",
			apiVersion:      "networking.k8s.io/v1",
			netpolMatchLabels: map[string]string{
				"role": "frontend",
				"tier": "tier1",
			},
			podSpecLabels:         map[string]string{},
			serviceSelectorLabels: map[string]string{},
		},
		{
			name:      "applicationactivity",
			namespace: "kubescape",
			annotations: map[string]string{
				"kubescape.io/status": "",
				"kubescape.io/wlid":   "wlid://cluster-gke_armo-test-clusters_us-central1-c_danielg/namespace-kubescape/deployment-storage",
			},
			labels: map[string]string{
				"kubescape.io/workload-api-group":   "apps",
				"kubescape.io/workload-api-version": "v1",
				"kubescape.io/workload-kind":        "Deployment",
				"kubescape.io/workload-name":        "storage",
				"kubescape.io/workload-namespace":   "kubescape",
			},
			ownerReferences:       map[string]string{},
			creationTs:            "2023-11-16T10:15:05Z",
			resourceVersion:       "1",
			kind:                  "ApplicationActivity",
			apiVersion:            "spdx.softwarecomposition.kubescape.io/v1beta1",
			netpolMatchLabels:     map[string]string{},
			podSpecLabels:         map[string]string{},
			serviceSelectorLabels: map[string]string{},
		},
		{
			name:      "pod",
			namespace: "kubescape",
			annotations: map[string]string{
				"cni.projectcalico.org/containerID": "d2e279e2ac8fda015bce3d0acf86121f9df8fdf9bf9e028d99d41110ab1b81dc",
				"cni.projectcalico.org/podIP":       "10.0.2.169/32",
				"cni.projectcalico.org/podIPs":      "10.0.2.169/32",
			},
			labels: map[string]string{
				"app":                        "kubescape",
				"app.kubernetes.io/instance": "kubescape",
				"app.kubernetes.io/name":     "kubescape",
				"helm.sh/chart":              "kubescape-operator-1.16.2",
				"helm.sh/revision":           "1",
				"otel":                       "enabled",
				"pod-template-hash":          "549f95c69",
				"tier":                       "ks-control-plane",
			},
			ownerReferences: map[string]string{
				"apiVersion":         "apps/v1",
				"blockOwnerDeletion": "true",
				"controller":         "true",
				"kind":               "ReplicaSet",
				"name":               "kubescape-549f95c69",
				"uid":                "c0ff7d3b-4183-482c-81c5-998faf0b6150",
			},
			creationTs:            "2023-11-16T10:12:35Z",
			resourceVersion:       "59348379",
			kind:                  "Pod",
			apiVersion:            "v1",
			netpolMatchLabels:     map[string]string{},
			podSpecLabels:         map[string]string{},
			serviceSelectorLabels: map[string]string{},
		},
		{
			name:      "sbom",
			namespace: "kubescape",
			annotations: map[string]string{
				"kubescape.io/image-id": "quay.io/kubescape/kubescape@sha256:608b85d3de51caad84a2bfe089ec2c5dbc192dbe9dc319849834bf0e678e0523",
				"kubescape.io/status":   "",
			},
			labels: map[string]string{
				"kubescape.io/image-id":   "quay-io-kubescape-kubescape-sha256-608b85d3de51caad84a2bfe089ec",
				"kubescape.io/image-name": "quay-io-kubescape-kubescape",
			},
			ownerReferences:       map[string]string{},
			creationTs:            "2023-11-16T10:13:40Z",
			resourceVersion:       "1",
			kind:                  "SBOMSPDXv2p3",
			apiVersion:            "spdx.softwarecomposition.kubescape.io/v1beta1",
			netpolMatchLabels:     map[string]string{},
			podSpecLabels:         map[string]string{},
			serviceSelectorLabels: map[string]string{},
		},
		{
			name:                  "caliconetworkpolicy",
			namespace:             "production",
			annotations:           map[string]string{},
			labels:                map[string]string{},
			ownerReferences:       map[string]string{},
			kind:                  "NetworkPolicy",
			apiVersion:            "projectcalico.org/v3",
			netpolMatchLabels:     map[string]string{"role": "database"},
			podSpecLabels:         map[string]string{},
			serviceSelectorLabels: map[string]string{},
		},
		{
			name:                  "ciliumnetworkpolicy",
			namespace:             "",
			annotations:           map[string]string{},
			labels:                map[string]string{},
			ownerReferences:       map[string]string{},
			kind:                  "CiliumNetworkPolicy",
			apiVersion:            "cilium.io/v2",
			netpolMatchLabels:     map[string]string{"any:app": "frontend", "app": "frontend"},
			podSpecLabels:         map[string]string{},
			serviceSelectorLabels: map[string]string{},
		},
		{
			name:                  "istionetworkpolicy",
			namespace:             "ns1",
			annotations:           map[string]string{},
			labels:                map[string]string{},
			ownerReferences:       map[string]string{},
			kind:                  "AuthorizationPolicy",
			apiVersion:            "security.istio.io/v1",
			netpolMatchLabels:     map[string]string{"app": "myapi"},
			podSpecLabels:         map[string]string{},
			serviceSelectorLabels: map[string]string{},
		},
		{
			name:      "service",
			namespace: "kubescape",
			annotations: map[string]string{
				"meta.helm.sh/release-name":      "kubescape",
				"meta.helm.sh/release-namespace": "kubescape",
			},
			creationTs:      "2024-12-15T06:13:34Z",
			resourceVersion: "1082880680",
			labels: map[string]string{
				"app":                       "kubescape",
				"app.kubernetes.io/name":    "kubescape-operator",
				"app.kubernetes.io/version": "1.26.0",
				"helm.sh/chart":             "kubescape-operator-1.26.0",
				"kubescape.io/ignore":       "true",
				"tier":                      "ks-control-plane",
			},
			ownerReferences:   map[string]string{},
			kind:              "Service",
			apiVersion:        "v1",
			netpolMatchLabels: map[string]string{},
			podSpecLabels:     map[string]string{},
			serviceSelectorLabels: map[string]string{
				"app.kubernetes.io/component": "kubescape",
				"app.kubernetes.io/instance":  "kubescape",
				"app.kubernetes.io/name":      "kubescape-operator",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input, err := os.ReadFile(fmt.Sprintf("testdata/%s.json", tt.name))
			assert.NoError(t, err)
			m, err := ExtractMetadataFromJsonBytes(input)
			assert.Equal(t, tt.wantErr, err)
			assert.Equal(t, tt.annotations, m.Annotations)
			assert.Equal(t, tt.labels, m.Labels)
			assert.Equal(t, tt.ownerReferences, m.OwnerReferences)
			assert.Equal(t, tt.creationTs, m.CreationTimestamp)
			assert.Equal(t, tt.resourceVersion, m.ResourceVersion)
			assert.Equal(t, tt.kind, m.Kind)
			assert.Equal(t, tt.apiVersion, m.ApiVersion)
			assert.Equal(t, tt.netpolMatchLabels, m.NetworkPolicyPodSelectorMatchLabels)
			assert.Equal(t, tt.podSpecLabels, m.PodSpecLabels)
			assert.Equal(t, tt.serviceSelectorLabels, m.ServicePodSelectorMatchLabels)
			assert.Equal(t, tt.namespace, m.Namespace)
			assert.Equal(t, tt.roleRef, m.RoleRef)
			assert.Equal(t, tt.subjects, m.Subjects)
		})
	}
}

func BenchmarkExtractMetadataFromJsonBytes(b *testing.B) {
	input, err := os.ReadFile("testdata/applicationactivity.json")
	assert.NoError(b, err)
	for i := 0; i < b.N; i++ {
		_, _ = ExtractMetadataFromJsonBytes(input)
	}
}

func Test_parseCalicoSelector(t *testing.T) {
	tests := []struct {
		name  string
		value []byte
		want  map[string]string
	}{
		{
			name:  "empty",
			value: []byte(""),
			want:  map[string]string{},
		},
		{
			name:  "single",
			value: []byte(`"role == 'database'"`),
			want:  map[string]string{"role": "database"},
		},
		{
			name:  "multiple",
			value: []byte(`"role == 'database' && tier == 'frontend'"`),
			want:  map[string]string{"role": "database", "tier": "frontend"},
		},
		{
			name:  "real",
			value: []byte(`"app.kubernetes.io/instance == 'kubescape' && app.kubernetes.io/name == 'operator' && tier == 'ks-control-plane'"`),
			want:  map[string]string{"app.kubernetes.io/instance": "kubescape", "app.kubernetes.io/name": "operator", "tier": "ks-control-plane"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, ParseCalicoSelector(tt.value), "ParseCalicoSelector(%v)", tt.value)
		})
	}
}

func TestExtractMetadataFromJsonBytesForNetworkPolicies(t *testing.T) {
	tests := []struct {
		filename        string
		hasIngressRules *bool
		hasEgressRules  *bool
	}{
		{
			filename:       "testdata/networkpolicies/calico/egress-only.json",
			hasEgressRules: ptr.Bool(true),
		},
		{
			filename: "testdata/networkpolicies/calico/empty.json",
		},
		{
			filename:        "testdata/networkpolicies/calico/ingress-egress.json",
			hasIngressRules: ptr.Bool(true),
			hasEgressRules:  ptr.Bool(true),
		},
		{
			filename:        "testdata/networkpolicies/calico/ingress-only.json",
			hasIngressRules: ptr.Bool(true),
		},
		{
			filename:        "testdata/networkpolicies/cilium/multi-rule-cilium.json",
			hasIngressRules: ptr.Bool(true),
			hasEgressRules:  ptr.Bool(true),
		},
		{
			filename:        "testdata/networkpolicies/cilium/ingress-egress-cilium.json",
			hasIngressRules: ptr.Bool(true),
			hasEgressRules:  ptr.Bool(true),
		},
		{
			filename:        "testdata/networkpolicies/cilium/ingress-only-cilium.json",
			hasIngressRules: ptr.Bool(true),
		},
		{
			filename:        "testdata/networkpolicies/cilium/ingress-deny-cilium.json",
			hasIngressRules: ptr.Bool(true),
		},
		{
			filename: "testdata/networkpolicies/cilium/empty-cilium.json",
		},
		{
			filename:       "testdata/networkpolicies/cilium/egress-only-cilium.json",
			hasEgressRules: ptr.Bool(true),
		},
		{
			filename:       "testdata/networkpolicies/cilium/egress-deny-cilium.json",
			hasEgressRules: ptr.Bool(true),
		},
		{
			filename:        "testdata/networkpolicies/k8s/k8s-ingress-only.json",
			hasIngressRules: ptr.Bool(true),
		},
		{
			filename:       "testdata/networkpolicies/k8s/k8s-egress-only.json",
			hasEgressRules: ptr.Bool(true),
		},
		{
			filename:        "testdata/networkpolicies/k8s/k8s-ingress-egress.json",
			hasIngressRules: ptr.Bool(true),
			hasEgressRules:  ptr.Bool(true),
		},
		{
			filename: "testdata/networkpolicies/k8s/k8s-empty.json",
		},
		{
			filename:        "testdata/networkpolicies/k8s/k8s-ingress-no-policy-type.json",
			hasIngressRules: ptr.Bool(true),
		},
		{
			filename:       "testdata/networkpolicies/k8s/k8s-egress-no-policy-type.json",
			hasEgressRules: ptr.Bool(true),
		},
		{
			filename: "testdata/networkpolicies/k8s/k8s-both-no-policy-type.json",

			hasIngressRules: ptr.Bool(true),
			hasEgressRules:  ptr.Bool(true),
		},
	}

	for _, tc := range tests {
		t.Run(tc.filename, func(t *testing.T) {

			var err error
			networkPolicyBytes, err := os.ReadFile(tc.filename)
			if err != nil {
				t.Fatalf("failed to convert YAML to JSON: %v", err)
			}

			result, err := ExtractMetadataFromJsonBytes(networkPolicyBytes)

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			assert.Equal(t, tc.hasIngressRules, result.HasIngressRules)
			assert.Equal(t, tc.hasEgressRules, result.HasEgressRules)
		})
	}
}
