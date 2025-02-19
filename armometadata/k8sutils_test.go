package armometadata

import (
	"fmt"
	"os"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
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
					ImageVulnerabilitiesScanningEnabled:       BoolPtr(true),
					PostureScanEnabled:                        BoolPtr(true),
					OtelCollectorEnabled:                      BoolPtr(true),
					ClusterProvider:                           "aws",
					ClusterShortName:                          "ccc",
					StorageEnabled:                            BoolPtr(true),
					RelevantImageVulnerabilitiesConfiguration: "detect",
					RelevantImageVulnerabilitiesEnabled:       BoolPtr(false),
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

func BoolPtr(b bool) *bool {
	return &b
}

func TestExtractMetadataFromJsonBytes(t *testing.T) {
	tests := []struct {
		name                   string
		wantErr                error
		annotations            map[string]string
		labels                 map[string]string
		ownerReferences        map[string]string
		creationTs             string
		resourceVersion        string
		kind                   string
		apiVersion             string
		podSelectorMatchLabels map[string]string
		podSpecLabels          map[string]string
	}{
		{
			name:        "testcronjob",
			annotations: map[string]string{},
			labels: map[string]string{
				"app":         "backup-system",
				"team":        "platform",
				"cost-center": "platform-123",
			},
			ownerReferences:        map[string]string{},
			creationTs:             "",
			resourceVersion:        "",
			kind:                   "CronJob",
			apiVersion:             "batch/v1",
			podSelectorMatchLabels: map[string]string{},
			podSpecLabels: map[string]string{
				"app":         "backup-job",
				"type":        "scheduled-backup",
				"environment": "prod",
				"component":   "database",
				"version":     "v1.2",
			},
		},
		{
			name: "testdeployment",
			annotations: map[string]string{
				"deployment.kubernetes.io/revision": "1",
			},
			labels: map[string]string{
				"label-key-1": "label-value-1",
			},
			ownerReferences:        map[string]string{},
			creationTs:             "2024-07-18T19:58:44Z",
			resourceVersion:        "6486",
			kind:                   "Deployment",
			apiVersion:             "apps/v1",
			podSelectorMatchLabels: map[string]string{},
			podSpecLabels: map[string]string{
				"app":           "emailservice",
				"pod_label_key": "pod_label_value",
			},
		},
		{
			name:                   "networkpolicy_withoutmatching_labels",
			annotations:            map[string]string{},
			labels:                 map[string]string{},
			ownerReferences:        map[string]string{},
			creationTs:             "2023-11-16T10:12:35Z",
			resourceVersion:        "",
			kind:                   "NetworkPolicy",
			apiVersion:             "networking.k8s.io/v1",
			podSelectorMatchLabels: map[string]string{},
			podSpecLabels:          map[string]string{},
		},
		{
			name:            "networkpolicy_withmatching_labels",
			annotations:     map[string]string{},
			labels:          map[string]string{},
			ownerReferences: map[string]string{},
			creationTs:      "2023-11-16T10:12:35Z",
			resourceVersion: "",
			kind:            "NetworkPolicy",
			apiVersion:      "networking.k8s.io/v1",
			podSelectorMatchLabels: map[string]string{
				"role": "frontend",
				"tier": "tier1",
			},
			podSpecLabels: map[string]string{},
		},
		{
			name: "applicationactivity",
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
			ownerReferences:        map[string]string{},
			creationTs:             "2023-11-16T10:15:05Z",
			resourceVersion:        "1",
			kind:                   "ApplicationActivity",
			apiVersion:             "spdx.softwarecomposition.kubescape.io/v1beta1",
			podSelectorMatchLabels: map[string]string{},
			podSpecLabels:          map[string]string{},
		},
		{
			name: "pod",
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
			creationTs:             "2023-11-16T10:12:35Z",
			resourceVersion:        "59348379",
			kind:                   "Pod",
			apiVersion:             "v1",
			podSelectorMatchLabels: map[string]string{},
			podSpecLabels:          map[string]string{},
		},
		{
			name: "sbom",
			annotations: map[string]string{
				"kubescape.io/image-id": "quay.io/kubescape/kubescape@sha256:608b85d3de51caad84a2bfe089ec2c5dbc192dbe9dc319849834bf0e678e0523",
				"kubescape.io/status":   "",
			},
			labels: map[string]string{
				"kubescape.io/image-id":   "quay-io-kubescape-kubescape-sha256-608b85d3de51caad84a2bfe089ec",
				"kubescape.io/image-name": "quay-io-kubescape-kubescape",
			},
			ownerReferences:        map[string]string{},
			creationTs:             "2023-11-16T10:13:40Z",
			resourceVersion:        "1",
			kind:                   "SBOMSPDXv2p3",
			apiVersion:             "spdx.softwarecomposition.kubescape.io/v1beta1",
			podSelectorMatchLabels: map[string]string{},
			podSpecLabels:          map[string]string{},
		},
		{
			name:                   "caliconetworkpolicy",
			annotations:            map[string]string{},
			labels:                 map[string]string{},
			ownerReferences:        map[string]string{},
			kind:                   "NetworkPolicy",
			apiVersion:             "projectcalico.org/v3",
			podSelectorMatchLabels: map[string]string{"role": "database"},
			podSpecLabels:          map[string]string{},
		},
		{
			name:                   "ciliumnetworkpolicy",
			annotations:            map[string]string{},
			labels:                 map[string]string{},
			ownerReferences:        map[string]string{},
			kind:                   "CiliumNetworkPolicy",
			apiVersion:             "cilium.io/v2",
			podSelectorMatchLabels: map[string]string{"any:app": "frontend", "app": "frontend"},
			podSpecLabels:          map[string]string{},
		},
		{
			name:                   "istionetworkpolicy",
			annotations:            map[string]string{},
			labels:                 map[string]string{},
			ownerReferences:        map[string]string{},
			kind:                   "AuthorizationPolicy",
			apiVersion:             "security.istio.io/v1",
			podSelectorMatchLabels: map[string]string{"app": "myapi"},
			podSpecLabels:          map[string]string{},
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
			assert.Equal(t, tt.podSelectorMatchLabels, m.PodSelectorMatchLabels)
			assert.Equal(t, tt.podSpecLabels, m.PodSpecLabels)
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
