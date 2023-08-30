package armometadata

import (
	"testing"

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
