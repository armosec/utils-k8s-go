package armometadata

import (
	"fmt"
	"testing"
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
				VersionImage: "latest",
			},
			expectedErr: nil,
		},
		{
			imageTag: "myregistry/myimage",
			expected: &ImageInfo{
				Registry:     "myregistry",
				VersionImage: "",
			},
			expectedErr: nil,
		},
		{
			imageTag:    "myimage:latest",
			expected:    nil,
			expectedErr: fmt.Errorf("invalid image info myimage:latest"),
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
