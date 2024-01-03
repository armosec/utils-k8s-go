package armometadata

import (
	"reflect"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNewKubernetesResourceParser(t *testing.T) {
	// Test case with valid JSON input
	t.Run("valid input", func(t *testing.T) {
		validInput := []byte(`{
            "metadata": {
                "annotations": {"kubescape.io/status": "active"},
                "labels": {"kubescape.io/workload-name": "example"},
                "ownerReferences": [{"name": "ownerName", "kind": "ownerKind"}],
                "creationTimestamp": "2023-03-15T08:00:00Z",
                "resourceVersion": "12345"
            }
        }`)

		expectedCreationTimestamp, _ := time.Parse(time.RFC3339, "2023-03-15T08:00:00Z")
		expectedParser := &KubernetesObjectParser{
			resourceVersion:        "12345",
			labels:                 map[string]string{"kubescape.io/workload-name": "example"},
			annotations:            map[string]string{"kubescape.io/status": "active"},
			creationStamp:          expectedCreationTimestamp,
			ownerReferences:        metav1.OwnerReference{Name: "ownerName", Kind: "ownerKind"},
			podSelectorMatchLabels: map[string]string{},
		}

		parser, err := NewKubernetesResourceParser(validInput)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if !reflect.DeepEqual(parser, expectedParser) {
			t.Errorf("Expected parser %+v, got %+v", expectedParser, parser)
		}
	})

	// Test case with invalid JSON input
	t.Run("invalid json input", func(t *testing.T) {
		invalidInput := []byte(`invalid json`)

		_, err := NewKubernetesResourceParser(invalidInput)
		if err == nil {
			t.Errorf("Expected error, got nil")
		}
	})

	// Test case with invalid date format
	t.Run("invalid date format", func(t *testing.T) {
		invalidDateInput := []byte(`{
            "metadata": {
                "creationTimestamp": "invalid-date-format"
            }
        }`)

		_, err := NewKubernetesResourceParser(invalidDateInput)
		if err == nil {
			t.Errorf("Expected error parsing date, got nil")
		}
	})

	// Test case with empty JSON
	t.Run("empty json", func(t *testing.T) {
		emptyJSON := []byte(`{}`)

		_, err := NewKubernetesResourceParser(emptyJSON)
		if err == nil {
			t.Errorf("Expected error due to missing metadata, got nil")
		}
	})
}
