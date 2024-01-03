package armometadata

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	AnnotationKeyStatus       = "kubescape.io/status"
	AnnotationValueIncomplete = "incomplete"

	MetadataKeyResourceVersion = "resourceVersion"
)

type KubernetesObjectParser struct {
	resourceVersion        string
	labels                 map[string]string
	annotations            map[string]string
	creationStamp          time.Time
	ownerReferences        metav1.OwnerReference
	kind                   string
	apiVersion             string
	podSelectorMatchLabels map[string]string
}

func NewKubernetesResourceParser(input []byte) (*KubernetesObjectParser, error) {
	err, annotations, labels, ownerReferences, creationStamp, resourceVersion, kind, apiVersion, podSelectorMatchLabels := ExtractMetadataFromJsonBytes(input)

	if err != nil {
		return nil, err
	}

	creationStampTime, err := time.Parse(time.RFC3339, creationStamp)
	if err != nil {
		return nil, err
	}

	newOwnerReferences := metav1.OwnerReference{}

	if len(ownerReferences) > 0 {
		if value, ok := ownerReferences["name"]; ok {
			newOwnerReferences.Name = value
		}

		if value, ok := ownerReferences["kind"]; ok {
			newOwnerReferences.Kind = value
		}

	}

	newKubernetesResourceParser := &KubernetesObjectParser{}
	newKubernetesResourceParser.resourceVersion = resourceVersion
	newKubernetesResourceParser.labels = labels
	newKubernetesResourceParser.annotations = annotations
	newKubernetesResourceParser.creationStamp = creationStampTime
	newKubernetesResourceParser.ownerReferences = newOwnerReferences
	newKubernetesResourceParser.kind = kind
	newKubernetesResourceParser.apiVersion = apiVersion
	newKubernetesResourceParser.podSelectorMatchLabels = podSelectorMatchLabels

	return newKubernetesResourceParser, nil
}

func (k *KubernetesObjectParser) GetLabels() map[string]string {
	return k.labels
}

func (k *KubernetesObjectParser) GetLabel(label string) string {
	return k.labels[label]
}

func (k *KubernetesObjectParser) GetAnnotation(annotation string) string {
	return k.annotations[annotation]
}

func (k *KubernetesObjectParser) GetCreationTimestamp() time.Time {
	return k.creationStamp
}

func (k *KubernetesObjectParser) GetResourceVersion() string {
	return k.resourceVersion
}

func (k *KubernetesObjectParser) GetOwnerReferencesKind() string {
	return k.ownerReferences.Kind
}

func (k *KubernetesObjectParser) GetOwnerReferencesName() string {
	return k.ownerReferences.Name
}

func (k *KubernetesObjectParser) GetStatus() string {
	return k.annotations[AnnotationKeyStatus]
}

func (k *KubernetesObjectParser) GetKind() string {
	return k.kind
}

func (k *KubernetesObjectParser) GetApiVersion() string {
	return k.apiVersion
}

func (k *KubernetesObjectParser) GetPodSelectorMatchLabels() map[string]string {
	return k.podSelectorMatchLabels
}
