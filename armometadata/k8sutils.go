package armometadata

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"path"
	"slices"
	"strings"

	"github.com/armosec/utils-k8s-go/wlid"
	"github.com/olvrng/ujson"
	"github.com/spf13/viper"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var NamespacesListToIgnore = make([]string, 0)
var KubeNamespaces = []string{metav1.NamespaceSystem, metav1.NamespacePublic}

var DefaultConfigPath = "/etc/config/clusterData.json"

func IfIgnoreNamespace(ns string) bool {
	for i := range NamespacesListToIgnore {
		if NamespacesListToIgnore[i] == ns {
			return true
		}
	}
	return false
}

func IfKubeNamespace(ns string) bool {
	for i := range KubeNamespaces {
		if NamespacesListToIgnore[i] == ns {
			return true
		}
	}
	return false
}

func GenerateConfigMapName(w string) string {
	name := strings.ToLower(fmt.Sprintf("ks-%s-%s-%s", wlid.GetNamespaceFromWlid(w), wlid.GetKindFromWlid(w), wlid.GetNameFromWlid(w)))
	if len(name) >= 63 {
		name = hash(name)
	}
	return name
}
func hash(s string) string {
	h := fnv.New32a()
	h.Write([]byte(s))
	return fmt.Sprintf("%d", h.Sum32())
}

func ImageTagToImageInfo(imageTag string) (*ImageInfo, error) {
	ImageInfo := &ImageInfo{}
	spDelimiter := "/"
	pos := strings.Index(imageTag, spDelimiter)
	if pos < 0 {
		ImageInfo.Registry = ""
		ImageInfo.VersionImage = imageTag
		return ImageInfo, nil
	}

	splits := strings.Split(imageTag, spDelimiter)
	if len(splits) == 0 {

		return nil, fmt.Errorf("invalid image info %s", imageTag)
	}

	ImageInfo.Registry = splits[0]
	if len(splits) > 1 {
		ImageInfo.VersionImage = splits[len(splits)-1]
	} else {
		ImageInfo.VersionImage = ""
	}

	return ImageInfo, nil
}

// LoadConfig load config from file
func LoadConfig(configPath string) (*ClusterConfig, error) {
	if configPath == "" {
		configPath = DefaultConfigPath
	}

	viper.AddConfigPath(path.Dir(configPath))
	viper.SetConfigName(path.Base(configPath))
	viper.SetConfigType(path.Ext(configPath)[1:])

	viper.AutomaticEnv()

	config := &ClusterConfig{}

	err := viper.ReadInConfig()
	if err != nil {
		return config, err
	}

	res, err := json.Marshal(viper.AllSettings())
	if err != nil {
		return config, err
	}

	err = json.Unmarshal(res, &config)
	return config, err
}

type Metadata struct {
	Annotations            map[string]string
	Labels                 map[string]string
	OwnerReferences        map[string]string
	CreationTimestamp      string
	ResourceVersion        string
	Kind                   string
	ApiVersion             string
	PodSelectorMatchLabels map[string]string
}

// ExtractMetadataFromBytes extracts metadata from the JSON bytes of a Kubernetes object
func ExtractMetadataFromJsonBytes(input []byte) (Metadata, error) {
	// output values
	m := Metadata{
		Annotations:            map[string]string{},
		Labels:                 map[string]string{},
		OwnerReferences:        map[string]string{},
		PodSelectorMatchLabels: map[string]string{},
	}
	// ujson parsing
	jsonPathElements := make([]string, 0)
	err := ujson.Walk(input, func(level int, key, value []byte) bool {
		if level > 0 {
			jsonPathElements = slices.Replace(jsonPathElements, level-1, len(jsonPathElements), unquote(key))
		}
		jsonPath := strings.Join(jsonPathElements, ".")
		switch {
		case jsonPath == "kind":
			m.Kind = unquote(value)
		case jsonPath == "apiVersion":
			m.ApiVersion = unquote(value)
		case jsonPath == "metadata.creationTimestamp":
			m.CreationTimestamp = unquote(value)
		case jsonPath == "metadata.resourceVersion":
			m.ResourceVersion = unquote(value)
		case strings.HasPrefix(jsonPath, "metadata.annotations."):
			m.Annotations[unquote(key)] = unquote(value)
		case strings.HasPrefix(jsonPath, "metadata.labels."):
			m.Labels[unquote(key)] = unquote(value)
		case strings.HasPrefix(jsonPath, "metadata.ownerReferences.."):
			m.OwnerReferences[unquote(key)] = unquote(value)
		case m.ApiVersion == "cilium.io/v2" && strings.HasPrefix(jsonPath, "spec.endpointSelector.matchLabels."):
			m.PodSelectorMatchLabels[unquote(key)] = unquote(value)
		case m.ApiVersion == "networking.k8s.io/v1" && strings.HasPrefix(jsonPath, "spec.podSelector.matchLabels."):
			m.PodSelectorMatchLabels[unquote(key)] = unquote(value)
		case m.ApiVersion == "security.istio.io/v1" && strings.HasPrefix(jsonPath, "spec.selector.matchLabels."):
			m.PodSelectorMatchLabels[unquote(key)] = unquote(value)
		case m.ApiVersion == "projectcalico.org/v3" && jsonPath == "spec.selector":
			m.PodSelectorMatchLabels = parseCalicoSelector(value)
		}
		return true
	})
	return m, err
}

func parseCalicoSelector(value []byte) map[string]string {
	selector := map[string]string{}
	for _, rule := range strings.Split(unquote(value), "&&") {
		s := strings.Split(rule, "==")
		if len(s) != 2 {
			continue
		}
		k := strings.TrimSpace(s[0])
		v := strings.TrimSpace(s[1])
		// strconv.Unquote does not handle single quotes
		if (strings.HasPrefix(v, "'") && strings.HasSuffix(v, "'")) ||
			(strings.HasPrefix(v, "\"") && strings.HasSuffix(v, "\"")) {
			v = v[1 : len(v)-1]
		}
		selector[k] = v
	}
	return selector
}

func unquote(value []byte) string {
	buf, err := ujson.Unquote(value)
	if err != nil {
		return string(value)
	}
	return string(buf)
}
