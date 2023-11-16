package armometadata

import (
	"bytes"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"path"
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

// ExtractMetadataFromBytes extracts metadata from the JSON bytes of a Kubernetes object
func ExtractMetadataFromJsonBytes(input []byte) (error, map[string]string, map[string]string, map[string]string, string, string) {
	// output values
	annotations := map[string]string{}
	labels := map[string]string{}
	ownerReferences := map[string]string{}
	creationTs := ""
	resourceVersion := ""
	// ujson parsing
	var parent string
	err := ujson.Walk(input, func(level int, key, value []byte) bool {
		switch level {
		case 1:
			// skip everything except metadata
			if !bytes.EqualFold(key, []byte(`"metadata"`)) {
				return false
			}
		case 2:
			// read creationTimestamp
			if bytes.EqualFold(key, []byte(`"creationTimestamp"`)) {
				creationTs = unquote(value)
			}
			// read resourceVersion
			if bytes.EqualFold(key, []byte(`"resourceVersion"`)) {
				resourceVersion = unquote(value)
			}
			// record parent for level 3
			parent = unquote(key)
		case 3:
			// read annotations
			if parent == "annotations" {
				annotations[unquote(key)] = unquote(value)
			}
			// read labels
			if parent == "labels" {
				labels[unquote(key)] = unquote(value)
			}
		case 4:
			// read ownerReferences
			if parent == "ownerReferences" {
				ownerReferences[unquote(key)] = unquote(value)
			}

		}
		return true
	})
	return err, annotations, labels, ownerReferences, creationTs, resourceVersion
}

func unquote(value []byte) string {
	buf, err := ujson.Unquote(value)
	if err != nil {
		return string(value)
	}
	return string(buf)
}
