package armometadata

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io/ioutil"
	"strings"

	"github.com/armosec/utils-k8s-go/wlid"

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

	dat, err := ioutil.ReadFile(configPath)
	if err != nil || len(dat) == 0 {
		return nil, fmt.Errorf("config empty or not found. path: %s", configPath)
	}
	componentConfig := &ClusterConfig{}
	if err := json.Unmarshal(dat, componentConfig); err != nil {
		return componentConfig, fmt.Errorf("failed to read component config, path: %s, reason: %s", configPath, err.Error())
	}
	return componentConfig, nil
}
