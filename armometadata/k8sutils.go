package armometadata

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io/ioutil"
	"os"
	"strings"

	"github.com/armosec/utils-go/boolutils"
	"github.com/armosec/utils-k8s-go/wlid"

	"github.com/golang/glog"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var NamespacesListToIgnore = make([]string, 0)
var KubeNamespaces = []string{metav1.NamespaceSystem, metav1.NamespacePublic}

// NamespacesListToIgnore namespaces to ignore if a pod
func InitNamespacesListToIgnore(caNamespace string) {
	if len(NamespacesListToIgnore) > 0 {
		return
	}
	NamespacesListToIgnore = append(NamespacesListToIgnore, KubeNamespaces...)
	NamespacesListToIgnore = append(NamespacesListToIgnore, caNamespace)
}

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

func hash(s string) string {
	h := fnv.New32a()
	h.Write([]byte(s))
	return fmt.Sprintf("%d", h.Sum32())
}
func GenarateConfigMapName(w string) string {
	name := strings.ToLower(fmt.Sprintf("ca-%s-%s-%s", wlid.GetNamespaceFromWlid(w), wlid.GetKindFromWlid(w), wlid.GetNameFromWlid(w)))
	if len(name) >= 63 {
		name = hash(name)
	}
	return name
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

		return nil, fmt.Errorf("Invalid image info %s", imageTag)
	}

	ImageInfo.Registry = splits[0]
	if len(splits) > 1 {
		ImageInfo.VersionImage = splits[len(splits)-1]
	} else {
		ImageInfo.VersionImage = ""
	}

	return ImageInfo, nil
}

func IsAttached(labels map[string]string) *bool {
	if labels == nil {
		return nil
	}
	if attached, ok := labels[ArmoAttach]; ok {
		if boolutils.StringToBool(attached) {
			return boolutils.BoolPointer(true)
		} else {
			return boolutils.BoolPointer(false)
		}
	}

	// deprecated
	if _, ok := labels[CAAttachLabel]; ok {
		return boolutils.BoolPointer(true)
	}

	// deprecated
	if inject, ok := labels[CAInject]; ok {
		if boolutils.StringToBool(inject) {
			return boolutils.BoolPointer(true)
		}
	}

	// deprecated
	if ignore, ok := labels[CAIgnore]; ok {
		if boolutils.StringToBool(ignore) {
			return boolutils.BoolPointer(false)
		}
	}

	return nil
}

func IsSecretProtected(labels map[string]string) *bool {
	protect := false
	if labels == nil {
		return nil
	}
	if protected, ok := labels[ArmoSecretStatus]; ok {
		if strings.ToLower(protected) == ArmoSecretProtectStatus {
			protect = true
			return &protect
		} else {
			return &protect
		}
	}
	return nil
}

func LoadConfig(configPath string, loadToEnv bool) (*ClusterConfig, error) {
	if configPath == "" {
		configPath = "/etc/config/clusterData.json"
	}

	dat, err := ioutil.ReadFile(configPath)
	if err != nil || len(dat) == 0 {
		return nil, fmt.Errorf("Config empty or not found. path: %s", configPath)
	}
	componentConfig := &ClusterConfig{}
	if err := json.Unmarshal(dat, componentConfig); err != nil {
		return componentConfig, fmt.Errorf("Failed to read component config, path: %s, reason: %s", configPath, err.Error())
	}
	if loadToEnv {
		componentConfig.LoadConfigToEnv()
	}
	return componentConfig, nil
}

func (clusterConfig *ClusterConfig) LoadConfigToEnv() {

	SetEnv("CA_CLUSTER_NAME", clusterConfig.ClusterName)
	SetEnv("CA_CLUSTER_GUID", clusterConfig.ClusterGUID)
	SetEnv("CA_ORACLE_SERVER", clusterConfig.OracleURL)
	SetEnv("CA_CUSTOMER_GUID", clusterConfig.CustomerGUID)
	SetEnv("CA_DASHBOARD_BACKEND", clusterConfig.Dashboard)
	SetEnv("CA_NOTIFICATION_SERVER_WS", clusterConfig.NotificationWSURL)
	SetEnv("CA_NOTIFICATION_SERVER_REST", clusterConfig.NotificationRestURL)
	SetEnv("CA_OCIMAGE_URL", clusterConfig.OciImageURL)
	SetEnv("CA_K8S_REPORT_URL", clusterConfig.EventReceiverWS)
	SetEnv("CA_EVENT_RECEIVER_HTTP", clusterConfig.EventReceiverREST)
	SetEnv("CA_VULNSCAN", clusterConfig.VulnScanURL)
	SetEnv("CA_POSTMAN", clusterConfig.Postman)
	SetEnv("MASTER_NOTIFICATION_SERVER_HOST", clusterConfig.MaserNotificationServer)
	SetEnv("CLAIR_URL", clusterConfig.ClairURL)

}

func SetEnv(key, value string) {
	if e := os.Getenv(key); e == "" {
		if err := os.Setenv(key, value); err != nil {
			glog.Warningf("%s: %s", key, err.Error())
		}
	}
}
