package armometadata

import (
	"github.com/armosec/armoapi-go/armotypes"
)

// annotations added to the workload
const (
	ArmoPrefix        string = "armo"
	ArmoUpdate        string = ArmoPrefix + ".last-update"
	ArmoWlid          string = ArmoPrefix + ".wlid"
	ArmoSid           string = ArmoPrefix + ".sid"
	ArmoJobID         string = ArmoPrefix + ".job"
	ArmoJobIDPath     string = ArmoJobID + "/id"
	ArmoJobParentPath string = ArmoJobID + "/parent"
	ArmoJobActionPath string = ArmoJobID + "/action"
)

type ClusterConfig struct {
	ClusterName           string `json:"clusterName"`         // cluster name defined manually or from the cluster context
	AccountID             string `json:"accountID"`           // use accountID instead of customerGUID
	GatewayWebsocketURL   string `json:"gatewayWebsocketURL"` // in-cluster gateway component websocket url
	GatewayRestURL        string `json:"gatewayRestURL"`      // in-cluster gateway component REST API url
	KubevulnURL           string `json:"kubevulnURL"`         // in-cluster kubevuln component REST API url
	KubescapeURL          string `json:"kubescapeURL"`        // in-cluster kubescape component REST API url
	ContinuousPostureScan bool   `json:"continuousPostureScan"`
	armotypes.InstallationData
}

type ImageInfo struct {
	Registry     string `json:"registry"`
	VersionImage string `json:"versionImage"`
}
