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
	ClusterName               string `json:"clusterName"`               // cluster name defined manually or from the cluster context
	AccountID                 string `json:"accountID"`                 // use accountID instead of customerGUID
	EventReceiverRestURL      string `json:"eventReceiverRestURL"`      // event receiver rest url
	EventReceiverWebsocketURL string `json:"eventReceiverWebsocketURL"` // event receiver websocket url
	ApiServerRestURL          string `json:"apiServerRestURL"`          // api server rest url
	RootGatewayURL            string `json:"rootGatewayURL"`            // root gateway url
	GatewayWebsocketURL       string `json:"gatewayWebsocketURL"`       // in-cluster gateway component websocket url
	GatewayRestURL            string `json:"gatewayRestURL"`            // in-cluster gateway component REST API url
	KubevulnURL               string `json:"kubevulnURL"`               // in-cluster kubevuln component REST API url
	KubescapeURL              string `json:"kubescapeURL"`              // in-cluster kubescape component REST API url
	armotypes.InstallationData
}

type ImageInfo struct {
	Registry     string `json:"registry"`
	VersionImage string `json:"versionImage"`
}
