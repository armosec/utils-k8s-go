package armometadata

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
	AccountID         string `json:"accountID"` // use accountID instead of customerGUID
	EventReceiverREST string `json:"eventReceiverREST"`
	EventReceiverWS   string `json:"eventReceiverWS"`
	RootGatewayServer string `json:"rootGatewayServer"`
	ClusterName       string `json:"clusterName"`
	GatewayWSURL      string `json:"gatewayWSURL"`
	GatewayRestURL    string `json:"gatewayRestURL"`
	KubevulnURL       string `json:"kubevulnURL"`
	KubescapeURL      string `json:"kubescapeURL"`
}

type ImageInfo struct {
	Registry     string `json:"registry"`
	VersionImage string `json:"versionImage"`
}
