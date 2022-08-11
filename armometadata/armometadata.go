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
	EventReceiverREST string `json:"eventReceiverREST"`
	EventReceiverWS   string `json:"eventReceiverWS"`
	RootGatewayServer string `json:"rootGatewayServer"`
	CustomerGUID      string `json:"customerGUID"` // Deprecated, use accountID instead
	AccountID         string `json:"accountID"`
	ClusterName       string `json:"clusterName"`
	GatewayWSURL      string `json:"gatewayWSURL"`
	GatewayRestURL    string `json:"gatewayRestURL"`
	KubevulnURL       string `json:"kubevulnURL"`
	KubescapeURL      string `json:"kubescapeURL"`

	// DEPRECATED
	MasterNotificationServer string `json:"masterNotificationServer"`
	Postman                  string `json:"postman"`
	Dashboard                string `json:"dashboard"`
	Portal                   string `json:"portal"`
	ClusterGUID              string `json:"clusterGUID"`
	OciImageURL              string `json:"ociImageURL"`
	NotificationWSURL        string `json:"notificationWSURL"`
	NotificationRestURL      string `json:"notificationRestURL"`
	VulnScanURL              string `json:"vulnScanURL"`
	OracleURL                string `json:"oracleURL"`
	ClairURL                 string `json:"clairURL"`
}

type ImageInfo struct {
	Registry     string `json:"registry"`
	VersionImage string `json:"versionImage"`
}
