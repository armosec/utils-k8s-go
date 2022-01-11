package armometadata

// labels added to the workload
const (
	ArmoPrefix          string = "armo"
	ArmoAttach          string = ArmoPrefix + ".attach"
	ArmoInitialSecret   string = ArmoPrefix + ".initial"
	ArmoSecretStatus    string = ArmoPrefix + ".secret"
	ArmoCompatibleLabel string = ArmoPrefix + ".compatible"

	ArmoSecretProtectStatus string = "protect"
	ArmoSecretClearStatus   string = "clear"
)

// annotations added to the workload
const (
	ArmoUpdate               string = ArmoPrefix + ".last-update"
	ArmoWlid                 string = ArmoPrefix + ".wlid"
	ArmoSid                  string = ArmoPrefix + ".sid"
	ArmoJobID                string = ArmoPrefix + ".job"
	ArmoJobIDPath            string = ArmoJobID + "/id"
	ArmoJobParentPath        string = ArmoJobID + "/parent"
	ArmoJobActionPath        string = ArmoJobID + "/action"
	ArmoCompatibleAnnotation string = ArmoAttach + "/compatible"
	ArmoReplaceheaders       string = ArmoAttach + "/replaceheaders"
)

const ( // DEPRECATED

	CAAttachLabel string = "cyberarmor"
	Patched       string = "Patched"
	Done          string = "Done"
	Encrypted     string = "Protected"

	CAInjectOld = "injectCyberArmor"

	CAPrefix          string = "cyberarmor"
	CAProtectedSecret string = CAPrefix + ".secret"
	CAInitialSecret   string = CAPrefix + ".initial"
	CAInject          string = CAPrefix + ".inject"
	CAIgnore          string = CAPrefix + ".ignore"
	CAReplaceHeaders  string = CAPrefix + ".removeSecurityHeaders"
)

const ( // DEPRECATED
	CAUpdate string = CAPrefix + ".last-update"
	CAStatus string = CAPrefix + ".status"
	CAWlid   string = CAPrefix + ".wlid"
)

type ClusterConfig struct {
	EventReceiverREST string `json:"eventReceiverREST"`
	EventReceiverWS   string `json:"eventReceiverWS"`
	// depercated - typo
	MaserNotificationServer  string `json:"maserNotificationServer"`
	MasterNotificationServer string `json:"masterNotificationServer"`
	Postman                  string `json:"postman"`
	Dashboard                string `json:"dashboard"`
	Portal                   string `json:"portal"`
	CustomerGUID             string `json:"customerGUID"`
	ClusterGUID              string `json:"clusterGUID"`
	ClusterName              string `json:"clusterName"`
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
