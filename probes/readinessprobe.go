package probes

import (
	"fmt"
	"net/http"
)

// paths cannot be changed
const (
	ReadinessPath = "readiness"
	livenessPath  = "liveness"
)

// port can be changed
var (
	ReadinessPort = "8000"
)

// InitReadinessV1 initialize readiness handler. Change the port by changing the global variable. The paths cannot change.
func InitReadinessV1(isReadinessReady *bool) {
	http.HandleFunc(fmt.Sprintf("/v1/%s", ReadinessPath), func(w http.ResponseWriter, _ *http.Request) {
		if *isReadinessReady {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	},
	)
	http.HandleFunc(fmt.Sprintf("/v1/%s", livenessPath), func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	},
	)
	http.ListenAndServe(":8000", nil)
}
