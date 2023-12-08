package wlid

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

// tests wlid parse

func TestSpiffeWLIDToInfoSuccess(t *testing.T) {

	WLID := "wlid://cluster-HipsterShopCluster2/namespace-prod/deployment-cartservice"
	ms, er := SpiffeToSpiffeInfo(WLID)

	if er != nil || ms.Level0 != "HipsterShopCluster2" || ms.Level0Type != "cluster" || ms.Level1 != "prod" || ms.Level1Type != "namespace" ||
		ms.Kind != "deployment" || ms.Name != "cartservice" {
		t.Errorf("TestSpiffeWLIDToInfoSuccess failed to parse %v", WLID)
	}
}

func TestSpiffeSIDInfoSuccess(t *testing.T) {

	SID := "sid://cluster-HipsterShopCluster2/namespace-dev/secret-caregcred"
	ms, er := SpiffeToSpiffeInfo(SID)

	if er != nil || ms.Level0 != "HipsterShopCluster2" || ms.Level0Type != "cluster" || ms.Level1 != "dev" || ms.Level1Type != "namespace" ||
		ms.Kind != "secret" || ms.Name != "caregcred" {
		t.Errorf("TestSpiffeSIDInfoSuccess failed to parse %v", SID)
	}
}

func Test_generateWLID(t *testing.T) {
	type args struct {
		pLevel0 string
		level0  string
		pLevel1 string
		level1  string
		k       string
		name    string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "k8s wlid",
			args: args{
				pLevel0: ClusterWlidPrefix,
				level0:  "HipsterShopCluster2",
				pLevel1: NamespaceWlidPrefix,
				level1:  "prod",
				k:       "Deployment",
				name:    "cartservice",
			},
			want: "wlid://cluster-HipsterShopCluster2/namespace-prod/deployment-cartservice",
		},
		{
			name: "k8s wlid no namespace",
			args: args{
				pLevel0: ClusterWlidPrefix,
				level0:  "HipsterShopCluster2",
				pLevel1: NamespaceWlidPrefix,
				level1:  "",
				k:       "ClusterRoleBinding",
				name:    "cartservice",
			},
			want: "wlid://cluster-HipsterShopCluster2/namespace-/clusterrolebinding-cartservice",
			// FIXME: do we want "wlid://cluster-HipsterShopCluster2/clusterrolebinding-cartservice" instead?
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := generateWLID(tt.args.pLevel0, tt.args.level0, tt.args.pLevel1, tt.args.level1, tt.args.k, tt.args.name)
			assert.Equal(t, tt.want, got)
		})
	}
}
