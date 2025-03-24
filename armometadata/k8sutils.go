package armometadata

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"path"
	"slices"
	"strings"

	"github.com/armosec/utils-k8s-go/wlid"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/olvrng/ujson"
	"github.com/spf13/viper"
	rbac "k8s.io/api/rbac/v1"
	"k8s.io/utils/ptr"

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

type Metadata struct {
	Annotations       map[string]string
	Labels            map[string]string
	OwnerReferences   map[string]string
	CreationTimestamp string
	ResourceVersion   string
	Kind              string
	ApiVersion        string
	Namespace         string

	// workloads
	PodSpecLabels map[string]string
	// network policies
	NetworkPolicyPodSelectorMatchLabels map[string]string
	HasEgressRules                      *bool
	HasIngressRules                     *bool

	// services
	ServicePodSelectorMatchLabels map[string]string
	// for role bindings
	Subjects []rbac.Subject
	RoleRef  *rbac.RoleRef
}

// ExtractMetadataFromBytes extracts metadata from the JSON bytes of a Kubernetes object
func ExtractMetadataFromJsonBytes(input []byte) (Metadata, error) {
	// output values
	m := Metadata{
		Annotations:                         map[string]string{},
		Labels:                              map[string]string{},
		OwnerReferences:                     map[string]string{},
		PodSpecLabels:                       map[string]string{},
		NetworkPolicyPodSelectorMatchLabels: map[string]string{},
		ServicePodSelectorMatchLabels:       map[string]string{},
	}

	currentSubjectIndex := -1

	// ujson parsing
	jsonPathElements := make([]string, 0)
	err := ujson.Walk(input, func(level int, key, value []byte) bool {
		if level > 0 {
			jsonPathElements = slices.Replace(jsonPathElements, level-1, len(jsonPathElements), unquote(key))
		}
		jsonPath := strings.Join(jsonPathElements, ".")

		switch {
		case jsonPath == "kind":
			m.Kind = unquote(value)
		case jsonPath == "apiVersion":
			m.ApiVersion = unquote(value)
		case jsonPath == "metadata.namespace":
			m.Namespace = unquote(value)
		case jsonPath == "metadata.creationTimestamp":
			m.CreationTimestamp = unquote(value)
		case jsonPath == "metadata.resourceVersion":
			m.ResourceVersion = unquote(value)
		case strings.HasPrefix(jsonPath, "metadata.annotations."):
			m.Annotations[unquote(key)] = unquote(value)
		case strings.HasPrefix(jsonPath, "metadata.labels."):
			m.Labels[unquote(key)] = unquote(value)
		case strings.HasPrefix(jsonPath, "metadata.ownerReferences.."):
			m.OwnerReferences[unquote(key)] = unquote(value)
		case strings.HasPrefix(jsonPath, "spec.template.metadata.labels."):
			m.PodSpecLabels[unquote(key)] = unquote(value)
		case strings.HasPrefix(jsonPath, "spec.jobTemplate.spec.template.metadata.labels."):
			m.PodSpecLabels[unquote(key)] = unquote(value)
		case strings.HasPrefix(jsonPath, "subjects."):
			parseRoleBindingSubjects(&m, &currentSubjectIndex, key, value)
		case strings.HasPrefix(jsonPath, "roleRef."):
			parseRoleBindingRoleRef(&m, key, value)
		case m.Kind == "Service" && strings.HasPrefix(jsonPath, "spec.selector."):
			m.ServicePodSelectorMatchLabels[unquote(key)] = unquote(value)
		// cilium network policies
		case m.ApiVersion == "cilium.io/v2":
			if strings.HasPrefix(jsonPath, "spec.endpointSelector.matchLabels.") {
				addCiliumMatchLabels(m.NetworkPolicyPodSelectorMatchLabels, key, value)
			} else if jsonPath == "spec.egress." || jsonPath == "spec.egressDeny." {
				setHasEgress(&m)
			} else if jsonPath == "spec.ingress." || jsonPath == "spec.ingressDeny." {
				setHasIngress(&m)
			} else if jsonPath == "specs..ingress" || jsonPath == "specs..ingressDeny" {
				setHasIngress(&m)
			} else if jsonPath == "specs..egress" || jsonPath == "specs..egressDeny" {
				setHasEgress(&m)
			}
		// k8s network policies
		case m.ApiVersion == "networking.k8s.io/v1":
			if strings.HasPrefix(jsonPath, "spec.podSelector.matchLabels.") {
				m.NetworkPolicyPodSelectorMatchLabels[unquote(key)] = unquote(value)
			} else if strings.HasPrefix(jsonPath, "spec.policyTypes.") {
				val := unquote(value)
				if val == "Egress" {
					setHasEgress(&m)
				} else if val == "Ingress" {
					setHasIngress(&m)
				}
			} else if jsonPath == "spec.egress" {
				setHasEgress(&m)
			} else if jsonPath == "spec.ingress" {
				setHasIngress(&m)
			}
		// istio network policies
		case m.ApiVersion == "security.istio.io/v1" && strings.HasPrefix(jsonPath, "spec.selector.matchLabels."):
			m.NetworkPolicyPodSelectorMatchLabels[unquote(key)] = unquote(value)
		// calico
		case m.ApiVersion == "projectcalico.org/v3":
			if jsonPath == "spec.selector" {
				m.NetworkPolicyPodSelectorMatchLabels = ParseCalicoSelector(value)
			} else if strings.HasPrefix(jsonPath, "spec.types.") {
				val := unquote(value)
				if val == "Egress" {
					setHasEgress(&m)
				}
				if val == "Ingress" {
					setHasIngress(&m)
				}
			} else if jsonPath == "spec.egress" {
				setHasEgress(&m)
			} else if jsonPath == "spec.ingress" {
				setHasIngress(&m)
			}
		}
		return true
	})

	return m, err
}

func setHasEgress(m *Metadata) {
	if m.HasEgressRules == nil {
		m.HasEgressRules = ptr.To(true)
	}
}

func setHasIngress(m *Metadata) {
	if m.HasIngressRules == nil {
		m.HasIngressRules = ptr.To(true)
	}
}

func ParseCalicoSelector(value []byte) map[string]string {
	selector := map[string]string{}
	for _, rule := range strings.Split(unquote(value), "&&") {
		s := strings.Split(rule, "==")
		if len(s) != 2 {
			continue
		}
		k := strings.TrimSpace(s[0])
		v := strings.TrimSpace(s[1])
		// strconv.Unquote does not handle single quotes
		if (strings.HasPrefix(v, "'") && strings.HasSuffix(v, "'")) ||
			(strings.HasPrefix(v, "\"") && strings.HasSuffix(v, "\"")) {
			v = v[1 : len(v)-1]
		}
		selector[k] = v
	}
	return selector
}

// addCiliumMatchLabels adds matchLabels from a Cilium EndpointSelector to the given map
// a virtual label is created for each label with a Cilium specific prefix for matching
func addCiliumMatchLabels(matchLabels map[string]string, key, value []byte) {
	k := unquote(key)
	v := unquote(value)
	matchLabels[k] = v
	// check if we have to trim a Cilium specific prefix to k and create a virtual label
	for _, labelSource := range []string{labels.LabelSourceAny, labels.LabelSourceK8s,
		labels.LabelSourceReserved, labels.LabelSourceUnspec} {
		prefix := labelSource + ":"
		if strings.HasPrefix(k, prefix) {
			matchLabels[k[len(prefix):]] = v
		}
	}
}

func unquote(value []byte) string {
	buf, err := ujson.Unquote(value)
	if err != nil {
		return string(value)
	}
	return string(buf)
}

func parseRoleBindingRoleRef(m *Metadata, key, value []byte) {
	if m.RoleRef == nil {
		m.RoleRef = &rbac.RoleRef{}
	}

	k := unquote(key)
	switch k {
	case "apiGroup":
		m.RoleRef.APIGroup = unquote(value)
	case "kind":
		m.RoleRef.Kind = unquote(value)
	case "name":
		m.RoleRef.Name = unquote(value)
	}
}

func parseRoleBindingSubjects(m *Metadata, currentSubjectIndex *int, key, value []byte) {
	v := unquote(value)
	if v == "{" {
		if m.Subjects == nil {
			m.Subjects = make([]rbac.Subject, 0)
		}
		*currentSubjectIndex += 1
		m.Subjects = append(m.Subjects, rbac.Subject{})
		return
	}

	k := unquote(key)
	switch k {
	case "apiGroup":
		m.Subjects[*currentSubjectIndex].APIGroup = v
	case "kind":
		m.Subjects[*currentSubjectIndex].Kind = v
	case "name":
		m.Subjects[*currentSubjectIndex].Name = v
	case "namespace":
		m.Subjects[*currentSubjectIndex].Namespace = v
	}
}
