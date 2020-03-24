package kuberuntime

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"k8s.io/klog"

	v1 "k8s.io/api/core/v1"
)

// All the BS below are just for research purpose. Hacks could be turned into real code
// later but now we need to get the system up and running.

const (
	metadata_server = "http://mds:19851"
)

var (
	safe_client *http.Client
)

func init() {
	tr := &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: true,
	}

	safe_client = &http.Client{Transport: tr}
}

func (m *kubeGenericRuntimeManager) helper(pod *v1.Pod) {
}

func getMyIP() net.IP {
	return net.ParseIP("192.168.0.1")
}

type SafeRequest struct {
	Principal   string   `json="principal"`
	OtherValues []string `json="otherValues"`
}

func encode(v interface{}) (*bytes.Buffer, error) {

	buf := bytes.NewBuffer(nil)
	encoder := json.NewEncoder(buf)
	if err := encoder.Encode(v); err != nil {
		return nil, err
	}
	return buf, nil
}

func encodeSafeRequest(principal string, otherValues ...string) (io.Reader, error) {
	v := SafeRequest{
		Principal:   principal,
		OtherValues: otherValues,
	}
	return encode(&v)
}

func formatSafeList(vals []string) string {
	return fmt.Sprintf("[\"%s\"]", strings.Join(vals, ","))
}

func safeAPI(method string, principal string, otherValues ...string) {
	url := fmt.Sprintf("%s/%s", metadata_server, method)
	reqbuf, err := encodeSafeRequest(principal, otherValues...)
	if err != nil {
		klog.Errorf("Encoding safe request %v, %v, %v", principal, otherValues, err)
		return
	}

	resp, err := safe_client.Post(url, "application/json", reqbuf)
	if err != nil {
		klog.Errorf("Sending safe request: %v, %v, [%v] %v", method, principal, otherValues, err)
		return
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		klog.Errorf("Reading safe response: %v, %v, [%v] %v", method, principal, otherValues, err)
		return
	}

	klog.Infof("Ydev safe request: %v, %v, [%v], resp: %v", method, principal, otherValues, string(data))
}

type latteConfigPair struct {
	key string
	val string
}

type latteConfigs []latteConfigPair

// Generate configurations from string
func (configs latteConfigs) Len() int {
	return len(configs)
}

func (configs latteConfigs) Less(i, j int) bool {
	return configs[i].key < configs[j].key
}

func (configs latteConfigs) Swap(i, j int) {
	configs[i], configs[j] = configs[j], configs[i]
}

func (configs latteConfigs) String() string {
	sort.Sort(&configs)
	// generate list?
	kvs := make([]string, 0, len(configs))
	for _, c := range configs {
		kvs = append(kvs, fmt.Sprintf("[\"%s\",\"%s\"]", c.key, c.val))
	}
	return fmt.Sprintf("%s", strings.Join(kvs, ","))
}

func getSafeContainerName(pod *v1.Pod, container *v1.Container, init bool) string {
	uid := string(pod.UID)
	var typeName string
	if init {
		typeName = "init"
	} else {
		typeName = "default"
	}
	return fmt.Sprintf("%s/%s/%s", uid, typeName, container.Name)
}

func (m *kubeGenericRuntimeManager) attestContainer(principal string, uid string, ctnName string, container *v1.Container,
	configMaps, volToConfigMaps map[string]*v1.ConfigMap) {

	// generate Container specific configurations
	// each container has an Image and a property list. The property list needs special resolve if it
	// starts with "-", or if it can be resolved to be valid yaml, json, or property list.
	configPairs := make(latteConfigs, 0, 64)

	workdir := container.WorkingDir
	if workdir == "" {
		workdir = "/"
	}
	configPairs = append(configPairs,
		latteConfigPair{key: "pwd", val: workdir},
		latteConfigPair{key: "tty", val: strconv.FormatBool(container.TTY)},
		latteConfigPair{key: "stdin", val: strconv.FormatBool(container.Stdin)})

	for _, port := range container.Ports {
		configPairs = append(configPairs, latteConfigPair{
			key: fmt.Sprintf("%s-port-%d-mapping", strings.ToLower(string(port.Protocol)), port.ContainerPort),
			val: string(port.HostPort)})
	}
	for _, env := range container.Env {
		configPairs = append(configPairs, latteConfigPair{
			key: fmt.Sprintf("%s", env.Name),
			val: env.Value})
	}
	for i, arg := range container.Command {
		configPairs = append(configPairs, latteConfigPair{
			key: fmt.Sprintf("arg%d", i),
			val: arg})
	}
	for i, arg := range container.Args {
		configPairs = append(configPairs, latteConfigPair{
			key: fmt.Sprintf("arg%d", i+len(container.Command)),
			val: arg})
	}
	// parse EnvFrom
	// parse ConfigMapVolumeSource
	ctnConfigString := configPairs.String()
	safeAPI("postInstanceConfig", principal, uid, ctnName, fmt.Sprintf("[%s, %s]", container.Image, ctnConfigString))
}

func (m *kubeGenericRuntimeManager) attest(pod *v1.Pod, podIP string) {
	klog.Infof("attesting pod %s on %s", pod.Name, podIP)

	pod_bytes, err := encode(pod)
	if err != nil {
		klog.Errorf("Can not encode pod object: {}", err)
		return
	}
	myip := getMyIP()

	uid := string(pod.UID)
	hash := sha256.Sum256(pod_bytes.Bytes())
	imageRef := base64.RawStdEncoding.EncodeToString(hash[:])
	principal := fmt.Sprintf("%s:6431", myip.String())
	safeAPI("postInstance", principal, uid, imageRef, fmt.Sprintf("%s:1-65535", podIP))

	allConfigMaps := make(map[string]*v1.ConfigMap)
	configMapVolumes := make(map[string]*v1.ConfigMap)
	for _, v := range pod.Spec.Volumes {
		if v.VolumeSource.ConfigMap != nil {
			klog.Info("Processing ConfigMap ", v.Name)
			if _, ok := allConfigMaps[v.VolumeSource.ConfigMap.Name]; !ok {
				configMap, err := m.runtimeHelper.GetConfigMap(pod.Namespace, v.VolumeSource.ConfigMap.Name)
				if err != nil {
					klog.Infof("Ydev: err getting configmap %s, %s: %s", pod.Namespace, v.VolumeSource.ConfigMap.Name, err)
					continue
				}
				allConfigMaps[v.VolumeSource.ConfigMap.Name] = configMap
				configMapVolumes[v.Name] = configMap
			}
		}
	}

	configPairs := latteConfigs{
		latteConfigPair{key: "namespace", val: pod.Namespace},
		latteConfigPair{key: "service_account", val: pod.Spec.ServiceAccountName},
	}
	if pubkey, ok := pod.Annotations["latte.pubkey"]; ok {
		configPairs = append(configPairs, latteConfigPair{key: "latte.key", val: pubkey})
	}
	if name, ok := pod.Annotations["latte.user"]; ok {
		configPairs = append(configPairs, latteConfigPair{key: "latte.user", val: name})
	}

	if creator, ok := pod.Annotations["latte.creator"]; ok {
		configPairs = append(configPairs, latteConfigPair{key: "latte.creator", val: creator})
	}
	podConfigString := configPairs.String()
	safeAPI("postInstanceConfig", principal, uid, "global", fmt.Sprintf("[%s]", podConfigString))

	containerNames := make([]string, 0)
	for _, container := range pod.Spec.Containers {
		ctnName := getSafeContainerName(pod, &container, false)
		m.attestContainer(principal, uid, ctnName, &container, allConfigMaps, configMapVolumes)
		containerNames = append(containerNames, ctnName)
	}

	for _, container := range pod.Spec.InitContainers {
		// fixme: image should not be a name. Should be its sha256 hash. Need to query docker.
		ctnName := getSafeContainerName(pod, &container, true)
		m.attestContainer(principal, uid, ctnName, &container, allConfigMaps, configMapVolumes)
		containerNames = append(containerNames, ctnName)
	}
	safeAPI("postInstanceConfig", principal, uid, "containers",
		fmt.Sprintf("[%s]", strings.Join(containerNames, ",")))
}
