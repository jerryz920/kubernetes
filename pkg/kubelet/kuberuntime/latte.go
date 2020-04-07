package kuberuntime

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
	"k8s.io/klog"

	v1 "k8s.io/api/core/v1"
)

// All the BS below are just for research purpose. Hacks could be turned into real code
// later but now we need to get the system up and running.

const (
	metadata_server = "http://mds:19851"
)

var (
	safe_client         *http.Client
	logDir                    = filepath.Join(os.TempDir(), "latte-k8s")
	debugLogSuffixIndex int64 = 0 // only for debug usage
)

func init() {
	tr := &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: true,
	}

	safe_client = &http.Client{Transport: tr}
	if err := os.MkdirAll(logDir, 0700); err != nil {
		klog.Errorf("Failed to create the latte debug log directory: %v", err)
	}

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

func encodeSafeRequest(principal string, otherValues ...string) (*bytes.Buffer, error) {
	v := SafeRequest{
		Principal:   principal,
		OtherValues: otherValues,
	}
	return encode(&v)
}

func dumpSafeRequestAsCurl(url string, buf *bytes.Buffer) {
	suffix := atomic.AddInt64(&debugLogSuffixIndex, 1)
	scriptFile := filepath.Join(fmt.Sprintf("req.%d.sh", suffix))
	dataFile := filepath.Join(logDir, fmt.Sprintf("req.%d.json", suffix))
	scriptContent := fmt.Sprintf("curl -XPOST \"%s\" --data-binary \"@%s\"", url, dataFile)
	// Try our best
	if err := ioutil.WriteFile(scriptFile, []byte(scriptContent), 0700); err != nil {
		klog.Error("Failed to write out latte script data: ", err)
	}

	if err := ioutil.WriteFile(dataFile, buf.Bytes(), 0700); err != nil {
		klog.Error("Failed to write out latte json data: ", err)
	}
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

	dumpSafeRequestAsCurl(url, reqbuf)

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

type PodRequest struct {
	Uuid string
	Addr string
	Tag  string `json="omitempty"`
}

func podAPI(method string, preq *PodRequest) {
	url := fmt.Sprintf("%s/%s", metadata_server, method)
	reqbuf, err := encode(preq)
	if err != nil {
		if preq != nil {
			klog.Errorf("Encoding pod req to metadata server %v", *preq)
		} else {
			klog.Errorf("Encoding null pod req to metadta server")
		}
		return
	}

	resp, err := safe_client.Post(url, "application/json", reqbuf)
	if err != nil {
		klog.Errorf("Sending pod request: %v, [%v], %v", method, *preq, err)
		return
	}

	if resp.Body != nil {
		ioutil.ReadAll(resp.Body)
		resp.Body.Close()
	}

	if resp.StatusCode != http.StatusOK {
		klog.Errorf("Failed to post POD to metadata API, status: %d", resp.StatusCode)
	}
	klog.Infof("Ydev successful pod request: %v", *preq)
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

	preq := PodRequest{
		Uuid: uid,
		Addr: podIP,
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

	if outputTag, ok := pod.Annotations["latte.outputTag"]; ok {
		configPairs = append(configPairs, latteConfigPair{key: "latte.outputTag", val: outputTag})
		preq.Tag = outputTag
	}

	podConfigString := configPairs.String()
	safeAPI("postInstanceConfig", principal, uid, "global", fmt.Sprintf("[%s]", podConfigString))
	podAPI("postPod", &preq)

	containerNames := make([]string, 0)
	for _, container := range pod.Spec.Containers {
		containerNames = append(containerNames, getSafeContainerName(pod, &container, false))
	}

	for _, container := range pod.Spec.InitContainers {
		//		m.attestContainer(principal, uid, ctnName, &container, allConfigMaps, configMapVolumes)
		containerNames = append(containerNames, getSafeContainerName(pod, &container, true))
	}
	safeAPI("postInstanceConfig", principal, uid, "containers",
		fmt.Sprintf("[%s]", strings.Join(containerNames, ",")))
}

func (m *kubeGenericRuntimeManager) attestContainer(pod *v1.Pod, container *v1.Container, opts *runtimeapi.ContainerConfig) {

	myip := getMyIP()
	uid := string(pod.UID)
	principal := fmt.Sprintf("%s:6431", myip.String())
	// generate Container specific configurations
	// each container has an Image and a property list. The property list needs special resolve if it
	// starts with "-", or if it can be resolved to be valid yaml, json, or property list.
	configPairs := make(latteConfigs, 0, 64)
	ctnName := getSafeContainerName(pod, container, true)

	workdir := opts.WorkingDir
	if workdir == "" {
		workdir = "/"
	}
	configPairs = append(configPairs,
		latteConfigPair{key: "pwd", val: workdir},
		latteConfigPair{key: "tty", val: strconv.FormatBool(container.TTY)},
		latteConfigPair{key: "stdin", val: strconv.FormatBool(container.Stdin)})

	// opts.Mounts
	// opts.Devices
	// opts.Labels
	// opts.Annotations

	for _, port := range container.Ports {
		configPairs = append(configPairs, latteConfigPair{
			key: fmt.Sprintf("%s-port-%d-mapping", strings.ToLower(string(port.Protocol)), port.ContainerPort),
			val: string(port.HostPort)})
	}
	for _, env := range opts.Envs {
		configPairs = append(configPairs, latteConfigPair{
			key: fmt.Sprintf("%s", env.Key),
			val: env.Value})
	}
	for i, arg := range opts.Command {
		configPairs = append(configPairs, latteConfigPair{
			key: fmt.Sprintf("arg%d", i),
			val: arg})
	}
	for i, arg := range opts.Args {
		configPairs = append(configPairs, latteConfigPair{
			key: fmt.Sprintf("arg%d", i+len(container.Command)),
			val: arg})
	}
	// parse EnvFrom
	// parse ConfigMapVolumeSource
	ctnConfigString := configPairs.String()
	safeAPI("postInstanceConfig", principal, uid, ctnName, fmt.Sprintf("[%s, %s]", container.Image, ctnConfigString))

}

func (m *kubeGenericRuntimeManager) isInitContainer(pod *v1.Pod, container *v1.Container) bool {
	for _, c := range pod.Spec.InitContainers {
		if c.Name == container.Name {
			return true
		}
	}
	return false
}
