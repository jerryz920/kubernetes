package kuberuntime

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/golang/glog"

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

func getMyIP() (net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	// handle err
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			return nil, err
		}
		// handle err
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if strings.HasPrefix(ip.String(), "192.1.") {
				return ip, nil
			}
			// process IP address
		}
	}
	return nil, errors.New("System IP not found")
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

func safeAPI(method string, principal string, otherValues ...string) {
	url := fmt.Sprintf("%s/%s", metadata_server, method)
	reqbuf, err := encodeSafeRequest(principal, otherValues...)
	if err != nil {
		glog.Errorf("Encoding safe request %v, %v, %v", principal, otherValues, err)
		return
	}

	resp, err := safe_client.Post(url, "application/json", reqbuf)
	if err != nil {
		glog.Errorf("Sending safe request: %v, %v, [%v] %v", method, principal, otherValues, err)
		return
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		glog.Errorf("Reading safe response: %v, %v, [%v] %v", method, principal, otherValues, err)
		return
	}

	glog.Infof("Ydev safe request: %v, %v, [%v], resp: %v", method, principal, otherValues, string(data))
}

type latteConfigPair struct {
	key string
	val string
}

type latteConfigs = []latteConfigPair

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
	return ""
}

func (m *kubeGenericRuntimeManager) attestContainer(principal string, pod *v1.Pod, container *v1.Container, init bool,
	configMaps, volToConfigMaps map[string]*v1.ConfigMap) {
	uid := string(pod.UID)
	var typeName string
	if init {
		typeName = "init"
	} else {
		typeName = "default"
	}
	ctnName := fmt.Sprintf("%s/%s/%s", uid, typeName, container.Name)
	safeAPI("postInstanceConfig", principal, uid, "container", ctnName)
	// fixme: image should not be a name. Should be its sha256 hash. Need to query docker.
	safeAPI("endorse", principal, ctnName, "image", container.Image)

	// generate Container specific configurations
	// each container has an Image and a property list. The property list needs special resolve if it
	// starts with "-", or if it can be resolved to be valid yaml, json, or property list.
	configPairs := make(latteConfigs, 0, 64)

	workdir := container.WorkingDir
	if workdir == "" {
		workdir = "/"
	}
	configPairs = append(configPairs,
		latteConfigPair{key: "pwd", value: workdir},
		latteConfigPair{key: "tty", value: strconv.FormatBool(container.TTY)},
		latteConfigPair{key: "stdin", value: strconv.FormatBool(container.Stdin)})

	for i, port := range container.Ports {
		configPairs = append(configPairs, latteConfigPair{
			key:   fmt.Sprintf("%s-port-%d", strings.ToLower(string(port.Protocol)), string(port.ContainerPort)),
			value: string(port.HostPort)})
	}
	for _, env := range container.Env {
		configPairs = append(configPairs, latteConfigPair{
			key:   fmt.Sprintf("%s", env.Name),
			value: env.Value})
	}
	// parse container.Args, container.Command
	// parse EnvFrom
	// parse ConfigMapVolumeSource
	ctnConfigString := configPairs.String()
	safeAPI("endorse", principal, ctnName, "configlist", ctnConfigString)

}

func (m *kubeGenericRuntimeManager) attest(pod *v1.Pod, podIP string) {
	glog.Infof("attesting pod %s on %s", pod.Name, ip)

	pod_bytes, err := encode(pod)
	if err != nil {
		glog.Errorf("Can not encode pod object: {}", err)
		return
	}
	myip, err := getMyIP()
	if err != nil {
		glog.Errorf("Can not get system IP")
		return
	}

	uid := string(pod.UID)
	hash := sha256.Sum256(pod_bytes.Bytes())
	imageRef := base64.RawStdEncoding.EncodeToString(hash[:])
	principal := fmt.Sprintf("%s:6431", myip.String())
	safeAPI("postInstance", principal, uid, imageRef, fmt.Sprintf("%s:1-65535", ip))

	allConfigMaps := make(map[string]*v1.ConfigMap)
	configMapVolumes := make(map[string]*v1.ConfigMap)
	for _, v := range pod.Spec.Volumes {
		if v.VolumeSource.ConfigMap != nil {
			glog.Info("Processing ConfigMap ", v.Name)
			if _, ok := allConfigMaps[v.VolumeSource.ConfigMap.Name]; !ok {
				configMap, err := m.runtimeHelper.GetConfigMap(pod.Namespace, v.VolumeSource.ConfigMap.Name)
				if err != nil {
					glog.Infof("Ydev: err getting configmap %s, %s: %s", pod.Namespace, v.VolumeSource.ConfigMap.Name, err)
					continue
				}
				allConfigMaps[v.VolumeSource.ConfigMap.Name] = configMap
			}
			confgMapVolumes[v.Name] = configMap
		}
	}

	configPairs := latteConfigs{
		latteConfigPair{key: "namespace", value: pod.Namespace},
		latteConfigPair{key: "service_account", value: pod.Spec.ServiceAccountName},
	}
	if pubkey, ok := pod.Annotations["latte.pubkey"]; ok {
		configPairs = append(configPairs, latteConfigPair{key: "latte.key", value: pubkey})
	}
	if name, ok := pod.Annotations["latte.user"]; ok {
		configPairs = append(configPairs, latteConfigPair{key: "latte.user", value: name})
	}

	if creator, ok := pod.Annotations["latte.creator"]; ok {
		configPairs = append(configPairs, latteConfigPair{key: "latte.creator", value: creator})
	}
	podConfigString := configPairs.String()
	safeAPI("postInstanceConfig", principal, uid, "configlist", podConfigString)

	for _, container := range pod.Spec.Containers {
		m.attestContainer(principal, pod, container, false, allConfigMaps, volToConfigMaps)
	}

	for _, container := range pod.Spec.InitContainers {
		// fixme: image should not be a name. Should be its sha256 hash. Need to query docker.
		m.attestContainer(principal, pod, container, true, allConfigMaps, volToConfigMaps)
	}
}
