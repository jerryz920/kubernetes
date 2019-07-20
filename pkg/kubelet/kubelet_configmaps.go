package kubelet

import (
	v1 "k8s.io/api/core/v1"
)

func (kl *Kubelet) GetConfigMap(namespace, name string) (*v1.ConfigMap, error) {
	return kl.configMapManager.GetConfigMap(namespace, name)
}
