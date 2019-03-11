
KUBE_FASTBUILD=true build/run.sh make kube-apiserver
KUBE_FASTBUILD=true make package

eval $(docker-machine env master)

hack/print-workspace-status.sh | grep DOCKER_TAG | awk '{print $2}'
docker load -i _output/release-images/amd64/kube-apiserver.tar

# replace kubelet configure

