#!/bin/bash


source ./env.sh
workers=$WORKERS
echo $workers


for m in kubelet kubectl kubeadm; do
  docker-machine scp _output/bin/$m master:
  for n in $workers; do
    docker-machine scp _output/bin/$m worker-$n:
  done
done

cmd="sudo systemctl stop kubelet.service; sudo cp kubelet kubectl kubeadm /usr/bin; sudo systemctl start kubelet.service;"
docker-machine ssh master "$cmd"
for n in $workers; do
docker-machine ssh worker-$n "$cmd"
done

