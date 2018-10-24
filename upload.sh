

workers=`seq 1 5`

for m in kubelet kubectl kubeadm; do
  docker-machine scp _output/bin/$m master:
  for n in $workers; do
    docker-machine scp _output/bin/$m worker$n:
  done
done

cmd="sudo cp kubelet kubectl kubeadm /usr/bin"
docker-machine ssh master "$cmd"
for n in $workers; do
docker-machine ssh worker$n "$cmd"
done

