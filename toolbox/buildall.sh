source ../env.sh
eval $(docker-machine env master)
docker build -t tools .
for n in $WORKERS; do
  eval $(docker-machine env worker$n)
  docker build -t tools .
done
