#!/bin/bash

source ./env.sh

for n in $WORKERS; do
 docker-machine scp $1 worker-$n:
done
 docker-machine scp $1 master:
