#!/bin/bash

source ./env.sh

for n in $WORKERS; do
 docker-machine ssh worker-$n "$@"
done
 docker-machine ssh master "$@"
