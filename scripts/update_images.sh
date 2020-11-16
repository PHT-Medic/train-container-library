#!/bin/bash

# TODO check build context
docker login harbor.personalhealthtrain.de
docker build -t harbor.personalhealthtrain.de/pht_master/master:dl -f ../docker/Dockerfile_dl ..
docker build -t harbor.personalhealthtrain.de/pht_master/master:slim  -f ../docker/Dockerfile_slim ..
docker build -t harbor.personalhealthtrain.de/pht_master/master:buster -f ../docker/Dockerfile_buster ..
docker push harbor.personalhealthtrain.de/pht_master/master:dl
docker push harbor.personalhealthtrain.de/pht_master/master:slim
docker push harbor.personalhealthtrain.de/pht_master/master:buster