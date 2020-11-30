#!/bin/bash

# TODO check build context
docker login harbor.personalhealthtrain.de
docker build -t harbor.personalhealthtrain.de/pht_master/master:dl -f ../docker_files/Dockerfile_dl ..
docker build -t harbor.personalhealthtrain.de/pht_master/master:slim  -f ../docker_files/Dockerfile_slim ..
docker build -t harbor.personalhealthtrain.de/pht_master/master:buster -f ../docker_files/Dockerfile_buster ..
docker push harbor.personalhealthtrain.de/pht_master/master:dl
docker push harbor.personalhealthtrain.de/pht_master/master:slim
docker push harbor.personalhealthtrain.de/pht_master/master:buster