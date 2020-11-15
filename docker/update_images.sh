#!/bin/bash

# TODO check build context
docker login harbor.personalhealthtrain.de
docker build -t harbor.personalhealthtrain.de/pht_master/master:dl -t harbor.personalhealthtrain.de/pht_master/master:latest -f Dockerfile_dl .
docker build -t harbor.personalhealthtrain.de/pht_master/master:slim -t harbor.personalhealthtrain.de/pht_master/master:latest -f Dockerfile_slim .
docker build -t harbor.personalhealthtrain.de/pht_master/master:buster -t harbor.personalhealthtrain.de/pht_master/master:latest -f Dockerfile_buster .