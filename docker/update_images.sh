#!/bin/bash

# TODO check build context
docker login
docker build -f Dockerfile_dl .