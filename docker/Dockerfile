FROM bitnami/python:3.11
MAINTAINER michael.graf@uni-tuebingen.de

# update the image
RUN apt -y update && apt-get -y install software-properties-common && \
    apt-get upgrade -yqq && \
    apt-get install -yqq --no-install-recommends --no-install-suggests \
        libffi-dev \
        libpq-dev \
        build-essential \
        apt-utils \
        locales \
        curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /var/cache/apt/archives/*

# install train container library
RUN pip install --force-reinstall --no-cache-dir -v "pht-train-container-library==2.0.0"

ENTRYPOINT ["/opt/protocol/docker/entrypoint/entrypoint.sh"]

