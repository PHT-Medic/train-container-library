FROM ubuntu
MAINTAINER michael.graf@uni-tuebingen.de

# install python3.8 and os dependencies
RUN apt -y update && apt-get -y install software-properties-common && \
    apt-get install -yqq --no-install-recommends --no-install-suggests \
        git \
        libffi-dev \
        libpq-dev \
        build-essential \
        apt-utils \
        netcat \
        locales \
        curl && \
    # install python
    add-apt-repository ppa:deadsnakes/ppa && \
    apt-get install -y python3.8 && apt install python-is-python3 && apt install -y python3-pip && \
    rm -rf /var/lib/apt/lists

COPY . /opt/protocol
WORKDIR /opt/protocol
RUN python -m pip install pipenv && \
    pipenv install --deploy --system && \
    pip install .

ENTRYPOINT ["/opt/protocol/docker/entrypoint/entrypoint.sh"]

