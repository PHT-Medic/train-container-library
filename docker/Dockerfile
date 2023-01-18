FROM python:3.11-slim
MAINTAINER michael.graf@uni-tuebingen.de

# update the image
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
    apt-get upgrade -yqq && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* \
    rm -rf /var/cache/apt/archives/*


# set poetry environment variables
ENV POETRY_HOME="/opt/poetry" \
    POETRY_VIRTUALENVS_CREATE=false \
    POETRY_VIRTUALENVS_IN_PROJECT=false \
    POETRY_NO_INTERACTION=1 \
    POETRY_VERSION=1.3.0


RUN curl -sSL https://install.python-poetry.org | python3 -


ENV PATH="$PATH:$POETRY_HOME/bin"

COPY . /opt/protocol
WORKDIR /opt/protocol
RUN poetry install
RUN chmod +x /opt/protocol/docker/entrypoint/entrypoint.sh && \
    chmod +x /opt/protocol/docker/entrypoint/run_protocol.py

ENTRYPOINT ["/opt/protocol/docker/entrypoint/entrypoint.sh"]

