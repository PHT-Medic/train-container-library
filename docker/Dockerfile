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
    apt-get remove -yqq git && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /var/cache/apt/archives/*


# Setup poetry environment
ENV POETRY_HOME="/opt/poetry" \
    POETRY_VIRTUALENVS_CREATE=false \
    POETRY_VIRTUALENVS_IN_PROJECT=false \
    POETRY_NO_INTERACTION=1 \
    POETRY_VERSION=1.4.2

RUN curl -sSL https://install.python-poetry.org | python3 -
ENV PATH="$PATH:$POETRY_HOME/bin"

COPY . /opt/protocol
# install train container library
WORKDIR /opt/protocol

RUN poetry install --without dev

RUN chmod +x /opt/protocol/docker/entrypoint/entrypoint.sh

ENTRYPOINT ["/opt/protocol/docker/entrypoint/entrypoint.sh"]

