FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
        make \
        python3 \
        python3-pip \
        coreutils \
        ca-certificates \
        unzip \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install --no-cache-dir \
        numpy==2.3.5 \
        sympy==1.14.0

WORKDIR /artifact
COPY . /artifact

RUN chmod +x docker/reproduce.sh

ENTRYPOINT ["docker/reproduce.sh"]
