FROM debian:trixie

WORKDIR /work

RUN apt-get update -y \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        debhelper \
        devscripts \
        dpkg-dev \
        fakeroot \
        git \
        libjson-maybexs-perl \
        libjson-schema-modern-perl \
        libmojolicious-perl \
        libpath-tiny-perl \
        perl \
    && rm -rf /var/lib/apt/lists/*

CMD ["bash"]
