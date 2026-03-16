FROM perl:latest

WORKDIR /work

RUN apt-get update -y \
    && apt-get install -y --no-install-recommends \
        git \
        build-essential \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

COPY cpanfile /tmp/cpansa-feed-cpanfile

RUN curl -fsSL https://raw.githubusercontent.com/skaji/cpm/main/cpm -o /usr/local/bin/cpm \
    && chmod +x /usr/local/bin/cpm \
    && cpm install -g --show-build-log-on-failure --cpanfile /tmp/cpansa-feed-cpanfile \
    && cpm install -g --show-build-log-on-failure \
        YAML::Tiny \
        Mojolicious \
        HTTP::Tiny \
        CPAN::Audit::DB \
        Test::CVE

CMD ["bash"]
