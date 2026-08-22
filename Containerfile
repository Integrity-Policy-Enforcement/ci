# SPDX-License-Identifier: GPL-2.0-only

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

COPY config/host-packages.txt config/mkosi.version /tmp/ipe-ci/
RUN apt-get update \
    && xargs apt-get install -y --no-install-recommends \
        < /tmp/ipe-ci/host-packages.txt \
    && python3 -m pip install --break-system-packages \
        "git+https://github.com/systemd/mkosi@$(cat /tmp/ipe-ci/mkosi.version)" \
    && rm -rf /var/lib/apt/lists/* /tmp/ipe-ci

WORKDIR /work
COPY . /work

ENTRYPOINT ["./run.py"]
