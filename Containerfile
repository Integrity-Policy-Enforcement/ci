# SPDX-License-Identifier: GPL-2.0-only

FROM ubuntu:26.04

ENV DEBIAN_FRONTEND=noninteractive

COPY config/host-packages*.txt config/mkosi.version scripts/install-firmware.py /tmp/ipe-ci/
RUN case "$(dpkg --print-architecture)" in \
        amd64) architecture=x86_64 ;; \
        arm64) architecture=arm64 ;; \
        *) exit 1 ;; \
    esac \
    && apt-get update \
    && cat /tmp/ipe-ci/host-packages.txt \
        "/tmp/ipe-ci/host-packages-$architecture.txt" \
        | xargs apt-get install -y --no-install-recommends \
    && if [ "$architecture" = arm64 ]; then python3 /tmp/ipe-ci/install-firmware.py; fi \
    && python3 -m pip install --break-system-packages \
        "git+https://github.com/systemd/mkosi@$(cat /tmp/ipe-ci/mkosi.version)" \
    && rm -rf /var/lib/apt/lists/* /tmp/ipe-ci

WORKDIR /work
COPY . /work

ENTRYPOINT ["./run.py"]
