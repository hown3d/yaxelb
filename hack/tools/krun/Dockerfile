FROM debian:sid as builder

RUN apt-get update
RUN apt-get install -y make git gcc build-essential pkgconf libtool \
  libsystemd-dev libprotobuf-c-dev libcap-dev libseccomp-dev libyajl-dev \
  go-md2man autoconf python3 automake libcap-ng-dev

FROM builder as libkrunfw
ARG LIBKRUN_VERSION=v5.3.0
# from https://github.com/containers/libkrunfw/blob/463f717bbdd916e1352a025b6fb2456e882b0b39/build_on_krunvm_debian.sh#L35
RUN apt-get install  -y curl build-essential python3-pyelftools bc kmod cpio flex libncurses5-dev libelf-dev libssl-dev dwarves bison
ADD https://github.com/containers/libkrunfw.git#${LIBKRUN_VERSION} /opt/libkrunfw
WORKDIR /opt/libkrunfw
RUN make -j $(nproc)
RUN make install

FROM rustlang/rust:nightly-trixie as libkrun
ARG LIBKRUN_VERSION=v1.17.4
RUN apt-get update
RUN apt-get install -y clang libclang-dev llvm llvm-dev libcap-ng-dev

ADD --unpack https://github.com/NixOS/patchelf/releases/download/0.18.0/patchelf-0.18.0-aarch64.tar.gz /opt/patchelf
RUN install /opt/patchelf/bin/patchelf /bin/patchelf

ADD --keep-git-dir=true https://github.com/containers/libkrun.git#${LIBKRUN_VERSION} /opt/libkrun
WORKDIR /opt/libkrun
ARG LIBKRUN_FEATURES="NET=1"
RUN make ${LIBKRUN_FEATURES}
RUN make ${LIBKRUN_FEATURES} install

FROM builder as krun
ARG VERSION=1.27
COPY --from=libkrunfw /usr/local/lib64/libkrunfw.so* /usr/local/lib64/
COPY --from=libkrun /usr/local/lib64/libkrun.so* /usr/local/lib64/
COPY --from=libkrun /usr/local/include/libkrun*.h  /usr/local/include/
ADD --keep-git-dir=true https://github.com/containers/crun.git#${VERSION} /opt/crun
WORKDIR /opt/crun

RUN ./autogen.sh 
RUN ./configure --with-libkrun
RUN make git-version.h
RUN make -j $(nproc)
RUN make install
