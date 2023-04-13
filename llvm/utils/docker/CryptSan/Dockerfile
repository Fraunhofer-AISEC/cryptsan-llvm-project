#===-----------------------------------------------------------------------===//
#
# Dockerfile to create reliable builds of LLVM with CryptSan.
#
#===----------------------------------------------------------------------===//

FROM ubuntu:20.04 as builder


RUN apt-get update \
    && DEBIAN_FRONTEND="noninteractive" \
    apt-get install -f -y --no-install-recommends \
    bash-completion \
    binutils-dev \
    binutils-multiarch-dev \
    bison \
    build-essential \
    ca-certificates \
    ccache \
    clang \
    cmake \
    curl \
    distcc \
    distcc-pump \
    dpkg-dev \
    elfutils \
    file \
    flex \
    git \
    gdb-multiarch \
    g++-multilib \
    libaudit-dev \
    libbfd-dev \
    libc6-dev \
    libc6-dev-i386 \
    libdw-dev \
    libelf-dev \
    libelf1 \
    libgtk2.0-dev \
    libiberty-dev \
    libnuma-dev \
    libpcre3 \
    libperl-dev \
    libslang2 \
    libslang2-dev \
    libssl-dev \
    libunwind8 \
    libunwind8-dev \
    libz-dev \
    lld \
    lldb \
    llvm \
    libunwind-dev \
    m4 \
    ninja-build \
    python-dev \
    python3 \
    python3-cairo \
    python3-cairocffi \
    python3-cffi \
    python3-matplotlib \
    python3-numpy \
    python3-openpyxl \
    python3-pandas \
    python3-pip \
    python3-scipy \
    python3-setuptools \
    python3-wheel \
    snapd \
    time \
    qemu-system-arm \
    qemu-efi \
    qemu-efi-aarch64 \
    qemu-utils \
    qemu \
    qemu-user \
    qemu-user-static \
    valgrind \
    vim \
    wget \
    ccache \
    libncurses5-dev \
    swig \
    libedit-dev \
    libxml2-dev \
    build-essential \
    gcc-7-plugin-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install lit temci
RUN temci setup

ENV HOME=/home/builder
RUN groupadd builder && useradd -m -g builder builder


WORKDIR /home/builder/cryptsan/
RUN chown builder:builder .

USER builder
COPY entrypoint.sh .
COPY build.sh .
COPY test.sh .

ENTRYPOINT ["./entrypoint.sh"]
CMD ["build"]
