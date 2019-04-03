# Multistage docker build, requires docker 17.05
# Travis build:
#  docker build -f docker/tests/Dockerfile --build-arg BASE_IMAGE=ubuntu:14.04 -t="trezor-tests"  .

# builder stage
ARG BASE_IMAGE=ubuntu:20.04
FROM ${BASE_IMAGE} AS builder

ARG BASE_IMAGE=ubuntu:20.04
SHELL ["/bin/bash", "-c"]

ENV DEBIAN_FRONTEND=noninteractive
RUN set -ex && \
    apt-get update && \
    apt-get --no-install-recommends --yes install \
        ca-certificates \
        cmake \
        g++ \
        make \
        pkg-config \
        graphviz \
        doxygen \
        git \
        curl \
        autoconf \
        automake \
        build-essential \
        libtool \
        bzip2 \
        xsltproc \
        gperf \
        unzip \
        python \
        libpgm-dev \
        libgtest-dev \
        zlib1g-dev

ARG NBPROC
WORKDIR /usr/local

ENV CFLAGS='-fPIC'
ENV CXXFLAGS='-fPIC'

# OpenSSL
ARG OPENSSL_VERSION=1.1.1b
ARG OPENSSL_HASH=5c557b023230413dfb0756f3137a13e6d726838ccd1430888ad15bfb2b43ea4b
RUN set -ex \
    && curl -s -O https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz \
    && echo "${OPENSSL_HASH} openssl-${OPENSSL_VERSION}.tar.gz" | sha256sum -c \
    && tar -xzf openssl-${OPENSSL_VERSION}.tar.gz \
    && cd openssl-${OPENSSL_VERSION} \
    && ./Configure linux-x86_64 no-shared --static "$CFLAGS" \
    && make -j${NBPROC:-`nproc`} build_generated \
    && make -j${NBPROC:-`nproc`} libcrypto.a \
    && make install
ENV OPENSSL_ROOT_DIR=/usr/local/openssl-${OPENSSL_VERSION}

#Cmake
ARG CMAKE_VERSION=3.26.0
ARG CMAKE_VERSION_DOT=v3.26
ARG CMAKE_HASH=4256613188857e95700621f7cdaaeb954f3546a9249e942bc2f9b3c26e381365
RUN set -ex \
    && curl -s -O https://cmake.org/files/${CMAKE_VERSION_DOT}/cmake-${CMAKE_VERSION}.tar.gz \
    && echo "${CMAKE_HASH}  cmake-${CMAKE_VERSION}.tar.gz" | sha256sum -c \
    && tar -xzf cmake-${CMAKE_VERSION}.tar.gz \
    && cd cmake-${CMAKE_VERSION} \
    && ./bootstrap --parallel=${NBPROC:-`nproc`} -- -DCMAKE_USE_OPENSSL=OFF \
    && make install

## Boost
ARG BOOST_VERSION=1_69_0
ARG BOOST_VERSION_DOT=1.69.0
ARG BOOST_HASH=8f32d4617390d1c2d16f26a27ab60d97807b35440d45891fa340fc2648b04406
RUN set -ex \
    && curl -s -L -o  boost_${BOOST_VERSION}.tar.bz2 https://boostorg.jfrog.io/artifactory/main/release/${BOOST_VERSION_DOT}/source/boost_${BOOST_VERSION}.tar.bz2 \
    && echo "${BOOST_HASH}  boost_${BOOST_VERSION}.tar.bz2" | sha256sum -c \
    && tar -xvf boost_${BOOST_VERSION}.tar.bz2 \
    && cd boost_${BOOST_VERSION} \
    && ./bootstrap.sh \
    && ./b2 -j${NBPROC:-`nproc`} --build-type=minimal link=static runtime-link=static --with-chrono --with-date_time --with-filesystem --with-program_options --with-regex --with-serialization --with-system --with-thread --with-locale threading=multi threadapi=pthread cflags="$CFLAGS" cxxflags="$CXXFLAGS" stage
ENV BOOST_ROOT /usr/local/boost_${BOOST_VERSION}

# Sodium
ARG SODIUM_VERSION=1.0.17
ARG SODIUM_HASH=b732443c442239c2e0184820e9b23cca0de0828c
RUN set -ex \
    && git clone https://github.com/jedisct1/libsodium.git -b ${SODIUM_VERSION} \
    && cd libsodium \
    && test `git rev-parse HEAD` = ${SODIUM_HASH} || exit 1 \
    && ./autogen.sh \
    && ./configure \
    && make -j${NBPROC:-`nproc`} \
    && make check \
    && make install \
    && ldconfig

# ZMQ
ARG ZMQ_VERSION=v4.3.1
ARG ZMQ_HASH=2cb1240db64ce1ea299e00474c646a2453a8435b
RUN set -ex \
    && git clone https://github.com/zeromq/libzmq.git -b ${ZMQ_VERSION} \
    && cd libzmq \
    && test `git rev-parse HEAD` = ${ZMQ_HASH} || exit 1 \
    && ./autogen.sh \
    && ./configure --enable-static --with-libsodium --disable-libunwind \
    && make -j${NBPROC:-`nproc`} \
    && make install \
    && ldconfig

# zmq.hpp
ARG CPPZMQ_VERSION=v4.3.0
ARG CPPZMQ_HASH=213da0b04ae3b4d846c9abc46bab87f86bfb9cf4
RUN set -ex \
    && git clone https://github.com/zeromq/cppzmq.git -b ${CPPZMQ_VERSION} \
    && cd cppzmq \
    && test `git rev-parse HEAD` = ${CPPZMQ_HASH} || exit 1 \
    && mv *.hpp /usr/local/include

# Ncurses
ARG NCURSES_VERSION=6.1
RUN set -ex \
    && curl -s -O https://ftp.gnu.org/pub/gnu/ncurses/ncurses-${NCURSES_VERSION}.tar.gz \
    && tar -xzvf ncurses-${NCURSES_VERSION}.tar.gz \
    && cd ncurses-6.1 \
    && ./configure --enable-pc-files --with-shared --with-normal \
    && make -j${NBPROC:-`nproc`} \
    && make install

# Readline
ARG READLINE_VERSION=8.0
ARG READLINE_HASH=e339f51971478d369f8a053a330a190781acb9864cf4c541060f12078948e461
RUN set -ex \
    && curl -s -O https://ftp.gnu.org/gnu/readline/readline-${READLINE_VERSION}.tar.gz \
    && echo "${READLINE_HASH}  readline-${READLINE_VERSION}.tar.gz" | sha256sum -c \
    && tar -xzf readline-${READLINE_VERSION}.tar.gz \
    && cd readline-${READLINE_VERSION} \
    && ./configure --with-curses \
    && make -j${NBPROC:-`nproc`} \
    && make install

# Udev
ARG UDEV_VERSION=v3.2.11
ARG UDEV_HASH=0a4dae19c1a191c8054fc2b9c2d592e797715a69
RUN set -ex \
    && git clone https://github.com/gentoo/eudev -b ${UDEV_VERSION} \
    && cd eudev \
    && test `git rev-parse HEAD` = ${UDEV_HASH} || exit 1 \
    && autoreconf -f -i -s \
    && ./configure --disable-gudev --disable-introspection --disable-hwdb --disable-manpages --disable-selinux \
    && make -j${NBPROC:-`nproc`} \
    && make install

# Libusb
ARG USB_VERSION=v1.0.26
ARG USB_HASH=4239bc3a50014b8e6a5a2a59df1fff3b7469543b
RUN set -ex \
    && git clone https://github.com/libusb/libusb.git -b ${USB_VERSION} \
    && cd libusb \
    && test `git rev-parse HEAD` = ${USB_HASH} || exit 1 \
    && ./autogen.sh \
    && ./configure \
    && make -j${NBPROC:-`nproc`} \
    && make install

# Hidapi
ARG HIDAPI_VERSION=hidapi-0.8.0-rc1
ARG HIDAPI_HASH=40cf516139b5b61e30d9403a48db23d8f915f52c
RUN set -ex \
    && git clone https://github.com/signal11/hidapi -b ${HIDAPI_VERSION} \
    && cd hidapi \
    && test `git rev-parse HEAD` = ${HIDAPI_HASH} || exit 1 \
    && sed -i -E "s#libhidapi_libusb_la_LDFLAGS = \\$\(LTLDFLAGS\)#libhidapi_libusb_la_LDFLAGS = \$\(LTLDFLAGS\) \$\(PTHREAD_CFLAGS\)#g" libusb/Makefile.am \
    && ./bootstrap \
    && ./configure --enable-static \
    && make -j${NBPROC:-`nproc`} \
    && make install

# Protobuf
ARG PROTOBUF_VERSION=v21.12
ARG PROTOBUF_HASH=f0dc78d7e6e331b8c6bb2d5283e06aa26883ca7c
RUN set -ex \
    && git clone https://github.com/protocolbuffers/protobuf -b ${PROTOBUF_VERSION} \
    && cd protobuf \
    && test `git rev-parse HEAD` = ${PROTOBUF_HASH} || exit 1 \
    && git submodule update --init --recursive \
    && ./autogen.sh \
    && ./configure --enable-static \
    && make -j${NBPROC:-`nproc`} \
    && make install \
    && ldconfig

# libexpat
ARG LIBEXPAT_VERSION=2_4_8
ARG LIBEXPAT_VERSION_DOT=2.4.8
ARG LIBEXPAT_HASH=a247a7f6bbb21cf2ca81ea4cbb916bfb9717ca523631675f99b3d4a5678dcd16
RUN set -ex \
    && curl -s -O -L https://github.com/libexpat/libexpat/releases/download/R_${LIBEXPAT_VERSION}/expat-${LIBEXPAT_VERSION_DOT}.tar.bz2 \
    && echo "${LIBEXPAT_HASH} expat-${LIBEXPAT_VERSION_DOT}.tar.bz2" | sha256sum -c \
    && tar -xjf expat-${LIBEXPAT_VERSION_DOT}.tar.bz2 \
    && cd expat-${LIBEXPAT_VERSION_DOT} \
    && ./configure --enable-static \
    && make -j${NBPROC:-`nproc`} \
    && make install \
    && ldconfig

# Unbound
ARG UNBOUND_VERSION_DOT=1.15.0
ARG UNBOUND_HASH=a480dc6c8937447b98d161fe911ffc76cfaffa2da18788781314e81339f1126f
RUN set -ex \
    && curl -s -O -L https://www.nlnetlabs.nl/downloads/unbound/unbound-${UNBOUND_VERSION_DOT}.tar.gz \
    && echo "${UNBOUND_HASH} unbound-${UNBOUND_VERSION_DOT}.tar.gz" | sha256sum -c \
    && tar -xzf unbound-${UNBOUND_VERSION_DOT}.tar.gz \
    && cd unbound-${UNBOUND_VERSION_DOT} \
    && ./configure --enable-static \
    && make -j${NBPROC:-`nproc`} \
    && make install \
    && ldconfig

WORKDIR /src
COPY . .

# && make -j${NPROC:-`nproc`} debug-test-trezor-stat
ARG NPROC
ENV USE_SINGLE_BUILDDIR=1
RUN set -ex \
    && git submodule update --init --recursive \
    && rm -rf build \
    && echo "DONE"

#&& sed -i -E "s/NAMES tinfo termcap/NAMES /g" cmake/FindReadline.cmake \
#&& sed -i -E "s/if\(\(STATIC AND UNIX/if\(\(UNIX/g" cmake/FindHIDAPI.cmake \
