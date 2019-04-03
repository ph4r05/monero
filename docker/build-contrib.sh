#!/bin/bash
MAKEJOBS=-j`nproc`
CCACHE_SIZE=100M
CCACHE_TEMPDIR=/tmp/.ccache-temp
CCACHE_COMPRESS=1
CCACHE_DIR=$HOME/.ccache
SDK_URL=https://bitcoincore.org/depends-sources/sdks
DOCKER_PACKAGES="build-essential libtool cmake autotools-dev automake pkg-config bsdmainutils curl git ca-certificates ccache"

: "${DEBUG:=0}"
: "${TESTS:=0}"
: "${PLATFORM:=ubuntu_14.04}"
: "${NO_DEPENDS:=}"
: "${DPKG_ADD_ARCH:=}"
: "${BUILD_NEW_CMAKE:=0}"

BASE_IMAGE="ubuntu:18.04"
DIR="$(SHELL_SESSION_FILE= && cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
TRAVIS_BUILD_DIR="${DIR}/.."
BUILD_SUFFIX=$PLATFORM
BUILD_OUT_DIR="${TRAVIS_BUILD_DIR}/build-${BUILD_SUFFIX}"
BASE_OUTDIR=$TRAVIS_BUILD_DIR/out

if [[ "$PLATFORM" == "arm_7" ]]; then
  HOST=arm-linux-gnueabihf
  PACKAGES="python3 gperf g++-arm-linux-gnueabihf"
elif [[ "$PLATFORM" == "arm_8" ]]; then
  HOST=aarch64-linux-gnu
  PACKAGES="python3 gperf g++-aarch64-linux-gnu"
elif [[ "$PLATFORM" == "win_i686" ]]; then
  HOST=i686-w64-mingw32
  DEP_OPTS="NO_QT=1"
  PACKAGES="python3 g++-mingw-w64-i686 qttools5-dev-tools"
elif [[ "$PLATFORM" == "win_x64" ]]; then
  HOST=x86_64-w64-mingw32
  DEP_OPTS="NO_QT=1"
  PACKAGES="cmake python3 g++-mingw-w64-x86-64 qttools5-dev-tools"
elif [[ "$PLATFORM" == "linux_i686" ]]; then
  HOST=i686-pc-linux-gnu
  PACKAGES="gperf cmake g++-multilib python3-zmq"
elif [[ "$PLATFORM" == "linux_x64" ]]; then
  HOST=x86_64-unknown-linux-gnu
  PACKAGES="gperf cmake python3-zmq libdbus-1-dev libharfbuzz-dev"
elif [[ "$PLATFORM" == "ubuntu_14.04" ]]; then
  BASE_IMAGE="ubuntu:14.04"
  HOST=x86_64-ubuntu1404-linux-gnu
  PACKAGES="gperf cmake python3-zmq libdbus-1-dev libharfbuzz-dev"
elif [[ "$PLATFORM" == "osx" ]]; then
  HOST=x86_64-apple-darwin11
  PACKAGES="cmake imagemagick libcap-dev librsvg2-bin libz-dev libbz2-dev libtiff-tools python-dev python3-setuptools-git"
  OSX_SDK=10.11
else
  echo "ERROR: Platform not supported: $PLATFORM"
  exit 1
fi

set -ex

export PATH=$(echo $PATH | tr ':' "\n" | sed '/\/opt\/python/d' | tr "\n" ":" | sed "s|::|:|g")
env | grep -E '^(CCACHE_|DISPLAY|CONFIG_SHELL)' | tee /tmp/env
if [[ $HOST = *-mingw32 ]]; then DOCKER_ADMIN="--cap-add SYS_ADMIN"; fi

echo "Building for: $PLATFORM"
echo "Monero dir: $TRAVIS_BUILD_DIR"
echo "Build dir: $BUILD_OUT_DIR"
echo "Starting build docker image from base image $BASE_IMAGE"

DOCKER_ID=$(docker run $DOCKER_ADMIN -idt --mount type=bind,src=$TRAVIS_BUILD_DIR,dst=$TRAVIS_BUILD_DIR --mount type=bind,src=$CCACHE_DIR,dst=$CCACHE_DIR -w $TRAVIS_BUILD_DIR --env-file /tmp/env $BASE_IMAGE)
DOCKER_EXEC="docker exec $DOCKER_ID"
echo "Docker started: $DOCKER_ID"

if [ -n "$DPKG_ADD_ARCH" ]; then $DOCKER_EXEC dpkg --add-architecture "$DPKG_ADD_ARCH" ; fi

echo "Installing basic docker packages"
$DOCKER_EXEC apt-get update
$DOCKER_EXEC apt-get install --no-install-recommends --no-upgrade -qq $PACKAGES $DOCKER_PACKAGES

if [[ $BASE_IMAGE =~ "ubuntu:14"* ]]; then
    $DOCKER_EXEC apt-get --no-install-recommends --yes install libtool software-properties-common
    $DOCKER_EXEC add-apt-repository ppa:ubuntu-toolchain-r/test
    $DOCKER_EXEC apt-get update
    $DOCKER_EXEC apt-get --no-install-recommends --yes install  gcc-8 g++-8
    $DOCKER_EXEC update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-8 80 --slave /usr/bin/g++ g++ /usr/bin/g++-8;
fi

if [[ $BASE_IMAGE =~ "ubuntu:14"* || $BUILD_NEW_CMAKE > 0 ]]; then
    $DOCKER_EXEC apt-get remove --yes cmake
    $DOCKER_EXEC apt-get --no-install-recommends --yes install libncurses5-dev libssl-dev libcurl4-openssl-dev
    $DOCKER_EXEC bash -c "set -ex && cd /tmp && $TRAVIS_BUILD_DIR/docker/install-cmake.sh && ln -s /usr/local/bin/cmake /usr/bin/cmake && cd -"
fi

echo "Preparing build environment"
mkdir -p contrib/depends/SDKs contrib/depends/sdk-sources
if [ -n "$OSX_SDK" -a ! -f contrib/depends/sdk-sources/MacOSX${OSX_SDK}.sdk.tar.gz ]; then curl --location --fail $SDK_URL/MacOSX${OSX_SDK}.sdk.tar.gz -o contrib/depends/sdk-sources/MacOSX${OSX_SDK}.sdk.tar.gz; fi
if [ -n "$OSX_SDK" -a -f contrib/depends/sdk-sources/MacOSX${OSX_SDK}.sdk.tar.gz ]; then tar -C contrib/depends/SDKs -xf contrib/depends/sdk-sources/MacOSX${OSX_SDK}.sdk.tar.gz; fi
if [[ $HOST = *-mingw32 ]]; then $DOCKER_EXEC bash -c "update-alternatives --set $HOST-g++ \$(which $HOST-g++-posix)"; fi
if [[ $HOST = *-mingw32 ]]; then $DOCKER_EXEC bash -c "update-alternatives --set $HOST-gcc \$(which $HOST-gcc-posix)"; fi
if [ -z "$NO_DEPENDS" ]; then $DOCKER_EXEC bash -c "CONFIG_SHELL= make $MAKEJOBS -C contrib/depends HOST=$HOST $DEP_OPTS"; fi

echo "Building"
export TRAVIS_COMMIT_LOG=`git log --format=fuller -1`
OUTDIR=$BASE_OUTDIR/$TRAVIS_PULL_REQUEST/$TRAVIS_JOB_NUMBER-$HOST
if [ -z "$NO_DEPENDS" ]; then $DOCKER_EXEC ccache --max-size=$CCACHE_SIZE; fi
$DOCKER_EXEC bash -c "mkdir -p $BUILD_OUT_DIR && cd $BUILD_OUT_DIR && cmake -DCMAKE_TOOLCHAIN_FILE=$TRAVIS_BUILD_DIR/contrib/depends/$HOST/share/toolchain.cmake .. && make $MAKEJOBS"
