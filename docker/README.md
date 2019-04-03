# Docker builds

This dir helps with the Monero build using docker.

## Trezor tests

In order to statically build Trezor tests that can run in Travis do the following:

```bash
docker build -f docker/tests/Dockerfile --build-arg BASE_IMAGE=ubuntu:18.04 -t="trezor-tests"  .

# Auto build & extract binary
DOCKER_ID=$(docker run -idt --mount type=bind,src="/tmp/data",dst="/tmp/data" -w "/src" --cap-add SYS_PTRACE --cap-add sys_admin --security-opt seccomp:unconfined --network=host trezor-tests:latest)
docker exec $DOCKER_ID make debug-test-trezor-stat -j3 
docker exec $DOCKER_ID cp ./build/debug/tests/trezor/trezor_tests /tmp/data/trezor_tests
```

- Ubuntu 18.04 is binary compatible with Debian 10.

## Contrib build

Contrib build enables to cross-compile Monero to different platforms (i.e., linux, osx, windows)

```bash
DEBUG=1 TESTS=1 ./docker/build-contrib.sh
```

