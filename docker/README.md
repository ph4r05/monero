# Docker builds

This dir helps with the Monero build using docker.

## How to test:
```
TEST_MIN_HF=15 TEST_MAX_HF=15 MONERO_RANDOMX_UMASK=8 ./trezor_tests --chain-path chain.bin --fix-chain

# With mining test in wallet api 
TEST_MIN_HF=15 TEST_MAX_HF=15 MONERO_RANDOMX_UMASK=8 \
  TEST_MINING_ENABLED=1 TEST_MINING_TIMEOUT=600 ./trezor_tests --chain-path chain.bin --fix-chain

# Heavy tests included, mining is enabled
TEST_MIN_HF=15 TEST_MAX_HF=15 MONERO_RANDOMX_UMASK=8 ./trezor_tests --chain-path chain.bin --fix-chain --heavy-tests

shasum -a256 trezor_tests
e4e9f1561e008ef7342c54fecd7fc4068d11222e81681a55062222a1d76c6c38  trezor_tests
```

## Tests
- gen_trezor_ki_sync_with_refresh, key-image sync, with live refresh enabled
- gen_trezor_ki_sync_without_refresh, key-image sync, no live refresh
- gen_trezor_live_refresh, key-image sync live refresh test
- gen_trezor_1utxo, simple transaction, 1 input, no change
- gen_trezor_1utxo_paymentid_short, simple tx with payment it, change
- gen_trezor_1utxo_paymentid_short_integrated, simple tx with integrated address (contains payment id), change
- gen_trezor_4utxo, 4 inputs
- gen_trezor_4utxo_acc1, 4 inputs, from different account
- gen_trezor_4utxo_to_sub, 4 inputs, to subaddress
- gen_trezor_4utxo_to_2sub, 4 inputs, to 2 subaddresses
- gen_trezor_4utxo_to_1norm_2sub, 4 inputs, to 2 subaddress and 1 normal address
- gen_trezor_2utxo_sub_acc_to_1norm_2sub, 2 inputs to sub address, to 1 normal and 2 subaddresses
- gen_trezor_4utxo_to_7outs, 4 inputs, 7 outputs + change
- gen_trezor_4utxo_to_15outs, 4 inputs, 15 outputs + change (max)
- gen_trezor_16utxo_to_sub, 16 inputs, 1 output + change
- gen_trezor_many_utxo, 110 inputs (heavy test)
- gen_trezor_many_utxo_many_tx, 40 inputs, 14 outs + change (heavy test)
- gen_trezor_no_passphrase, passphrase disabled on trezot
- gen_trezor_wallet_passphrase, wallet open test with correct and incorrect passphrase
- gen_trezor_passphrase, simple passphrase test, trezor initialized with "a" passphrase
- gen_trezor_pin, trezor PIN entry on the host test
- wallet_api_tests, Monero wallet API test, used in monero-gui (mining is heavy test, optional part)

## How to build custom tests binary:

- Pull the newest master branch
- Checkout my branch `coverity_scan` which adds support for easy Trezor test build.
- Rebase `coverity_scan` on top of the master.
- Build for Ubuntu 18 statically:

```bash

docker build -f docker/tests/Dockerfile --build-arg BASE_IMAGE=ubuntu:18.04 -t="trezor-tests"  .

# Auto build & extract binary
mkdir -p /tmp/data && cd /tmp/data
DOCKER_ID=$(docker run -idt --mount type=bind,src="/root/monero",dst="/src" --mount type=bind,src="/tmp/data",dst="/tmp/data" -w "/src" --cap-add SYS_PTRACE --cap-add sys_admin --security-opt seccomp:unconfined --network=host trezor-tests:latest)
docker exec $DOCKER_ID make debug-test-trezor-stat -j3 
docker exec $DOCKER_ID cp ./build/debug/tests/trezor/trezor_tests /tmp/data/trezor_tests
# copy compiled trezor tests `tests/trezor/trezor_tests` to the host machine

# to get shell:
docker exec -it $DOCKER_ID /bin/bash
```

- Ubuntu 18.04 is binary compatible with Debian 10.

If there is a problem with the Docker build, install dependencies from the Dockerfile and compile outside of the Docker.

Running a trezor simulator:
```bash
sudo apt-get install scons libsdl2-dev libsdl2-image-dev
rm -rf ~/.local/share/virtualenvs

git clone --recursive https://github.com/trezor/trezor-firmware.git
cd trezor-firmware
git submodule update --init --recursive —force

nix-shell
poetry install
poetry shell
DEBUG_BUILD=1 UNIX_PORT_OPTS="PYOPT=0" poetry run make build_unix PYOPT=0
TREZOR_DISABLE_ANIMATION=1 SDL_VIDEODRIVER=dummy PYOPT=0 ./emu.sh
```

Then test:
```bash
/tmp/data/trezor_tests --chain-path chain6.bin

# Change HFs, OSX randomx segfault fix
TEST_MIN_HF=15 TEST_MAX_HF=15 MONERO_RANDOMX_UMASK=8 /tmp/data/trezor_tests --chain-path ../chain6.bin  | tee -a test.txt

# Real device test
TEST_MAX_HF=15 TEST_MIN_HF=15 MONERO_RANDOMX_UMASK=8 TEST_KI_SYNC=1 TREZOR_PATH=webusb:000:1 /Users/dusanklinec/workspace/monero-m2/cmake-build-debug-tests/tests/trezor/trezor_tests --chain-path /tmp/chain6.bin --heavy-tests | tee testout11.txt
```

## Contrib build

Contrib build enables to cross-compile Monero to different platforms (i.e., linux, osx, windows)

```bash
DEBUG=1 TESTS=1 ./docker/build-contrib.sh
```

