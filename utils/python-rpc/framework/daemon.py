# Copyright (c) 2018 The Monero Project
# 
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice, this list of
#    conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice, this list
#    of conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
# 
# 3. Neither the name of the copyright holder nor the names of its contributors may be
#    used to endorse or promote products derived from this software without specific
#    prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""Daemon class to make rpc calls and store state."""

from .rpc import JSONRPC 

class Daemon(object):

    def __init__(self, protocol='http', host='127.0.0.1', port=0, idx=0):
        self.rpc = JSONRPC('{protocol}://{host}:{port}'.format(protocol=protocol, host=host, port=port if port else 18180+idx))

    def getblocktemplate(self, address):
        getblocktemplate = {
            'method': 'getblocktemplate',
            'params': {
                'wallet_address': address,
                'reserve_size' : 1
            },
            'jsonrpc': '2.0', 
            'id': '0'
        }
        return self.rpc.send_json_rpc_request(getblocktemplate)

    def send_raw_transaction(self, tx_as_hex, do_not_relay = False):
        send_raw_transaction = {
            'tx_as_hex': tx_as_hex,
            'do_not_relay': do_not_relay,
        }
        return self.rpc.send_request("/send_raw_transaction", send_raw_transaction)

    def submitblock(self, block):
        submitblock = {
            'method': 'submitblock',
            'params': [ block ],    
            'jsonrpc': '2.0', 
            'id': '0'
        }    
        return self.rpc.send_json_rpc_request(submitblock)

    def getblock(self, height=0):
        getblock = {
            'method': 'getblock',
            'params': {
                'height': height
            },
            'jsonrpc': '2.0', 
            'id': '0'
        }
        return self.rpc.send_json_rpc_request(getblock)

    def getlastblockheader(self):
        getlastblockheader = {
            'method': 'getlastblockheader',
            'params': {
            },
            'jsonrpc': '2.0', 
            'id': '0'
        }
        return self.rpc.send_json_rpc_request(getlastblockheader)

    def getblockheaderbyhash(self, hash):
        getblockheaderbyhash = {
            'method': 'getblockheaderbyhash',
            'params': {
                'hash': hash,
            },
            'jsonrpc': '2.0', 
            'id': '0'
        }
        return self.rpc.send_json_rpc_request(getblockheaderbyhash)

    def getblockheaderbyheight(self, height):
        getblockheaderbyheight = {
            'method': 'getblockheaderbyheight',
            'params': {
                'height': height,
            },
            'jsonrpc': '2.0', 
            'id': '0'
        }
        return self.rpc.send_json_rpc_request(getblockheaderbyheight)

    def getblockheadersrange(self, start_height, end_height, fill_pow_hash = False):
        getblockheadersrange = {
            'method': 'getblockheadersrange',
            'params': {
                'start_height': start_height,
                'end_height': end_height,
                'fill_pow_hash': fill_pow_hash,
            },
            'jsonrpc': '2.0', 
            'id': '0'
        }
        return self.rpc.send_json_rpc_request(getblockheadersrange)

    def get_connections(self):
        get_connections = {
            'method': 'get_connections',
            'jsonrpc': '2.0', 
            'id': '0'
        }
        return self.rpc.send_json_rpc_request(get_connections)

    def get_info(self):
        get_info = {
                'method': 'get_info',
                'jsonrpc': '2.0', 
                'id': '0'
        }    
        return self.rpc.send_json_rpc_request(get_info)

    def hard_fork_info(self):
        hard_fork_info = {
                'method': 'hard_fork_info',
                'jsonrpc': '2.0', 
                'id': '0'
        }    
        return self.rpc.send_json_rpc_request(hard_fork_info)

    def generateblocks(self, address, blocks=1):
        generateblocks = {
            'method': 'generateblocks',
            'params': {
                'amount_of_blocks' : blocks,
                'reserve_size' : 20,
                'wallet_address': address
            },
            'jsonrpc': '2.0', 
            'id': '0'
        }
        return self.rpc.send_json_rpc_request(generateblocks)

    def get_height(self):
        get_height = {
                'method': 'get_height',
                'jsonrpc': '2.0',
                'id': '0'
        }
        return self.rpc.send_request("/get_height", get_height)

    def pop_blocks(self, nblocks = 1):
        pop_blocks = {
            'nblocks' : nblocks,
        }
        return self.rpc.send_request("/pop_blocks", pop_blocks)

    def start_mining(self, miner_address, threads_count = 0, do_background_mining = False, ignore_battery = False):
        start_mining = {
            'miner_address' : miner_address,
            'threads_count' : threads_count,
            'do_background_mining' : do_background_mining,
            'ignore_battery' : ignore_battery,
        }
        return self.rpc.send_request('/start_mining', start_mining)

    def stop_mining(self):
        stop_mining = {
        }
        return self.rpc.send_request('/stop_mining', stop_mining)

    def mining_status(self):
        mining_status = {
        }
        return self.rpc.send_request('/mining_status', mining_status)

    def get_transaction_pool(self):
        get_transaction_pool = {
        }
        return self.rpc.send_request('/get_transaction_pool', get_transaction_pool)

    def get_transaction_pool_hashes(self):
        get_transaction_pool_hashes = {
        }
        return self.rpc.send_request('/get_transaction_pool_hashes', get_transaction_pool_hashes)

    def flush_txpool(self, txids = []):
        flush_txpool = {
            'method': 'flush_txpool',
            'params': {
                'txids': txids
            },
            'jsonrpc': '2.0',
            'id': '0'
        }
        return self.rpc.send_json_rpc_request(flush_txpool)

    def get_version(self):
        get_version = {
            'method': 'get_version',
            'jsonrpc': '2.0',
            'id': '0'
        }
        return self.rpc.send_json_rpc_request(get_version)
