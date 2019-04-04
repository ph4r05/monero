// Copyright (c) 2014-2019, The Monero Project
//
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "gtest/gtest.h"
#include "net/http_auth.h"

#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/fusion/adapted/std_pair.hpp>
#include <boost/range/algorithm/find_if.hpp>
#include <boost/range/iterator_range_core.hpp>
#include <cstdint>
#include <iterator>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>
#include <daemon/core.h>

#include "md5_l.h"
#include "string_tools.h"
#include "crypto/crypto.h"
#include "common/rpc_client.h"
#include "daemon.h"

namespace {
namespace po = boost::program_options;
namespace http = epee::net_utils::http;
using fields = std::unordered_map<std::string, std::string>;
using auth_responses = std::vector<fields>;

}

#define GET_VERSION_MC(m_http_client, VER) \
  cryptonote::COMMAND_RPC_GET_VERSION::request req_t = AUTO_VAL_INIT(req_t);          \
  cryptonote::COMMAND_RPC_GET_VERSION::response resp_t = AUTO_VAL_INIT(resp_t);       \
  bool r = net_utils::invoke_http_json_rpc("/json_rpc", "get_version", req_t, resp_t, m_http_client, std::chrono::seconds(60)); \
                                                                                      \
  CHECK_AND_ASSERT_THROW_MES(r, "RPC error - Get version");                           \
  CHECK_AND_ASSERT_THROW_MES(resp_t.status != CORE_RPC_STATUS_BUSY, "Daemon problem");\
  CHECK_AND_ASSERT_THROW_MES(resp_t.status == CORE_RPC_STATUS_OK, "Daemon response inva lid: " << resp_t.status); \
  VER = resp_t.version

static uint64_t get_version(epee::net_utils::http::http_simple_client & m_http_client)
{
  uint64_t ver;
  GET_VERSION_MC(m_http_client, ver);
  return ver;
}

static uint64_t get_version2(epee::net_utils::http::http_simple_client & m_http_client){
  cryptonote::COMMAND_RPC_GET_VERSION::request req_t = AUTO_VAL_INIT(req_t);
  cryptonote::COMMAND_RPC_GET_VERSION::response resp_t = AUTO_VAL_INIT(resp_t);
  bool r = net_utils::invoke_http_json_rpc("/json_rpc", "get_version", req_t, resp_t, m_http_client, std::chrono::seconds(60));

  CHECK_AND_ASSERT_THROW_MES(r, "RPC error - Get version");
  CHECK_AND_ASSERT_THROW_MES(resp_t.status != CORE_RPC_STATUS_BUSY, "Daemon problem");
  CHECK_AND_ASSERT_THROW_MES(resp_t.status == CORE_RPC_STATUS_OK, "Daemon response inva lid: " << resp_t.status);
  return resp_t.version;
}

TEST(HTTP_Simple_Client, GetHeight)
{
  const char * env_rpc_addr = getenv("RPC_ADDR");
  const char * env_force_ssl = getenv("FORCE_SSL");
  const char * env_poc_method = getenv("POC_METHOD");

  std::string rpc_addr;
  if (!env_rpc_addr || !strlen(env_rpc_addr)){
    MDEBUG("Set RPC_ADDR env var to continue http client test");
  } else {
    rpc_addr = std::string(env_rpc_addr);
  }

  bool use_custom_daemon = false;
  bool force_ssl = env_force_ssl && strlen(env_force_ssl) > 0 ? atoi(env_force_ssl) : 1;
  int poc_method = env_poc_method && strlen(env_poc_method) > 0 ? atoi(env_poc_method) : 0;

  tools::on_startup();
  //epee::string_tools::set_module_name_and_folder("");
  mlog_configure(mlog_get_default_log_path("http_client_tests.log"), true);
  mlog_set_log_level(2);

  std::shared_ptr<mock_daemon> daemon = nullptr;

  if (rpc_addr.empty()) {
    cryptonote::core core_obj(nullptr);
    po::variables_map vm_core;
    po::options_description desc_params_core("Core");
    mock_daemon::init_options(desc_params_core);
    tools::options::build_options(vm_core, desc_params_core);
    mock_daemon::default_options(vm_core);

    daemon = std::make_shared<mock_daemon>(&core_obj, vm_core);
    daemon->try_init_and_run();
    rpc_addr = daemon->rpc_addr();
    use_custom_daemon = true;
  }

  epee::net_utils::http::http_simple_client m_http_client;
  CHECK_AND_ASSERT_THROW_MES(m_http_client.set_server(rpc_addr, boost::none,
                                                      force_ssl ? epee::net_utils::ssl_support_t::e_ssl_support_enabled : epee::net_utils::ssl_support_t::e_ssl_support_autodetect), "HTTP client set failed");
  uint64_t version = 0;
  if (poc_method == 0){
    MDEBUG("Method 0");
    version = get_version(m_http_client);

  } else if (poc_method == 1){
    MDEBUG("Method 1");
    GET_VERSION_MC(m_http_client, version);
  
  } else if (poc_method == 2){
    MDEBUG("Method 2");
    version = get_version2(m_http_client);
  }

  MINFO("Version: " << version);

  if(m_http_client.is_connected())
    m_http_client.disconnect();
  MINFO("DISCONNECTED");
}

