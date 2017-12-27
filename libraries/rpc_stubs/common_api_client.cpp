#define DEFAULT_LOGGER "rpc"
#include <fbtc/api/global_api_logger.hpp>
#include <fbtc/api/conversion_functions.hpp>
#include <fbtc/rpc_stubs/common_api_client.hpp>

namespace fbtc { namespace rpc_stubs {

fc::variant_object common_api_client::about() const
{
  ilog("received RPC call: about()", );
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    call_id = glog->log_call_started( this, "about", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call about finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fc::variant_object result = get_impl()->about();
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "about", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fc::variant_object common_api_client::get_info() const
{
  ilog("received RPC call: get_info()", );
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    call_id = glog->log_call_started( this, "get_info", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call get_info finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fc::variant_object result = get_impl()->get_info();
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "get_info", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::stop()
{
  ilog("received RPC call: stop()", );
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    call_id = glog->log_call_started( this, "stop", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call stop finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->stop();
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "stop", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::string common_api_client::help(const std::string& command_name /* = fc::json::from_string("\"\"").as<std::string>() */) const
{
  ilog("received RPC call: help(${command_name})", ("command_name", command_name));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(command_name) );
    call_id = glog->log_call_started( this, "help", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call help finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::string result = get_impl()->help(command_name);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "help", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fc::variant_object common_api_client::validate_address(const std::string& address) const
{
  ilog("received RPC call: validate_address(${address})", ("address", address));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(address) );
    call_id = glog->log_call_started( this, "validate_address", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call validate_address finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fc::variant_object result = get_impl()->validate_address(address);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "validate_address", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::blockchain::address common_api_client::convert_to_native_address(const std::string& raw_address) const
{
  ilog("received RPC call: convert_to_native_address(${raw_address})", ("raw_address", raw_address));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(raw_address) );
    call_id = glog->log_call_started( this, "convert_to_native_address", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call convert_to_native_address finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::blockchain::address result = get_impl()->convert_to_native_address(raw_address);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "convert_to_native_address", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::string common_api_client::execute_command_line(const std::string& input) const
{
  ilog("received RPC call: execute_command_line(*********)", );
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    if( glog->obscure_passwords() )
      args.push_back( fc::variant("*********") );
    else
      args.push_back( fc::variant(input) );
    call_id = glog->log_call_started( this, "execute_command_line", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call execute_command_line finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::string result = get_impl()->execute_command_line(input);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "execute_command_line", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::execute_script(const fc::path& script) const
{
  ilog("received RPC call: execute_script(${script})", ("script", script));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(script) );
    call_id = glog->log_call_started( this, "execute_script", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call execute_script finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->execute_script(script);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "execute_script", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fc::variants common_api_client::batch(const std::string& method_name, const std::vector<fc::variants>& parameters_list) const
{
  ilog("received RPC call: batch(${method_name}, ${parameters_list})", ("method_name", method_name)("parameters_list", parameters_list));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(method_name) );
    args.push_back( fc::variant(parameters_list) );
    call_id = glog->log_call_started( this, "batch", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call batch finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fc::variants result = get_impl()->batch(method_name, parameters_list);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "batch", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fc::variants common_api_client::batch_authenticated(const std::string& method_name, const std::vector<fc::variants>& parameters_list) const
{
  ilog("received RPC call: batch_authenticated(${method_name}, ${parameters_list})", ("method_name", method_name)("parameters_list", parameters_list));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(method_name) );
    args.push_back( fc::variant(parameters_list) );
    call_id = glog->log_call_started( this, "batch_authenticated", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call batch_authenticated finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fc::variants result = get_impl()->batch_authenticated(method_name, parameters_list);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "batch_authenticated", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::builder_finalize_and_sign(const fbtc::wallet::transaction_builder& builder) const
{
  ilog("received RPC call: builder_finalize_and_sign(${builder})", ("builder", builder));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(builder) );
    call_id = glog->log_call_started( this, "builder_finalize_and_sign", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call builder_finalize_and_sign finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->builder_finalize_and_sign(builder);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "builder_finalize_and_sign", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::map<std::string, fbtc::api::method_data> common_api_client::meta_help() const
{
  ilog("received RPC call: meta_help()", );
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    call_id = glog->log_call_started( this, "meta_help", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call meta_help finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::map<std::string, fbtc::api::method_data> result = get_impl()->meta_help();
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "meta_help", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::rpc_set_username(const std::string& username /* = fc::json::from_string("\"\"").as<std::string>() */)
{
  ilog("received RPC call: rpc_set_username(${username})", ("username", username));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(username) );
    call_id = glog->log_call_started( this, "rpc_set_username", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call rpc_set_username finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->rpc_set_username(username);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "rpc_set_username", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::rpc_set_password(const std::string& password /* = fc::json::from_string("\"\"").as<std::string>() */)
{
  ilog("received RPC call: rpc_set_password(*********)", );
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    if( glog->obscure_passwords() )
      args.push_back( fc::variant("*********") );
    else
      args.push_back( fc::variant(password) );
    call_id = glog->log_call_started( this, "rpc_set_password", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call rpc_set_password finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->rpc_set_password(password);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "rpc_set_password", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::rpc_start_server(uint32_t port /* = fc::json::from_string("\"65065\"").as<uint32_t>() */)
{
  ilog("received RPC call: rpc_start_server(${port})", ("port", port));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(port) );
    call_id = glog->log_call_started( this, "rpc_start_server", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call rpc_start_server finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->rpc_start_server(port);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "rpc_start_server", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::http_start_server(uint32_t port /* = fc::json::from_string("\"65066\"").as<uint32_t>() */)
{
  ilog("received RPC call: http_start_server(${port})", ("port", port));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(port) );
    call_id = glog->log_call_started( this, "http_start_server", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call http_start_server finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->http_start_server(port);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "http_start_server", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::ntp_update_time()
{
  ilog("received RPC call: ntp_update_time()", );
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    call_id = glog->log_call_started( this, "ntp_update_time", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call ntp_update_time finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->ntp_update_time();
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "ntp_update_time", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fc::variant common_api_client::disk_usage() const
{
  ilog("received RPC call: disk_usage()", );
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    call_id = glog->log_call_started( this, "disk_usage", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call disk_usage finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fc::variant result = get_impl()->disk_usage();
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "disk_usage", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::network_add_node(const std::string& node, const std::string& command /* = fc::json::from_string("\"add\"").as<std::string>() */)
{
  ilog("received RPC call: network_add_node(${node}, ${command})", ("node", node)("command", command));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(node) );
    args.push_back( fc::variant(command) );
    call_id = glog->log_call_started( this, "network_add_node", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call network_add_node finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->network_add_node(node, command);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "network_add_node", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

uint32_t common_api_client::network_get_connection_count() const
{
  ilog("received RPC call: network_get_connection_count()", );
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    call_id = glog->log_call_started( this, "network_get_connection_count", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call network_get_connection_count finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    uint32_t result = get_impl()->network_get_connection_count();
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "network_get_connection_count", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::vector<fc::variant_object> common_api_client::network_get_peer_info(bool not_firewalled /* = fc::json::from_string("false").as<bool>() */) const
{
  ilog("received RPC call: network_get_peer_info(${not_firewalled})", ("not_firewalled", not_firewalled));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(not_firewalled) );
    call_id = glog->log_call_started( this, "network_get_peer_info", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call network_get_peer_info finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::vector<fc::variant_object> result = get_impl()->network_get_peer_info(not_firewalled);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "network_get_peer_info", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::blockchain::transaction_id_type common_api_client::network_broadcast_transaction(const fbtc::blockchain::signed_transaction& transaction_to_broadcast)
{
  ilog("received RPC call: network_broadcast_transaction(${transaction_to_broadcast})", ("transaction_to_broadcast", transaction_to_broadcast));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(transaction_to_broadcast) );
    call_id = glog->log_call_started( this, "network_broadcast_transaction", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call network_broadcast_transaction finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::blockchain::transaction_id_type result = get_impl()->network_broadcast_transaction(transaction_to_broadcast);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "network_broadcast_transaction", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::network_set_advanced_node_parameters(const fc::variant_object& params)
{
  ilog("received RPC call: network_set_advanced_node_parameters(${params})", ("params", params));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(params) );
    call_id = glog->log_call_started( this, "network_set_advanced_node_parameters", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call network_set_advanced_node_parameters finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->network_set_advanced_node_parameters(params);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "network_set_advanced_node_parameters", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fc::variant_object common_api_client::network_get_advanced_node_parameters() const
{
  ilog("received RPC call: network_get_advanced_node_parameters()", );
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    call_id = glog->log_call_started( this, "network_get_advanced_node_parameters", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call network_get_advanced_node_parameters finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fc::variant_object result = get_impl()->network_get_advanced_node_parameters();
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "network_get_advanced_node_parameters", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::net::message_propagation_data common_api_client::network_get_transaction_propagation_data(const fbtc::blockchain::transaction_id_type& transaction_id)
{
  ilog("received RPC call: network_get_transaction_propagation_data(${transaction_id})", ("transaction_id", transaction_id));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(transaction_id) );
    call_id = glog->log_call_started( this, "network_get_transaction_propagation_data", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call network_get_transaction_propagation_data finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::net::message_propagation_data result = get_impl()->network_get_transaction_propagation_data(transaction_id);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "network_get_transaction_propagation_data", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::net::message_propagation_data common_api_client::network_get_block_propagation_data(const fbtc::blockchain::block_id_type& block_hash)
{
  ilog("received RPC call: network_get_block_propagation_data(${block_hash})", ("block_hash", block_hash));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(block_hash) );
    call_id = glog->log_call_started( this, "network_get_block_propagation_data", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call network_get_block_propagation_data finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::net::message_propagation_data result = get_impl()->network_get_block_propagation_data(block_hash);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "network_get_block_propagation_data", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::network_set_allowed_peers(const std::vector<fbtc::net::node_id_t>& allowed_peers)
{
  ilog("received RPC call: network_set_allowed_peers(${allowed_peers})", ("allowed_peers", allowed_peers));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(allowed_peers) );
    call_id = glog->log_call_started( this, "network_set_allowed_peers", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call network_set_allowed_peers finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->network_set_allowed_peers(allowed_peers);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "network_set_allowed_peers", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fc::variant_object common_api_client::network_get_info() const
{
  ilog("received RPC call: network_get_info()", );
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    call_id = glog->log_call_started( this, "network_get_info", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call network_get_info finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fc::variant_object result = get_impl()->network_get_info();
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "network_get_info", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::vector<fbtc::net::potential_peer_record> common_api_client::network_list_potential_peers() const
{
  ilog("received RPC call: network_list_potential_peers()", );
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    call_id = glog->log_call_started( this, "network_list_potential_peers", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call network_list_potential_peers finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::vector<fbtc::net::potential_peer_record> result = get_impl()->network_list_potential_peers();
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "network_list_potential_peers", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fc::variant_object common_api_client::network_get_upnp_info() const
{
  ilog("received RPC call: network_get_upnp_info()", );
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    call_id = glog->log_call_started( this, "network_get_upnp_info", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call network_get_upnp_info finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fc::variant_object result = get_impl()->network_get_upnp_info();
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "network_get_upnp_info", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fc::variant_object common_api_client::network_get_usage_stats() const
{
  ilog("received RPC call: network_get_usage_stats()", );
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    call_id = glog->log_call_started( this, "network_get_usage_stats", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call network_get_usage_stats finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fc::variant_object result = get_impl()->network_get_usage_stats();
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "network_get_usage_stats", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fc::variant common_api_client::delegate_get_config() const
{
  ilog("received RPC call: delegate_get_config()", );
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    call_id = glog->log_call_started( this, "delegate_get_config", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call delegate_get_config finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fc::variant result = get_impl()->delegate_get_config();
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "delegate_get_config", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::delegate_set_network_min_connection_count(uint32_t count)
{
  ilog("received RPC call: delegate_set_network_min_connection_count(${count})", ("count", count));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(count) );
    call_id = glog->log_call_started( this, "delegate_set_network_min_connection_count", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call delegate_set_network_min_connection_count finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->delegate_set_network_min_connection_count(count);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "delegate_set_network_min_connection_count", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::delegate_set_block_max_transaction_count(uint32_t count)
{
  ilog("received RPC call: delegate_set_block_max_transaction_count(${count})", ("count", count));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(count) );
    call_id = glog->log_call_started( this, "delegate_set_block_max_transaction_count", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call delegate_set_block_max_transaction_count finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->delegate_set_block_max_transaction_count(count);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "delegate_set_block_max_transaction_count", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::delegate_set_block_max_size(uint32_t size)
{
  ilog("received RPC call: delegate_set_block_max_size(${size})", ("size", size));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(size) );
    call_id = glog->log_call_started( this, "delegate_set_block_max_size", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call delegate_set_block_max_size finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->delegate_set_block_max_size(size);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "delegate_set_block_max_size", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::delegate_set_block_max_production_time(uint64_t time)
{
  ilog("received RPC call: delegate_set_block_max_production_time(${time})", ("time", time));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(time) );
    call_id = glog->log_call_started( this, "delegate_set_block_max_production_time", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call delegate_set_block_max_production_time finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->delegate_set_block_max_production_time(time);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "delegate_set_block_max_production_time", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::delegate_set_transaction_max_size(uint32_t size)
{
  ilog("received RPC call: delegate_set_transaction_max_size(${size})", ("size", size));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(size) );
    call_id = glog->log_call_started( this, "delegate_set_transaction_max_size", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call delegate_set_transaction_max_size finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->delegate_set_transaction_max_size(size);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "delegate_set_transaction_max_size", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::delegate_set_transaction_canonical_signatures_required(bool required)
{
  ilog("received RPC call: delegate_set_transaction_canonical_signatures_required(${required})", ("required", required));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(required) );
    call_id = glog->log_call_started( this, "delegate_set_transaction_canonical_signatures_required", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call delegate_set_transaction_canonical_signatures_required finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->delegate_set_transaction_canonical_signatures_required(required);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "delegate_set_transaction_canonical_signatures_required", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::delegate_set_transaction_min_fee(uint64_t fee)
{
  ilog("received RPC call: delegate_set_transaction_min_fee(${fee})", ("fee", fee));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(fee) );
    call_id = glog->log_call_started( this, "delegate_set_transaction_min_fee", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call delegate_set_transaction_min_fee finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->delegate_set_transaction_min_fee(fee);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "delegate_set_transaction_min_fee", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::delegate_blacklist_add_transaction(const fbtc::blockchain::transaction_id_type& id)
{
  ilog("received RPC call: delegate_blacklist_add_transaction(${id})", ("id", id));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(id) );
    call_id = glog->log_call_started( this, "delegate_blacklist_add_transaction", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call delegate_blacklist_add_transaction finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->delegate_blacklist_add_transaction(id);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "delegate_blacklist_add_transaction", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::delegate_blacklist_remove_transaction(const fbtc::blockchain::transaction_id_type& id)
{
  ilog("received RPC call: delegate_blacklist_remove_transaction(${id})", ("id", id));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(id) );
    call_id = glog->log_call_started( this, "delegate_blacklist_remove_transaction", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call delegate_blacklist_remove_transaction finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->delegate_blacklist_remove_transaction(id);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "delegate_blacklist_remove_transaction", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::delegate_blacklist_add_operation(const fbtc::blockchain::operation_type_enum& id)
{
  ilog("received RPC call: delegate_blacklist_add_operation(${id})", ("id", id));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(id) );
    call_id = glog->log_call_started( this, "delegate_blacklist_add_operation", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call delegate_blacklist_add_operation finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->delegate_blacklist_add_operation(id);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "delegate_blacklist_add_operation", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::delegate_blacklist_remove_operation(const fbtc::blockchain::operation_type_enum& id)
{
  ilog("received RPC call: delegate_blacklist_remove_operation(${id})", ("id", id));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(id) );
    call_id = glog->log_call_started( this, "delegate_blacklist_remove_operation", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call delegate_blacklist_remove_operation finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->delegate_blacklist_remove_operation(id);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "delegate_blacklist_remove_operation", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fc::variant_object common_api_client::blockchain_get_info() const
{
  ilog("received RPC call: blockchain_get_info()", );
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    call_id = glog->log_call_started( this, "blockchain_get_info", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_get_info finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fc::variant_object result = get_impl()->blockchain_get_info();
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_get_info", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::blockchain_generate_snapshot(const std::string& filename) const
{
  ilog("received RPC call: blockchain_generate_snapshot(${filename})", ("filename", filename));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(filename) );
    call_id = glog->log_call_started( this, "blockchain_generate_snapshot", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_generate_snapshot finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->blockchain_generate_snapshot(filename);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_generate_snapshot", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::blockchain_graphene_snapshot(const std::string& filename, const std::string& whitelist_filename /* = fc::json::from_string("\"\"").as<std::string>() */) const
{
  ilog("received RPC call: blockchain_graphene_snapshot(${filename}, ${whitelist_filename})", ("filename", filename)("whitelist_filename", whitelist_filename));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(filename) );
    args.push_back( fc::variant(whitelist_filename) );
    call_id = glog->log_call_started( this, "blockchain_graphene_snapshot", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_graphene_snapshot finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->blockchain_graphene_snapshot(filename, whitelist_filename);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_graphene_snapshot", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::blockchain_generate_issuance_map(const std::string& symbol, const std::string& filename) const
{
  ilog("received RPC call: blockchain_generate_issuance_map(${symbol}, ${filename})", ("symbol", symbol)("filename", filename));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(symbol) );
    args.push_back( fc::variant(filename) );
    call_id = glog->log_call_started( this, "blockchain_generate_issuance_map", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_generate_issuance_map finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->blockchain_generate_issuance_map(symbol, filename);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_generate_issuance_map", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::blockchain::asset common_api_client::blockchain_calculate_supply(const std::string& asset) const
{
  ilog("received RPC call: blockchain_calculate_supply(${asset})", ("asset", asset));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(asset) );
    call_id = glog->log_call_started( this, "blockchain_calculate_supply", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_calculate_supply finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::blockchain::asset result = get_impl()->blockchain_calculate_supply(asset);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_calculate_supply", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::blockchain::asset common_api_client::blockchain_calculate_debt(const std::string& asset, bool include_interest /* = fc::json::from_string("\"false\"").as<bool>() */) const
{
  ilog("received RPC call: blockchain_calculate_debt(${asset}, ${include_interest})", ("asset", asset)("include_interest", include_interest));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(asset) );
    args.push_back( fc::variant(include_interest) );
    call_id = glog->log_call_started( this, "blockchain_calculate_debt", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_calculate_debt finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::blockchain::asset result = get_impl()->blockchain_calculate_debt(asset, include_interest);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_calculate_debt", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::blockchain::asset common_api_client::blockchain_calculate_max_supply(uint8_t average_delegate_pay_rate /* = fc::json::from_string("100").as<uint8_t>() */) const
{
  ilog("received RPC call: blockchain_calculate_max_supply(${average_delegate_pay_rate})", ("average_delegate_pay_rate", average_delegate_pay_rate));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(average_delegate_pay_rate) );
    call_id = glog->log_call_started( this, "blockchain_calculate_max_supply", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_calculate_max_supply finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::blockchain::asset result = get_impl()->blockchain_calculate_max_supply(average_delegate_pay_rate);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_calculate_max_supply", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

uint32_t common_api_client::blockchain_get_block_count() const
{
  ilog("received RPC call: blockchain_get_block_count()", );
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    call_id = glog->log_call_started( this, "blockchain_get_block_count", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_get_block_count finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    uint32_t result = get_impl()->blockchain_get_block_count();
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_get_block_count", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::vector<fbtc::blockchain::account_record> common_api_client::blockchain_list_accounts(const std::string& first_account_name /* = fc::json::from_string("\"\"").as<std::string>() */, uint32_t limit /* = fc::json::from_string("20").as<uint32_t>() */) const
{
  ilog("received RPC call: blockchain_list_accounts(${first_account_name}, ${limit})", ("first_account_name", first_account_name)("limit", limit));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(first_account_name) );
    args.push_back( fc::variant(limit) );
    call_id = glog->log_call_started( this, "blockchain_list_accounts", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_list_accounts finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::vector<fbtc::blockchain::account_record> result = get_impl()->blockchain_list_accounts(first_account_name, limit);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_list_accounts", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::vector<fbtc::blockchain::account_record> common_api_client::blockchain_list_recently_updated_accounts() const
{
  ilog("received RPC call: blockchain_list_recently_updated_accounts()", );
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    call_id = glog->log_call_started( this, "blockchain_list_recently_updated_accounts", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_list_recently_updated_accounts finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::vector<fbtc::blockchain::account_record> result = get_impl()->blockchain_list_recently_updated_accounts();
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_list_recently_updated_accounts", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::vector<fbtc::blockchain::account_record> common_api_client::blockchain_list_recently_registered_accounts() const
{
  ilog("received RPC call: blockchain_list_recently_registered_accounts()", );
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    call_id = glog->log_call_started( this, "blockchain_list_recently_registered_accounts", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_list_recently_registered_accounts finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::vector<fbtc::blockchain::account_record> result = get_impl()->blockchain_list_recently_registered_accounts();
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_list_recently_registered_accounts", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::vector<fbtc::blockchain::asset_record> common_api_client::blockchain_list_assets(const std::string& first_symbol /* = fc::json::from_string("\"\"").as<std::string>() */, uint32_t limit /* = fc::json::from_string("20").as<uint32_t>() */) const
{
  ilog("received RPC call: blockchain_list_assets(${first_symbol}, ${limit})", ("first_symbol", first_symbol)("limit", limit));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(first_symbol) );
    args.push_back( fc::variant(limit) );
    call_id = glog->log_call_started( this, "blockchain_list_assets", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_list_assets finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::vector<fbtc::blockchain::asset_record> result = get_impl()->blockchain_list_assets(first_symbol, limit);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_list_assets", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::map<std::string, std::string> common_api_client::blockchain_list_feed_prices() const
{
  ilog("received RPC call: blockchain_list_feed_prices()", );
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    call_id = glog->log_call_started( this, "blockchain_list_feed_prices", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_list_feed_prices finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::map<std::string, std::string> result = get_impl()->blockchain_list_feed_prices();
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_list_feed_prices", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::vector<fbtc::blockchain::burn_record> common_api_client::blockchain_get_account_wall(const std::string& account_name /* = fc::json::from_string("\"\"").as<std::string>() */) const
{
  ilog("received RPC call: blockchain_get_account_wall(${account_name})", ("account_name", account_name));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(account_name) );
    call_id = glog->log_call_started( this, "blockchain_get_account_wall", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_get_account_wall finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::vector<fbtc::blockchain::burn_record> result = get_impl()->blockchain_get_account_wall(account_name);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_get_account_wall", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::vector<fbtc::blockchain::signed_transaction> common_api_client::blockchain_list_pending_transactions() const
{
  ilog("received RPC call: blockchain_list_pending_transactions()", );
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    call_id = glog->log_call_started( this, "blockchain_list_pending_transactions", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_list_pending_transactions finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::vector<fbtc::blockchain::signed_transaction> result = get_impl()->blockchain_list_pending_transactions();
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_list_pending_transactions", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

int32_t common_api_client::blockchain_get_pending_transactions_count() const
{
  ilog("received RPC call: blockchain_get_pending_transactions_count()", );
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    call_id = glog->log_call_started( this, "blockchain_get_pending_transactions_count", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_get_pending_transactions_count finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    int32_t result = get_impl()->blockchain_get_pending_transactions_count();
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_get_pending_transactions_count", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::pair<fbtc::blockchain::transaction_id_type, fbtc::blockchain::transaction_record> common_api_client::blockchain_get_transaction(const std::string& transaction_id_prefix, bool exact /* = fc::json::from_string("false").as<bool>() */) const
{
  ilog("received RPC call: blockchain_get_transaction(${transaction_id_prefix}, ${exact})", ("transaction_id_prefix", transaction_id_prefix)("exact", exact));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(transaction_id_prefix) );
    args.push_back( fc::variant(exact) );
    call_id = glog->log_call_started( this, "blockchain_get_transaction", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_get_transaction finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::pair<fbtc::blockchain::transaction_id_type, fbtc::blockchain::transaction_record> result = get_impl()->blockchain_get_transaction(transaction_id_prefix, exact);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_get_transaction", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fc::optional<fbtc::blockchain::block_record> common_api_client::blockchain_get_block(const std::string& block) const
{
  ilog("received RPC call: blockchain_get_block(${block})", ("block", block));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(block) );
    call_id = glog->log_call_started( this, "blockchain_get_block", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_get_block finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fc::optional<fbtc::blockchain::block_record> result = get_impl()->blockchain_get_block(block);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_get_block", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::map<fbtc::blockchain::transaction_id_type, fbtc::blockchain::transaction_record> common_api_client::blockchain_get_block_transactions(const std::string& block) const
{
  ilog("received RPC call: blockchain_get_block_transactions(${block})", ("block", block));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(block) );
    call_id = glog->log_call_started( this, "blockchain_get_block_transactions", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_get_block_transactions finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::map<fbtc::blockchain::transaction_id_type, fbtc::blockchain::transaction_record> result = get_impl()->blockchain_get_block_transactions(block);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_get_block_transactions", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fc::optional<fbtc::blockchain::account_record> common_api_client::blockchain_get_account(const std::string& account) const
{
  ilog("received RPC call: blockchain_get_account(${account})", ("account", account));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(account) );
    call_id = glog->log_call_started( this, "blockchain_get_account", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_get_account finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fc::optional<fbtc::blockchain::account_record> result = get_impl()->blockchain_get_account(account);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_get_account", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::map<fbtc::blockchain::account_id_type, std::string> common_api_client::blockchain_get_slate(const std::string& slate) const
{
  ilog("received RPC call: blockchain_get_slate(${slate})", ("slate", slate));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(slate) );
    call_id = glog->log_call_started( this, "blockchain_get_slate", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_get_slate finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::map<fbtc::blockchain::account_id_type, std::string> result = get_impl()->blockchain_get_slate(slate);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_get_slate", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::blockchain::balance_record common_api_client::blockchain_get_balance(const fbtc::blockchain::address& balance_id) const
{
  ilog("received RPC call: blockchain_get_balance(${balance_id})", ("balance_id", balance_id));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(balance_id) );
    call_id = glog->log_call_started( this, "blockchain_get_balance", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_get_balance finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::blockchain::balance_record result = get_impl()->blockchain_get_balance(balance_id);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_get_balance", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::unordered_map<fbtc::blockchain::balance_id_type, fbtc::blockchain::balance_record> common_api_client::blockchain_list_balances(const std::string& asset /* = fc::json::from_string("\"0\"").as<std::string>() */, uint32_t limit /* = fc::json::from_string("20").as<uint32_t>() */) const
{
  ilog("received RPC call: blockchain_list_balances(${asset}, ${limit})", ("asset", asset)("limit", limit));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(asset) );
    args.push_back( fc::variant(limit) );
    call_id = glog->log_call_started( this, "blockchain_list_balances", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_list_balances finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::unordered_map<fbtc::blockchain::balance_id_type, fbtc::blockchain::balance_record> result = get_impl()->blockchain_list_balances(asset, limit);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_list_balances", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::unordered_map<fbtc::blockchain::balance_id_type, fbtc::blockchain::balance_record> common_api_client::blockchain_list_address_balances(const std::string& addr, const fc::time_point& chanced_since /* = fc::json::from_string("\"1970-1-1T00:00:01\"").as<fc::time_point>() */) const
{
  ilog("received RPC call: blockchain_list_address_balances(${addr}, ${chanced_since})", ("addr", addr)("chanced_since", chanced_since));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(addr) );
    args.push_back( fc::variant(chanced_since) );
    call_id = glog->log_call_started( this, "blockchain_list_address_balances", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_list_address_balances finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::unordered_map<fbtc::blockchain::balance_id_type, fbtc::blockchain::balance_record> result = get_impl()->blockchain_list_address_balances(addr, chanced_since);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_list_address_balances", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fc::variant_object common_api_client::blockchain_list_address_transactions(const std::string& addr, uint32_t filter_before /* = fc::json::from_string("\"0\"").as<uint32_t>() */) const
{
  ilog("received RPC call: blockchain_list_address_transactions(${addr}, ${filter_before})", ("addr", addr)("filter_before", filter_before));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(addr) );
    args.push_back( fc::variant(filter_before) );
    call_id = glog->log_call_started( this, "blockchain_list_address_transactions", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_list_address_transactions finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fc::variant_object result = get_impl()->blockchain_list_address_transactions(addr, filter_before);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_list_address_transactions", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::map<fbtc::blockchain::asset_id_type, fbtc::blockchain::share_type> common_api_client::blockchain_get_account_public_balance(const std::string& account_name) const
{
  ilog("received RPC call: blockchain_get_account_public_balance(${account_name})", ("account_name", account_name));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(account_name) );
    call_id = glog->log_call_started( this, "blockchain_get_account_public_balance", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_get_account_public_balance finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::map<fbtc::blockchain::asset_id_type, fbtc::blockchain::share_type> result = get_impl()->blockchain_get_account_public_balance(account_name);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_get_account_public_balance", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::string common_api_client::blockchain_median_feed_price(const std::string& symbol) const
{
  ilog("received RPC call: blockchain_median_feed_price(${symbol})", ("symbol", symbol));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(symbol) );
    call_id = glog->log_call_started( this, "blockchain_median_feed_price", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_median_feed_price finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::string result = get_impl()->blockchain_median_feed_price(symbol);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_median_feed_price", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::unordered_map<fbtc::blockchain::balance_id_type, fbtc::blockchain::balance_record> common_api_client::blockchain_list_key_balances(const fbtc::blockchain::public_key_type& key) const
{
  ilog("received RPC call: blockchain_list_key_balances(${key})", ("key", key));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(key) );
    call_id = glog->log_call_started( this, "blockchain_list_key_balances", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_list_key_balances finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::unordered_map<fbtc::blockchain::balance_id_type, fbtc::blockchain::balance_record> result = get_impl()->blockchain_list_key_balances(key);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_list_key_balances", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fc::optional<fbtc::blockchain::asset_record> common_api_client::blockchain_get_asset(const std::string& asset) const
{
  ilog("received RPC call: blockchain_get_asset(${asset})", ("asset", asset));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(asset) );
    call_id = glog->log_call_started( this, "blockchain_get_asset", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_get_asset finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fc::optional<fbtc::blockchain::asset_record> result = get_impl()->blockchain_get_asset(asset);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_get_asset", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::vector<fbtc::blockchain::feed_entry> common_api_client::blockchain_get_feeds_for_asset(const std::string& asset) const
{
  ilog("received RPC call: blockchain_get_feeds_for_asset(${asset})", ("asset", asset));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(asset) );
    call_id = glog->log_call_started( this, "blockchain_get_feeds_for_asset", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_get_feeds_for_asset finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::vector<fbtc::blockchain::feed_entry> result = get_impl()->blockchain_get_feeds_for_asset(asset);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_get_feeds_for_asset", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::vector<fbtc::blockchain::feed_entry> common_api_client::blockchain_get_feeds_from_delegate(const std::string& delegate_name) const
{
  ilog("received RPC call: blockchain_get_feeds_from_delegate(${delegate_name})", ("delegate_name", delegate_name));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(delegate_name) );
    call_id = glog->log_call_started( this, "blockchain_get_feeds_from_delegate", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_get_feeds_from_delegate finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::vector<fbtc::blockchain::feed_entry> result = get_impl()->blockchain_get_feeds_from_delegate(delegate_name);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_get_feeds_from_delegate", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::vector<fbtc::blockchain::market_order> common_api_client::blockchain_market_list_bids(const std::string& quote_symbol, const std::string& base_symbol, uint32_t limit /* = fc::json::from_string("\"-1\"").as<uint32_t>() */) const
{
  ilog("received RPC call: blockchain_market_list_bids(${quote_symbol}, ${base_symbol}, ${limit})", ("quote_symbol", quote_symbol)("base_symbol", base_symbol)("limit", limit));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(quote_symbol) );
    args.push_back( fc::variant(base_symbol) );
    args.push_back( fc::variant(limit) );
    call_id = glog->log_call_started( this, "blockchain_market_list_bids", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_market_list_bids finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::vector<fbtc::blockchain::market_order> result = get_impl()->blockchain_market_list_bids(quote_symbol, base_symbol, limit);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_market_list_bids", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::vector<fbtc::blockchain::market_order> common_api_client::blockchain_market_list_asks(const std::string& quote_symbol, const std::string& base_symbol, uint32_t limit /* = fc::json::from_string("\"-1\"").as<uint32_t>() */) const
{
  ilog("received RPC call: blockchain_market_list_asks(${quote_symbol}, ${base_symbol}, ${limit})", ("quote_symbol", quote_symbol)("base_symbol", base_symbol)("limit", limit));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(quote_symbol) );
    args.push_back( fc::variant(base_symbol) );
    args.push_back( fc::variant(limit) );
    call_id = glog->log_call_started( this, "blockchain_market_list_asks", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_market_list_asks finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::vector<fbtc::blockchain::market_order> result = get_impl()->blockchain_market_list_asks(quote_symbol, base_symbol, limit);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_market_list_asks", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::vector<fbtc::blockchain::market_order> common_api_client::blockchain_market_list_shorts(const std::string& quote_symbol, uint32_t limit /* = fc::json::from_string("\"-1\"").as<uint32_t>() */) const
{
  ilog("received RPC call: blockchain_market_list_shorts(${quote_symbol}, ${limit})", ("quote_symbol", quote_symbol)("limit", limit));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(quote_symbol) );
    args.push_back( fc::variant(limit) );
    call_id = glog->log_call_started( this, "blockchain_market_list_shorts", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_market_list_shorts finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::vector<fbtc::blockchain::market_order> result = get_impl()->blockchain_market_list_shorts(quote_symbol, limit);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_market_list_shorts", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::vector<fbtc::blockchain::market_order> common_api_client::blockchain_market_list_covers(const std::string& quote_symbol, const std::string& base_symbol /* = fc::json::from_string("\"XTS\"").as<std::string>() */, uint32_t limit /* = fc::json::from_string("\"-1\"").as<uint32_t>() */) const
{
  ilog("received RPC call: blockchain_market_list_covers(${quote_symbol}, ${base_symbol}, ${limit})", ("quote_symbol", quote_symbol)("base_symbol", base_symbol)("limit", limit));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(quote_symbol) );
    args.push_back( fc::variant(base_symbol) );
    args.push_back( fc::variant(limit) );
    call_id = glog->log_call_started( this, "blockchain_market_list_covers", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_market_list_covers finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::vector<fbtc::blockchain::market_order> result = get_impl()->blockchain_market_list_covers(quote_symbol, base_symbol, limit);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_market_list_covers", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::blockchain::share_type common_api_client::blockchain_market_get_asset_collateral(const std::string& symbol) const
{
  ilog("received RPC call: blockchain_market_get_asset_collateral(${symbol})", ("symbol", symbol));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(symbol) );
    call_id = glog->log_call_started( this, "blockchain_market_get_asset_collateral", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_market_get_asset_collateral finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::blockchain::share_type result = get_impl()->blockchain_market_get_asset_collateral(symbol);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_market_get_asset_collateral", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::pair<std::vector<fbtc::blockchain::market_order>,std::vector<fbtc::blockchain::market_order>> common_api_client::blockchain_market_order_book(const std::string& quote_symbol, const std::string& base_symbol, uint32_t limit /* = fc::json::from_string("\"10\"").as<uint32_t>() */) const
{
  ilog("received RPC call: blockchain_market_order_book(${quote_symbol}, ${base_symbol}, ${limit})", ("quote_symbol", quote_symbol)("base_symbol", base_symbol)("limit", limit));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(quote_symbol) );
    args.push_back( fc::variant(base_symbol) );
    args.push_back( fc::variant(limit) );
    call_id = glog->log_call_started( this, "blockchain_market_order_book", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_market_order_book finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::pair<std::vector<fbtc::blockchain::market_order>,std::vector<fbtc::blockchain::market_order>> result = get_impl()->blockchain_market_order_book(quote_symbol, base_symbol, limit);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_market_order_book", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::blockchain::market_order common_api_client::blockchain_get_market_order(const std::string& order_id) const
{
  ilog("received RPC call: blockchain_get_market_order(${order_id})", ("order_id", order_id));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(order_id) );
    call_id = glog->log_call_started( this, "blockchain_get_market_order", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_get_market_order finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::blockchain::market_order result = get_impl()->blockchain_get_market_order(order_id);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_get_market_order", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::map<fbtc::blockchain::order_id_type, fbtc::blockchain::market_order> common_api_client::blockchain_list_address_orders(const std::string& base_symbol, const std::string& quote_symbol, const std::string& account_address, uint32_t limit /* = fc::json::from_string("\"10\"").as<uint32_t>() */) const
{
  ilog("received RPC call: blockchain_list_address_orders(${base_symbol}, ${quote_symbol}, ${account_address}, ${limit})", ("base_symbol", base_symbol)("quote_symbol", quote_symbol)("account_address", account_address)("limit", limit));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(base_symbol) );
    args.push_back( fc::variant(quote_symbol) );
    args.push_back( fc::variant(account_address) );
    args.push_back( fc::variant(limit) );
    call_id = glog->log_call_started( this, "blockchain_list_address_orders", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_list_address_orders finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::map<fbtc::blockchain::order_id_type, fbtc::blockchain::market_order> result = get_impl()->blockchain_list_address_orders(base_symbol, quote_symbol, account_address, limit);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_list_address_orders", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::vector<fbtc::blockchain::order_history_record> common_api_client::blockchain_market_order_history(const std::string& quote_symbol, const std::string& base_symbol, uint32_t skip_count /* = fc::json::from_string("\"0\"").as<uint32_t>() */, uint32_t limit /* = fc::json::from_string("\"20\"").as<uint32_t>() */, const std::string& owner /* = fc::json::from_string("\"\"").as<std::string>() */) const
{
  ilog("received RPC call: blockchain_market_order_history(${quote_symbol}, ${base_symbol}, ${skip_count}, ${limit}, ${owner})", ("quote_symbol", quote_symbol)("base_symbol", base_symbol)("skip_count", skip_count)("limit", limit)("owner", owner));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(quote_symbol) );
    args.push_back( fc::variant(base_symbol) );
    args.push_back( fc::variant(skip_count) );
    args.push_back( fc::variant(limit) );
    args.push_back( fc::variant(owner) );
    call_id = glog->log_call_started( this, "blockchain_market_order_history", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_market_order_history finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::vector<fbtc::blockchain::order_history_record> result = get_impl()->blockchain_market_order_history(quote_symbol, base_symbol, skip_count, limit, owner);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_market_order_history", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::blockchain::market_history_points common_api_client::blockchain_market_price_history(const std::string& quote_symbol, const std::string& base_symbol, const fc::time_point& start_time, const fc::microseconds& duration, const fbtc::blockchain::market_history_key::time_granularity_enum& granularity /* = fc::json::from_string("\"each_block\"").as<fbtc::blockchain::market_history_key::time_granularity_enum>() */) const
{
  ilog("received RPC call: blockchain_market_price_history(${quote_symbol}, ${base_symbol}, ${start_time}, ${duration}, ${granularity})", ("quote_symbol", quote_symbol)("base_symbol", base_symbol)("start_time", start_time)("duration", duration)("granularity", granularity));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(quote_symbol) );
    args.push_back( fc::variant(base_symbol) );
    args.push_back( fc::variant(start_time) );
    args.push_back( fbtc::api::time_interval_in_seconds_to_variant(duration) );
    args.push_back( fc::variant(granularity) );
    call_id = glog->log_call_started( this, "blockchain_market_price_history", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_market_price_history finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::blockchain::market_history_points result = get_impl()->blockchain_market_price_history(quote_symbol, base_symbol, start_time, duration, granularity);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_market_price_history", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::vector<fbtc::blockchain::account_record> common_api_client::blockchain_list_active_delegates(uint32_t first /* = fc::json::from_string("0").as<uint32_t>() */, uint32_t count /* = fc::json::from_string("20").as<uint32_t>() */) const
{
  ilog("received RPC call: blockchain_list_active_delegates(${first}, ${count})", ("first", first)("count", count));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(first) );
    args.push_back( fc::variant(count) );
    call_id = glog->log_call_started( this, "blockchain_list_active_delegates", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_list_active_delegates finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::vector<fbtc::blockchain::account_record> result = get_impl()->blockchain_list_active_delegates(first, count);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_list_active_delegates", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::vector<fbtc::blockchain::account_record> common_api_client::blockchain_list_delegates(uint32_t first /* = fc::json::from_string("0").as<uint32_t>() */, uint32_t count /* = fc::json::from_string("20").as<uint32_t>() */) const
{
  ilog("received RPC call: blockchain_list_delegates(${first}, ${count})", ("first", first)("count", count));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(first) );
    args.push_back( fc::variant(count) );
    call_id = glog->log_call_started( this, "blockchain_list_delegates", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_list_delegates finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::vector<fbtc::blockchain::account_record> result = get_impl()->blockchain_list_delegates(first, count);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_list_delegates", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::vector<fbtc::blockchain::block_record> common_api_client::blockchain_list_blocks(uint32_t max_block_num /* = fc::json::from_string("-1").as<uint32_t>() */, uint32_t limit /* = fc::json::from_string("20").as<uint32_t>() */)
{
  ilog("received RPC call: blockchain_list_blocks(${max_block_num}, ${limit})", ("max_block_num", max_block_num)("limit", limit));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(max_block_num) );
    args.push_back( fc::variant(limit) );
    call_id = glog->log_call_started( this, "blockchain_list_blocks", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_list_blocks finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::vector<fbtc::blockchain::block_record> result = get_impl()->blockchain_list_blocks(max_block_num, limit);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_list_blocks", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::vector<std::string> common_api_client::blockchain_list_missing_block_delegates(uint32_t block_number)
{
  ilog("received RPC call: blockchain_list_missing_block_delegates(${block_number})", ("block_number", block_number));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(block_number) );
    call_id = glog->log_call_started( this, "blockchain_list_missing_block_delegates", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_list_missing_block_delegates finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::vector<std::string> result = get_impl()->blockchain_list_missing_block_delegates(block_number);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_list_missing_block_delegates", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::string common_api_client::blockchain_export_fork_graph(uint32_t start_block /* = fc::json::from_string("1").as<uint32_t>() */, uint32_t end_block /* = fc::json::from_string("-1").as<uint32_t>() */, const std::string& filename /* = fc::json::from_string("\"\"").as<std::string>() */) const
{
  ilog("received RPC call: blockchain_export_fork_graph(${start_block}, ${end_block}, ${filename})", ("start_block", start_block)("end_block", end_block)("filename", filename));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(start_block) );
    args.push_back( fc::variant(end_block) );
    args.push_back( fc::variant(filename) );
    call_id = glog->log_call_started( this, "blockchain_export_fork_graph", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_export_fork_graph finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::string result = get_impl()->blockchain_export_fork_graph(start_block, end_block, filename);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_export_fork_graph", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::map<uint32_t, std::vector<fbtc::blockchain::fork_record>> common_api_client::blockchain_list_forks() const
{
  ilog("received RPC call: blockchain_list_forks()", );
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    call_id = glog->log_call_started( this, "blockchain_list_forks", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_list_forks finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::map<uint32_t, std::vector<fbtc::blockchain::fork_record>> result = get_impl()->blockchain_list_forks();
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_list_forks", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::vector<fbtc::blockchain::slot_record> common_api_client::blockchain_get_delegate_slot_records(const std::string& delegate_name, uint32_t limit /* = fc::json::from_string("\"10\"").as<uint32_t>() */) const
{
  ilog("received RPC call: blockchain_get_delegate_slot_records(${delegate_name}, ${limit})", ("delegate_name", delegate_name)("limit", limit));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(delegate_name) );
    args.push_back( fc::variant(limit) );
    call_id = glog->log_call_started( this, "blockchain_get_delegate_slot_records", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_get_delegate_slot_records finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::vector<fbtc::blockchain::slot_record> result = get_impl()->blockchain_get_delegate_slot_records(delegate_name, limit);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_get_delegate_slot_records", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::string common_api_client::blockchain_get_block_signee(const std::string& block) const
{
  ilog("received RPC call: blockchain_get_block_signee(${block})", ("block", block));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(block) );
    call_id = glog->log_call_started( this, "blockchain_get_block_signee", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_get_block_signee finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::string result = get_impl()->blockchain_get_block_signee(block);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_get_block_signee", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::vector<fbtc::blockchain::string_status_record> common_api_client::blockchain_list_markets() const
{
  ilog("received RPC call: blockchain_list_markets()", );
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    call_id = glog->log_call_started( this, "blockchain_list_markets", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_list_markets finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::vector<fbtc::blockchain::string_status_record> result = get_impl()->blockchain_list_markets();
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_list_markets", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::vector<fbtc::blockchain::market_transaction> common_api_client::blockchain_list_market_transactions(uint32_t block_number) const
{
  ilog("received RPC call: blockchain_list_market_transactions(${block_number})", ("block_number", block_number));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(block_number) );
    call_id = glog->log_call_started( this, "blockchain_list_market_transactions", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_list_market_transactions finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::vector<fbtc::blockchain::market_transaction> result = get_impl()->blockchain_list_market_transactions(block_number);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_list_market_transactions", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::blockchain::string_status_record common_api_client::blockchain_market_status(const std::string& quote_symbol, const std::string& base_symbol) const
{
  ilog("received RPC call: blockchain_market_status(${quote_symbol}, ${base_symbol})", ("quote_symbol", quote_symbol)("base_symbol", base_symbol));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(quote_symbol) );
    args.push_back( fc::variant(base_symbol) );
    call_id = glog->log_call_started( this, "blockchain_market_status", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_market_status finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::blockchain::string_status_record result = get_impl()->blockchain_market_status(quote_symbol, base_symbol);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_market_status", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::blockchain::asset common_api_client::blockchain_unclaimed_genesis() const
{
  ilog("received RPC call: blockchain_unclaimed_genesis()", );
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    call_id = glog->log_call_started( this, "blockchain_unclaimed_genesis", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_unclaimed_genesis finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::blockchain::asset result = get_impl()->blockchain_unclaimed_genesis();
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_unclaimed_genesis", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

bool common_api_client::blockchain_verify_signature(const std::string& signer, const fc::sha256& hash, const fc::ecc::compact_signature& signature) const
{
  ilog("received RPC call: blockchain_verify_signature(${signer}, ${hash}, ${signature})", ("signer", signer)("hash", hash)("signature", signature));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(signer) );
    args.push_back( fc::variant(hash) );
    args.push_back( fc::variant(signature) );
    call_id = glog->log_call_started( this, "blockchain_verify_signature", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_verify_signature finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    bool result = get_impl()->blockchain_verify_signature(signer, hash, signature);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_verify_signature", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::blockchain_broadcast_transaction(const fbtc::blockchain::signed_transaction& trx)
{
  ilog("received RPC call: blockchain_broadcast_transaction(${trx})", ("trx", trx));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(trx) );
    call_id = glog->log_call_started( this, "blockchain_broadcast_transaction", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call blockchain_broadcast_transaction finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->blockchain_broadcast_transaction(trx);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "blockchain_broadcast_transaction", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fc::variant_object common_api_client::wallet_get_info()
{
  ilog("received RPC call: wallet_get_info()", );
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    call_id = glog->log_call_started( this, "wallet_get_info", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_get_info finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fc::variant_object result = get_impl()->wallet_get_info();
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_get_info", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::wallet_open(const std::string& wallet_name)
{
  ilog("received RPC call: wallet_open(${wallet_name})", ("wallet_name", wallet_name));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(wallet_name) );
    call_id = glog->log_call_started( this, "wallet_open", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_open finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->wallet_open(wallet_name);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_open", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::string common_api_client::wallet_get_account_public_address(const std::string& account_name) const
{
  ilog("received RPC call: wallet_get_account_public_address(${account_name})", ("account_name", account_name));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(account_name) );
    call_id = glog->log_call_started( this, "wallet_get_account_public_address", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_get_account_public_address finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::string result = get_impl()->wallet_get_account_public_address(account_name);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_get_account_public_address", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::vector<fbtc::wallet::account_address_data> common_api_client::wallet_list_my_addresses() const
{
  ilog("received RPC call: wallet_list_my_addresses()", );
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    call_id = glog->log_call_started( this, "wallet_list_my_addresses", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_list_my_addresses finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::vector<fbtc::wallet::account_address_data> result = get_impl()->wallet_list_my_addresses();
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_list_my_addresses", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::wallet_create(const std::string& wallet_name, const std::string& new_passphrase, const std::string& brain_key /* = fc::json::from_string("\"\"").as<std::string>() */, const std::string& new_passphrase_verify /* = fc::json::from_string("\"\"").as<std::string>() */)
{
  ilog("received RPC call: wallet_create(${wallet_name}, *********, *********, *********)", ("wallet_name", wallet_name));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(wallet_name) );
    if( glog->obscure_passwords() )
      args.push_back( fc::variant("*********") );
    else
      args.push_back( fc::variant(new_passphrase) );
    if( glog->obscure_passwords() )
      args.push_back( fc::variant("*********") );
    else
      args.push_back( fc::variant(brain_key) );
    if( glog->obscure_passwords() )
      args.push_back( fc::variant("*********") );
    else
      args.push_back( fc::variant(new_passphrase_verify) );
    call_id = glog->log_call_started( this, "wallet_create", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_create finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->wallet_create(wallet_name, new_passphrase, brain_key, new_passphrase_verify);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_create", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::string common_api_client::wallet_import_private_key(const std::string& wif_key, const std::string& account_name /* = fc::json::from_string("null").as<std::string>() */, bool create_new_account /* = fc::json::from_string("false").as<bool>() */, bool rescan /* = fc::json::from_string("false").as<bool>() */)
{
  ilog("received RPC call: wallet_import_private_key(*********, ${account_name}, ${create_new_account}, ${rescan})", ("account_name", account_name)("create_new_account", create_new_account)("rescan", rescan));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    if( glog->obscure_passwords() )
      args.push_back( fc::variant("*********") );
    else
      args.push_back( fc::variant(wif_key) );
    args.push_back( fc::variant(account_name) );
    args.push_back( fc::variant(create_new_account) );
    args.push_back( fc::variant(rescan) );
    call_id = glog->log_call_started( this, "wallet_import_private_key", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_import_private_key finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::string result = get_impl()->wallet_import_private_key(wif_key, account_name, create_new_account, rescan);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_import_private_key", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

uint32_t common_api_client::wallet_import_bitcoin(const fc::path& wallet_filename, const std::string& passphrase, const std::string& account_name)
{
  ilog("received RPC call: wallet_import_bitcoin(${wallet_filename}, *********, ${account_name})", ("wallet_filename", wallet_filename)("account_name", account_name));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(wallet_filename) );
    if( glog->obscure_passwords() )
      args.push_back( fc::variant("*********") );
    else
      args.push_back( fc::variant(passphrase) );
    args.push_back( fc::variant(account_name) );
    call_id = glog->log_call_started( this, "wallet_import_bitcoin", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_import_bitcoin finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    uint32_t result = get_impl()->wallet_import_bitcoin(wallet_filename, passphrase, account_name);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_import_bitcoin", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

uint32_t common_api_client::wallet_import_electrum(const fc::path& wallet_filename, const std::string& passphrase, const std::string& account_name)
{
  ilog("received RPC call: wallet_import_electrum(${wallet_filename}, *********, ${account_name})", ("wallet_filename", wallet_filename)("account_name", account_name));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(wallet_filename) );
    if( glog->obscure_passwords() )
      args.push_back( fc::variant("*********") );
    else
      args.push_back( fc::variant(passphrase) );
    args.push_back( fc::variant(account_name) );
    call_id = glog->log_call_started( this, "wallet_import_electrum", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_import_electrum finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    uint32_t result = get_impl()->wallet_import_electrum(wallet_filename, passphrase, account_name);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_import_electrum", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::wallet_import_keyhotee(const std::string& firstname, const std::string& middlename, const std::string& lastname, const std::string& brainkey, const std::string& keyhoteeid)
{
  ilog("received RPC call: wallet_import_keyhotee(${firstname}, ${middlename}, ${lastname}, *********, ${keyhoteeid})", ("firstname", firstname)("middlename", middlename)("lastname", lastname)("keyhoteeid", keyhoteeid));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(firstname) );
    args.push_back( fc::variant(middlename) );
    args.push_back( fc::variant(lastname) );
    if( glog->obscure_passwords() )
      args.push_back( fc::variant("*********") );
    else
      args.push_back( fc::variant(brainkey) );
    args.push_back( fc::variant(keyhoteeid) );
    call_id = glog->log_call_started( this, "wallet_import_keyhotee", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_import_keyhotee finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->wallet_import_keyhotee(firstname, middlename, lastname, brainkey, keyhoteeid);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_import_keyhotee", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

uint32_t common_api_client::wallet_import_keys_from_json(const fc::path& json_filename, const std::string& imported_wallet_passphrase, const std::string& account)
{
  ilog("received RPC call: wallet_import_keys_from_json(${json_filename}, *********, ${account})", ("json_filename", json_filename)("account", account));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(json_filename) );
    if( glog->obscure_passwords() )
      args.push_back( fc::variant("*********") );
    else
      args.push_back( fc::variant(imported_wallet_passphrase) );
    args.push_back( fc::variant(account) );
    call_id = glog->log_call_started( this, "wallet_import_keys_from_json", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_import_keys_from_json finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    uint32_t result = get_impl()->wallet_import_keys_from_json(json_filename, imported_wallet_passphrase, account);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_import_keys_from_json", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::wallet_close()
{
  ilog("received RPC call: wallet_close()", );
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    call_id = glog->log_call_started( this, "wallet_close", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_close finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->wallet_close();
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_close", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::wallet_backup_create(const fc::path& json_filename) const
{
  ilog("received RPC call: wallet_backup_create(${json_filename})", ("json_filename", json_filename));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(json_filename) );
    call_id = glog->log_call_started( this, "wallet_backup_create", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_backup_create finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->wallet_backup_create(json_filename);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_backup_create", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::wallet_backup_restore(const fc::path& json_filename, const std::string& wallet_name, const std::string& imported_wallet_passphrase)
{
  ilog("received RPC call: wallet_backup_restore(${json_filename}, ${wallet_name}, *********)", ("json_filename", json_filename)("wallet_name", wallet_name));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(json_filename) );
    args.push_back( fc::variant(wallet_name) );
    if( glog->obscure_passwords() )
      args.push_back( fc::variant("*********") );
    else
      args.push_back( fc::variant(imported_wallet_passphrase) );
    call_id = glog->log_call_started( this, "wallet_backup_restore", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_backup_restore finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->wallet_backup_restore(json_filename, wallet_name, imported_wallet_passphrase);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_backup_restore", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::wallet_export_keys(const fc::path& json_filename) const
{
  ilog("received RPC call: wallet_export_keys(${json_filename})", ("json_filename", json_filename));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(json_filename) );
    call_id = glog->log_call_started( this, "wallet_export_keys", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_export_keys finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->wallet_export_keys(json_filename);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_export_keys", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

bool common_api_client::wallet_set_automatic_backups(bool enabled)
{
  ilog("received RPC call: wallet_set_automatic_backups(${enabled})", ("enabled", enabled));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(enabled) );
    call_id = glog->log_call_started( this, "wallet_set_automatic_backups", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_set_automatic_backups finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    bool result = get_impl()->wallet_set_automatic_backups(enabled);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_set_automatic_backups", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

uint32_t common_api_client::wallet_set_transaction_expiration_time(uint32_t seconds)
{
  ilog("received RPC call: wallet_set_transaction_expiration_time(${seconds})", ("seconds", seconds));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(seconds) );
    call_id = glog->log_call_started( this, "wallet_set_transaction_expiration_time", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_set_transaction_expiration_time finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    uint32_t result = get_impl()->wallet_set_transaction_expiration_time(seconds);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_set_transaction_expiration_time", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::vector<fbtc::wallet::pretty_transaction> common_api_client::wallet_account_transaction_history(const std::string& account_name /* = fc::json::from_string("\"\"").as<std::string>() */, const std::string& asset_symbol /* = fc::json::from_string("\"\"").as<std::string>() */, int32_t limit /* = fc::json::from_string("0").as<int32_t>() */, uint32_t start_block_num /* = fc::json::from_string("0").as<uint32_t>() */, uint32_t end_block_num /* = fc::json::from_string("-1").as<uint32_t>() */) const
{
  ilog("received RPC call: wallet_account_transaction_history(${account_name}, ${asset_symbol}, ${limit}, ${start_block_num}, ${end_block_num})", ("account_name", account_name)("asset_symbol", asset_symbol)("limit", limit)("start_block_num", start_block_num)("end_block_num", end_block_num));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(account_name) );
    args.push_back( fc::variant(asset_symbol) );
    args.push_back( fc::variant(limit) );
    args.push_back( fc::variant(start_block_num) );
    args.push_back( fc::variant(end_block_num) );
    call_id = glog->log_call_started( this, "wallet_account_transaction_history", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_account_transaction_history finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::vector<fbtc::wallet::pretty_transaction> result = get_impl()->wallet_account_transaction_history(account_name, asset_symbol, limit, start_block_num, end_block_num);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_account_transaction_history", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::account_balance_summary_type common_api_client::wallet_account_historic_balance(const fc::time_point& time, const std::string& account_name /* = fc::json::from_string("\"\"").as<std::string>() */) const
{
  ilog("received RPC call: wallet_account_historic_balance(${time}, ${account_name})", ("time", time)("account_name", account_name));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(time) );
    args.push_back( fc::variant(account_name) );
    call_id = glog->log_call_started( this, "wallet_account_historic_balance", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_account_historic_balance finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::account_balance_summary_type result = get_impl()->wallet_account_historic_balance(time, account_name);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_account_historic_balance", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::set<fbtc::wallet::pretty_transaction_experimental> common_api_client::wallet_transaction_history_experimental(const std::string& account_name /* = fc::json::from_string("\"\"").as<std::string>() */) const
{
  ilog("received RPC call: wallet_transaction_history_experimental(${account_name})", ("account_name", account_name));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(account_name) );
    call_id = glog->log_call_started( this, "wallet_transaction_history_experimental", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_transaction_history_experimental finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::set<fbtc::wallet::pretty_transaction_experimental> result = get_impl()->wallet_transaction_history_experimental(account_name);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_transaction_history_experimental", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::wallet_remove_transaction(const std::string& transaction_id)
{
  ilog("received RPC call: wallet_remove_transaction(${transaction_id})", ("transaction_id", transaction_id));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(transaction_id) );
    call_id = glog->log_call_started( this, "wallet_remove_transaction", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_remove_transaction finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->wallet_remove_transaction(transaction_id);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_remove_transaction", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::map<fbtc::blockchain::transaction_id_type, fc::exception> common_api_client::wallet_get_pending_transaction_errors(const std::string& filename /* = fc::json::from_string("\"\"").as<std::string>() */) const
{
  ilog("received RPC call: wallet_get_pending_transaction_errors(${filename})", ("filename", filename));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(filename) );
    call_id = glog->log_call_started( this, "wallet_get_pending_transaction_errors", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_get_pending_transaction_errors finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::map<fbtc::blockchain::transaction_id_type, fc::exception> result = get_impl()->wallet_get_pending_transaction_errors(filename);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_get_pending_transaction_errors", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::wallet_lock()
{
  ilog("received RPC call: wallet_lock()", );
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    call_id = glog->log_call_started( this, "wallet_lock", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_lock finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->wallet_lock();
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_lock", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::wallet_unlock(uint32_t timeout, const std::string& passphrase)
{
  ilog("received RPC call: wallet_unlock(${timeout}, *********)", ("timeout", timeout));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(timeout) );
    if( glog->obscure_passwords() )
      args.push_back( fc::variant("*********") );
    else
      args.push_back( fc::variant(passphrase) );
    call_id = glog->log_call_started( this, "wallet_unlock", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_unlock finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->wallet_unlock(timeout, passphrase);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_unlock", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::wallet_change_passphrase(const std::string& new_passphrase, const std::string& new_passphrase_verify /* = fc::json::from_string("\"\"").as<std::string>() */)
{
  ilog("received RPC call: wallet_change_passphrase(*********, *********)", );
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    if( glog->obscure_passwords() )
      args.push_back( fc::variant("*********") );
    else
      args.push_back( fc::variant(new_passphrase) );
    if( glog->obscure_passwords() )
      args.push_back( fc::variant("*********") );
    else
      args.push_back( fc::variant(new_passphrase_verify) );
    call_id = glog->log_call_started( this, "wallet_change_passphrase", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_change_passphrase finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->wallet_change_passphrase(new_passphrase, new_passphrase_verify);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_change_passphrase", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::vector<std::string> common_api_client::wallet_list() const
{
  ilog("received RPC call: wallet_list()", );
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    call_id = glog->log_call_started( this, "wallet_list", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_list finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::vector<std::string> result = get_impl()->wallet_list();
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_list", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::blockchain::public_key_type common_api_client::wallet_account_create(const std::string& account_name)
{
  ilog("received RPC call: wallet_account_create(${account_name})", ("account_name", account_name));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(account_name) );
    call_id = glog->log_call_started( this, "wallet_account_create", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_account_create finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::blockchain::public_key_type result = get_impl()->wallet_account_create(account_name);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_account_create", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::vector<fbtc::wallet::wallet_contact_record> common_api_client::wallet_list_contacts() const
{
  ilog("received RPC call: wallet_list_contacts()", );
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    call_id = glog->log_call_started( this, "wallet_list_contacts", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_list_contacts finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::vector<fbtc::wallet::wallet_contact_record> result = get_impl()->wallet_list_contacts();
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_list_contacts", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::owallet_contact_record common_api_client::wallet_get_contact(const std::string& contact) const
{
  ilog("received RPC call: wallet_get_contact(${contact})", ("contact", contact));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(contact) );
    call_id = glog->log_call_started( this, "wallet_get_contact", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_get_contact finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::owallet_contact_record result = get_impl()->wallet_get_contact(contact);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_get_contact", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_contact_record common_api_client::wallet_add_contact(const std::string& contact, const std::string& label /* = fc::json::from_string("\"\"").as<std::string>() */)
{
  ilog("received RPC call: wallet_add_contact(${contact}, ${label})", ("contact", contact)("label", label));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(contact) );
    args.push_back( fc::variant(label) );
    call_id = glog->log_call_started( this, "wallet_add_contact", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_add_contact finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_contact_record result = get_impl()->wallet_add_contact(contact, label);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_add_contact", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::owallet_contact_record common_api_client::wallet_remove_contact(const std::string& contact)
{
  ilog("received RPC call: wallet_remove_contact(${contact})", ("contact", contact));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(contact) );
    call_id = glog->log_call_started( this, "wallet_remove_contact", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_remove_contact finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::owallet_contact_record result = get_impl()->wallet_remove_contact(contact);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_remove_contact", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::vector<fbtc::wallet::wallet_approval_record> common_api_client::wallet_list_approvals() const
{
  ilog("received RPC call: wallet_list_approvals()", );
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    call_id = glog->log_call_started( this, "wallet_list_approvals", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_list_approvals finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::vector<fbtc::wallet::wallet_approval_record> result = get_impl()->wallet_list_approvals();
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_list_approvals", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::owallet_approval_record common_api_client::wallet_get_approval(const std::string& approval) const
{
  ilog("received RPC call: wallet_get_approval(${approval})", ("approval", approval));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(approval) );
    call_id = glog->log_call_started( this, "wallet_get_approval", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_get_approval finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::owallet_approval_record result = get_impl()->wallet_get_approval(approval);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_get_approval", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_approval_record common_api_client::wallet_approve(const std::string& name, int8_t approval /* = fc::json::from_string("1").as<int8_t>() */)
{
  ilog("received RPC call: wallet_approve(${name}, ${approval})", ("name", name)("approval", approval));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(name) );
    args.push_back( fc::variant(approval) );
    call_id = glog->log_call_started( this, "wallet_approve", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_approve finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_approval_record result = get_impl()->wallet_approve(name, approval);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_approve", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_burn(const std::string& amount_to_burn, const std::string& asset_symbol, const std::string& from_account_name, const std::string& for_or_against, const std::string& to_account_name, const std::string& public_message /* = fc::json::from_string("\"\"").as<std::string>() */, bool anonymous /* = fc::json::from_string("\"false\"").as<bool>() */)
{
  ilog("received RPC call: wallet_burn(${amount_to_burn}, ${asset_symbol}, ${from_account_name}, ${for_or_against}, ${to_account_name}, ${public_message}, ${anonymous})", ("amount_to_burn", amount_to_burn)("asset_symbol", asset_symbol)("from_account_name", from_account_name)("for_or_against", for_or_against)("to_account_name", to_account_name)("public_message", public_message)("anonymous", anonymous));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(amount_to_burn) );
    args.push_back( fc::variant(asset_symbol) );
    args.push_back( fc::variant(from_account_name) );
    args.push_back( fc::variant(for_or_against) );
    args.push_back( fc::variant(to_account_name) );
    args.push_back( fc::variant(public_message) );
    args.push_back( fc::variant(anonymous) );
    call_id = glog->log_call_started( this, "wallet_burn", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_burn finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_burn(amount_to_burn, asset_symbol, from_account_name, for_or_against, to_account_name, public_message, anonymous);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_burn", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::string common_api_client::wallet_address_create(const std::string& account_name, const std::string& label /* = fc::json::from_string("\"\"").as<std::string>() */, int32_t legacy_network_byte /* = fc::json::from_string("-1").as<int32_t>() */)
{
  ilog("received RPC call: wallet_address_create(${account_name}, ${label}, ${legacy_network_byte})", ("account_name", account_name)("label", label)("legacy_network_byte", legacy_network_byte));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(account_name) );
    args.push_back( fc::variant(label) );
    args.push_back( fc::variant(legacy_network_byte) );
    call_id = glog->log_call_started( this, "wallet_address_create", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_address_create finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::string result = get_impl()->wallet_address_create(account_name, label, legacy_network_byte);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_address_create", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_transfer_to_address(const std::string& amount_to_transfer, const std::string& asset_symbol, const std::string& from_account_name, const std::string& to_address, const std::string& memo_message /* = fc::json::from_string("\"\"").as<std::string>() */, const fbtc::wallet::vote_strategy& strategy /* = fc::json::from_string("\"vote_recommended\"").as<fbtc::wallet::vote_strategy>() */)
{
  ilog("received RPC call: wallet_transfer_to_address(${amount_to_transfer}, ${asset_symbol}, ${from_account_name}, ${to_address}, ${memo_message}, ${strategy})", ("amount_to_transfer", amount_to_transfer)("asset_symbol", asset_symbol)("from_account_name", from_account_name)("to_address", to_address)("memo_message", memo_message)("strategy", strategy));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(amount_to_transfer) );
    args.push_back( fc::variant(asset_symbol) );
    args.push_back( fc::variant(from_account_name) );
    args.push_back( fc::variant(to_address) );
    args.push_back( fc::variant(memo_message) );
    args.push_back( fc::variant(strategy) );
    call_id = glog->log_call_started( this, "wallet_transfer_to_address", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_transfer_to_address finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_transfer_to_address(amount_to_transfer, asset_symbol, from_account_name, to_address, memo_message, strategy);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_transfer_to_address", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_transfer_to_genesis_multisig_address(const std::string& amount_to_transfer, const std::string& asset_symbol, const std::string& from_account_name, const std::string& to_address, const std::string& memo_message /* = fc::json::from_string("\"\"").as<std::string>() */, const fbtc::wallet::vote_strategy& strategy /* = fc::json::from_string("\"vote_recommended\"").as<fbtc::wallet::vote_strategy>() */)
{
  ilog("received RPC call: wallet_transfer_to_genesis_multisig_address(${amount_to_transfer}, ${asset_symbol}, ${from_account_name}, ${to_address}, ${memo_message}, ${strategy})", ("amount_to_transfer", amount_to_transfer)("asset_symbol", asset_symbol)("from_account_name", from_account_name)("to_address", to_address)("memo_message", memo_message)("strategy", strategy));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(amount_to_transfer) );
    args.push_back( fc::variant(asset_symbol) );
    args.push_back( fc::variant(from_account_name) );
    args.push_back( fc::variant(to_address) );
    args.push_back( fc::variant(memo_message) );
    args.push_back( fc::variant(strategy) );
    call_id = glog->log_call_started( this, "wallet_transfer_to_genesis_multisig_address", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_transfer_to_genesis_multisig_address finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_transfer_to_genesis_multisig_address(amount_to_transfer, asset_symbol, from_account_name, to_address, memo_message, strategy);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_transfer_to_genesis_multisig_address", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_transfer_to_address_from_file(const std::string& from_account_name, const std::string& file_path, const std::string& memo_message /* = fc::json::from_string("\"\"").as<std::string>() */, const fbtc::wallet::vote_strategy& strategy /* = fc::json::from_string("\"vote_recommended\"").as<fbtc::wallet::vote_strategy>() */)
{
  ilog("received RPC call: wallet_transfer_to_address_from_file(${from_account_name}, ${file_path}, ${memo_message}, ${strategy})", ("from_account_name", from_account_name)("file_path", file_path)("memo_message", memo_message)("strategy", strategy));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(from_account_name) );
    args.push_back( fc::variant(file_path) );
    args.push_back( fc::variant(memo_message) );
    args.push_back( fc::variant(strategy) );
    call_id = glog->log_call_started( this, "wallet_transfer_to_address_from_file", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_transfer_to_address_from_file finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_transfer_to_address_from_file(from_account_name, file_path, memo_message, strategy);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_transfer_to_address_from_file", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_transfer_to_genesis_multisig_address_from_file(const std::string& from_account_name, const std::string& file_path, const std::string& memo_message /* = fc::json::from_string("\"\"").as<std::string>() */, const fbtc::wallet::vote_strategy& strategy /* = fc::json::from_string("\"vote_recommended\"").as<fbtc::wallet::vote_strategy>() */)
{
  ilog("received RPC call: wallet_transfer_to_genesis_multisig_address_from_file(${from_account_name}, ${file_path}, ${memo_message}, ${strategy})", ("from_account_name", from_account_name)("file_path", file_path)("memo_message", memo_message)("strategy", strategy));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(from_account_name) );
    args.push_back( fc::variant(file_path) );
    args.push_back( fc::variant(memo_message) );
    args.push_back( fc::variant(strategy) );
    call_id = glog->log_call_started( this, "wallet_transfer_to_genesis_multisig_address_from_file", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_transfer_to_genesis_multisig_address_from_file finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_transfer_to_genesis_multisig_address_from_file(from_account_name, file_path, memo_message, strategy);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_transfer_to_genesis_multisig_address_from_file", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

bool common_api_client::wallet_check_passphrase(const std::string& passphrase)
{
  ilog("received RPC call: wallet_check_passphrase(*********)", );
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    if( glog->obscure_passwords() )
      args.push_back( fc::variant("*********") );
    else
      args.push_back( fc::variant(passphrase) );
    call_id = glog->log_call_started( this, "wallet_check_passphrase", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_check_passphrase finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    bool result = get_impl()->wallet_check_passphrase(passphrase);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_check_passphrase", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_transfer(const std::string& amount_to_transfer, const std::string& asset_symbol, const std::string& from_account_name, const std::string& recipient, const std::string& memo_message /* = fc::json::from_string("\"\"").as<std::string>() */, const fbtc::wallet::vote_strategy& strategy /* = fc::json::from_string("\"vote_recommended\"").as<fbtc::wallet::vote_strategy>() */)
{
  ilog("received RPC call: wallet_transfer(${amount_to_transfer}, ${asset_symbol}, ${from_account_name}, ${recipient}, ${memo_message}, ${strategy})", ("amount_to_transfer", amount_to_transfer)("asset_symbol", asset_symbol)("from_account_name", from_account_name)("recipient", recipient)("memo_message", memo_message)("strategy", strategy));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(amount_to_transfer) );
    args.push_back( fc::variant(asset_symbol) );
    args.push_back( fc::variant(from_account_name) );
    args.push_back( fc::variant(recipient) );
    args.push_back( fc::variant(memo_message) );
    args.push_back( fc::variant(strategy) );
    call_id = glog->log_call_started( this, "wallet_transfer", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_transfer finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_transfer(amount_to_transfer, asset_symbol, from_account_name, recipient, memo_message, strategy);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_transfer", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::blockchain::address common_api_client::wallet_multisig_get_balance_id(const std::string& symbol, uint32_t m, const std::vector<fbtc::blockchain::address>& addresses) const
{
  ilog("received RPC call: wallet_multisig_get_balance_id(${symbol}, ${m}, ${addresses})", ("symbol", symbol)("m", m)("addresses", addresses));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(symbol) );
    args.push_back( fc::variant(m) );
    args.push_back( fc::variant(addresses) );
    call_id = glog->log_call_started( this, "wallet_multisig_get_balance_id", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_multisig_get_balance_id finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::blockchain::address result = get_impl()->wallet_multisig_get_balance_id(symbol, m, addresses);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_multisig_get_balance_id", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_multisig_deposit(const std::string& amount, const std::string& symbol, const std::string& from_name, uint32_t m, const std::vector<fbtc::blockchain::address>& addresses, const fbtc::wallet::vote_strategy& strategy /* = fc::json::from_string("\"vote_none\"").as<fbtc::wallet::vote_strategy>() */)
{
  ilog("received RPC call: wallet_multisig_deposit(${amount}, ${symbol}, ${from_name}, ${m}, ${addresses}, ${strategy})", ("amount", amount)("symbol", symbol)("from_name", from_name)("m", m)("addresses", addresses)("strategy", strategy));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(amount) );
    args.push_back( fc::variant(symbol) );
    args.push_back( fc::variant(from_name) );
    args.push_back( fc::variant(m) );
    args.push_back( fc::variant(addresses) );
    args.push_back( fc::variant(strategy) );
    call_id = glog->log_call_started( this, "wallet_multisig_deposit", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_multisig_deposit finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_multisig_deposit(amount, symbol, from_name, m, addresses, strategy);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_multisig_deposit", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::transaction_builder common_api_client::wallet_withdraw_from_address(const std::string& amount, const std::string& symbol, const fbtc::blockchain::address& from_address, const std::string& to, const fbtc::wallet::vote_strategy& strategy /* = fc::json::from_string("\"vote_none\"").as<fbtc::wallet::vote_strategy>() */, bool sign_and_broadcast /* = fc::json::from_string("true").as<bool>() */, const std::string& builder_path /* = fc::json::from_string("\"\"").as<std::string>() */)
{
  ilog("received RPC call: wallet_withdraw_from_address(${amount}, ${symbol}, ${from_address}, ${to}, ${strategy}, ${sign_and_broadcast}, ${builder_path})", ("amount", amount)("symbol", symbol)("from_address", from_address)("to", to)("strategy", strategy)("sign_and_broadcast", sign_and_broadcast)("builder_path", builder_path));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(amount) );
    args.push_back( fc::variant(symbol) );
    args.push_back( fc::variant(from_address) );
    args.push_back( fc::variant(to) );
    args.push_back( fc::variant(strategy) );
    args.push_back( fc::variant(sign_and_broadcast) );
    args.push_back( fc::variant(builder_path) );
    call_id = glog->log_call_started( this, "wallet_withdraw_from_address", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_withdraw_from_address finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::transaction_builder result = get_impl()->wallet_withdraw_from_address(amount, symbol, from_address, to, strategy, sign_and_broadcast, builder_path);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_withdraw_from_address", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::transaction_builder common_api_client::wallet_receive_genesis_multisig_blanace(const fbtc::blockchain::address& from_address, const std::string& from_address_redeemscript, const std::string& to, const fbtc::wallet::vote_strategy& strategy /* = fc::json::from_string("\"vote_none\"").as<fbtc::wallet::vote_strategy>() */, bool sign_and_broadcast /* = fc::json::from_string("true").as<bool>() */, const std::string& builder_path /* = fc::json::from_string("\"\"").as<std::string>() */)
{
  ilog("received RPC call: wallet_receive_genesis_multisig_blanace(${from_address}, ${from_address_redeemscript}, ${to}, ${strategy}, ${sign_and_broadcast}, ${builder_path})", ("from_address", from_address)("from_address_redeemscript", from_address_redeemscript)("to", to)("strategy", strategy)("sign_and_broadcast", sign_and_broadcast)("builder_path", builder_path));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(from_address) );
    args.push_back( fc::variant(from_address_redeemscript) );
    args.push_back( fc::variant(to) );
    args.push_back( fc::variant(strategy) );
    args.push_back( fc::variant(sign_and_broadcast) );
    args.push_back( fc::variant(builder_path) );
    call_id = glog->log_call_started( this, "wallet_receive_genesis_multisig_blanace", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_receive_genesis_multisig_blanace finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::transaction_builder result = get_impl()->wallet_receive_genesis_multisig_blanace(from_address, from_address_redeemscript, to, strategy, sign_and_broadcast, builder_path);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_receive_genesis_multisig_blanace", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::transaction_builder common_api_client::wallet_withdraw_from_legacy_address(const std::string& amount, const std::string& symbol, const fbtc::blockchain::pts_address& from_address, const std::string& to, const fbtc::wallet::vote_strategy& strategy /* = fc::json::from_string("\"vote_none\"").as<fbtc::wallet::vote_strategy>() */, bool sign_and_broadcast /* = fc::json::from_string("true").as<bool>() */, const std::string& builder_path /* = fc::json::from_string("\"\"").as<std::string>() */) const
{
  ilog("received RPC call: wallet_withdraw_from_legacy_address(${amount}, ${symbol}, ${from_address}, ${to}, ${strategy}, ${sign_and_broadcast}, ${builder_path})", ("amount", amount)("symbol", symbol)("from_address", from_address)("to", to)("strategy", strategy)("sign_and_broadcast", sign_and_broadcast)("builder_path", builder_path));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(amount) );
    args.push_back( fc::variant(symbol) );
    args.push_back( fc::variant(from_address) );
    args.push_back( fc::variant(to) );
    args.push_back( fc::variant(strategy) );
    args.push_back( fc::variant(sign_and_broadcast) );
    args.push_back( fc::variant(builder_path) );
    call_id = glog->log_call_started( this, "wallet_withdraw_from_legacy_address", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_withdraw_from_legacy_address finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::transaction_builder result = get_impl()->wallet_withdraw_from_legacy_address(amount, symbol, from_address, to, strategy, sign_and_broadcast, builder_path);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_withdraw_from_legacy_address", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::transaction_builder common_api_client::wallet_multisig_withdraw_start(const std::string& amount, const std::string& symbol, const fbtc::blockchain::address& from, const fbtc::blockchain::address& to_address, const fbtc::wallet::vote_strategy& strategy /* = fc::json::from_string("\"vote_none\"").as<fbtc::wallet::vote_strategy>() */, const std::string& builder_path /* = fc::json::from_string("\"\"").as<std::string>() */) const
{
  ilog("received RPC call: wallet_multisig_withdraw_start(${amount}, ${symbol}, ${from}, ${to_address}, ${strategy}, ${builder_path})", ("amount", amount)("symbol", symbol)("from", from)("to_address", to_address)("strategy", strategy)("builder_path", builder_path));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(amount) );
    args.push_back( fc::variant(symbol) );
    args.push_back( fc::variant(from) );
    args.push_back( fc::variant(to_address) );
    args.push_back( fc::variant(strategy) );
    args.push_back( fc::variant(builder_path) );
    call_id = glog->log_call_started( this, "wallet_multisig_withdraw_start", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_multisig_withdraw_start finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::transaction_builder result = get_impl()->wallet_multisig_withdraw_start(amount, symbol, from, to_address, strategy, builder_path);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_multisig_withdraw_start", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::transaction_builder common_api_client::wallet_builder_add_signature(const fbtc::wallet::transaction_builder& builder, bool broadcast /* = fc::json::from_string("false").as<bool>() */)
{
  ilog("received RPC call: wallet_builder_add_signature(${builder}, ${broadcast})", ("builder", builder)("broadcast", broadcast));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(builder) );
    args.push_back( fc::variant(broadcast) );
    call_id = glog->log_call_started( this, "wallet_builder_add_signature", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_builder_add_signature finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::transaction_builder result = get_impl()->wallet_builder_add_signature(builder, broadcast);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_builder_add_signature", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::transaction_builder common_api_client::wallet_builder_file_add_signature(const std::string& builder_path /* = fc::json::from_string("\"\"").as<std::string>() */, bool broadcast /* = fc::json::from_string("false").as<bool>() */)
{
  ilog("received RPC call: wallet_builder_file_add_signature(${builder_path}, ${broadcast})", ("builder_path", builder_path)("broadcast", broadcast));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(builder_path) );
    args.push_back( fc::variant(broadcast) );
    call_id = glog->log_call_started( this, "wallet_builder_file_add_signature", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_builder_file_add_signature finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::transaction_builder result = get_impl()->wallet_builder_file_add_signature(builder_path, broadcast);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_builder_file_add_signature", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_release_escrow(const std::string& pay_fee_with_account_name, const fbtc::blockchain::address& escrow_balance_id, const std::string& released_by_account, const std::string& amount_to_sender /* = fc::json::from_string("0").as<std::string>() */, const std::string& amount_to_receiver /* = fc::json::from_string("0").as<std::string>() */)
{
  ilog("received RPC call: wallet_release_escrow(${pay_fee_with_account_name}, ${escrow_balance_id}, ${released_by_account}, ${amount_to_sender}, ${amount_to_receiver})", ("pay_fee_with_account_name", pay_fee_with_account_name)("escrow_balance_id", escrow_balance_id)("released_by_account", released_by_account)("amount_to_sender", amount_to_sender)("amount_to_receiver", amount_to_receiver));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(pay_fee_with_account_name) );
    args.push_back( fc::variant(escrow_balance_id) );
    args.push_back( fc::variant(released_by_account) );
    args.push_back( fc::variant(amount_to_sender) );
    args.push_back( fc::variant(amount_to_receiver) );
    call_id = glog->log_call_started( this, "wallet_release_escrow", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_release_escrow finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_release_escrow(pay_fee_with_account_name, escrow_balance_id, released_by_account, amount_to_sender, amount_to_receiver);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_release_escrow", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_transfer_from_with_escrow(const std::string& amount_to_transfer, const std::string& asset_symbol, const std::string& paying_account_name, const std::string& from_account_name, const std::string& to_account_name, const std::string& escrow_account_name, const fbtc::blockchain::digest_type& agreement /* = fc::json::from_string("\"\"").as<fbtc::blockchain::digest_type>() */, const std::string& memo_message /* = fc::json::from_string("\"\"").as<std::string>() */, const fbtc::wallet::vote_strategy& strategy /* = fc::json::from_string("\"vote_recommended\"").as<fbtc::wallet::vote_strategy>() */)
{
  ilog("received RPC call: wallet_transfer_from_with_escrow(${amount_to_transfer}, ${asset_symbol}, ${paying_account_name}, ${from_account_name}, ${to_account_name}, ${escrow_account_name}, ${agreement}, ${memo_message}, ${strategy})", ("amount_to_transfer", amount_to_transfer)("asset_symbol", asset_symbol)("paying_account_name", paying_account_name)("from_account_name", from_account_name)("to_account_name", to_account_name)("escrow_account_name", escrow_account_name)("agreement", agreement)("memo_message", memo_message)("strategy", strategy));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(amount_to_transfer) );
    args.push_back( fc::variant(asset_symbol) );
    args.push_back( fc::variant(paying_account_name) );
    args.push_back( fc::variant(from_account_name) );
    args.push_back( fc::variant(to_account_name) );
    args.push_back( fc::variant(escrow_account_name) );
    args.push_back( fc::variant(agreement) );
    args.push_back( fc::variant(memo_message) );
    args.push_back( fc::variant(strategy) );
    call_id = glog->log_call_started( this, "wallet_transfer_from_with_escrow", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_transfer_from_with_escrow finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_transfer_from_with_escrow(amount_to_transfer, asset_symbol, paying_account_name, from_account_name, to_account_name, escrow_account_name, agreement, memo_message, strategy);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_transfer_from_with_escrow", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::wallet_rescan_blockchain(uint32_t start_block_num /* = fc::json::from_string("0").as<uint32_t>() */, uint32_t limit /* = fc::json::from_string("-1").as<uint32_t>() */, bool scan_in_background /* = fc::json::from_string("true").as<bool>() */)
{
  ilog("received RPC call: wallet_rescan_blockchain(${start_block_num}, ${limit}, ${scan_in_background})", ("start_block_num", start_block_num)("limit", limit)("scan_in_background", scan_in_background));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(start_block_num) );
    args.push_back( fc::variant(limit) );
    args.push_back( fc::variant(scan_in_background) );
    call_id = glog->log_call_started( this, "wallet_rescan_blockchain", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_rescan_blockchain finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->wallet_rescan_blockchain(start_block_num, limit, scan_in_background);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_rescan_blockchain", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::wallet_cancel_scan()
{
  ilog("received RPC call: wallet_cancel_scan()", );
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    call_id = glog->log_call_started( this, "wallet_cancel_scan", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_cancel_scan finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->wallet_cancel_scan();
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_cancel_scan", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_get_transaction(const std::string& transaction_id)
{
  ilog("received RPC call: wallet_get_transaction(${transaction_id})", ("transaction_id", transaction_id));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(transaction_id) );
    call_id = glog->log_call_started( this, "wallet_get_transaction", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_get_transaction finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_get_transaction(transaction_id);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_get_transaction", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_scan_transaction(const std::string& transaction_id, bool overwrite_existing /* = fc::json::from_string("false").as<bool>() */)
{
  ilog("received RPC call: wallet_scan_transaction(${transaction_id}, ${overwrite_existing})", ("transaction_id", transaction_id)("overwrite_existing", overwrite_existing));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(transaction_id) );
    args.push_back( fc::variant(overwrite_existing) );
    call_id = glog->log_call_started( this, "wallet_scan_transaction", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_scan_transaction finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_scan_transaction(transaction_id, overwrite_existing);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_scan_transaction", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::wallet_scan_transaction_experimental(const std::string& transaction_id, bool overwrite_existing /* = fc::json::from_string("false").as<bool>() */)
{
  ilog("received RPC call: wallet_scan_transaction_experimental(${transaction_id}, ${overwrite_existing})", ("transaction_id", transaction_id)("overwrite_existing", overwrite_existing));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(transaction_id) );
    args.push_back( fc::variant(overwrite_existing) );
    call_id = glog->log_call_started( this, "wallet_scan_transaction_experimental", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_scan_transaction_experimental finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->wallet_scan_transaction_experimental(transaction_id, overwrite_existing);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_scan_transaction_experimental", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::wallet_add_transaction_note_experimental(const std::string& transaction_id, const std::string& note)
{
  ilog("received RPC call: wallet_add_transaction_note_experimental(${transaction_id}, ${note})", ("transaction_id", transaction_id)("note", note));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(transaction_id) );
    args.push_back( fc::variant(note) );
    call_id = glog->log_call_started( this, "wallet_add_transaction_note_experimental", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_add_transaction_note_experimental finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->wallet_add_transaction_note_experimental(transaction_id, note);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_add_transaction_note_experimental", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::wallet_rebroadcast_transaction(const std::string& transaction_id)
{
  ilog("received RPC call: wallet_rebroadcast_transaction(${transaction_id})", ("transaction_id", transaction_id));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(transaction_id) );
    call_id = glog->log_call_started( this, "wallet_rebroadcast_transaction", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_rebroadcast_transaction finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->wallet_rebroadcast_transaction(transaction_id);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_rebroadcast_transaction", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_account_register(const std::string& account_name, const std::string& pay_from_account, const fc::variant& public_data /* = fc::json::from_string("null").as<fc::variant>() */, uint8_t delegate_pay_rate /* = fc::json::from_string("-1").as<uint8_t>() */, const std::string& account_type /* = fc::json::from_string("\"titan_account\"").as<std::string>() */)
{
  ilog("received RPC call: wallet_account_register(${account_name}, ${pay_from_account}, ${public_data}, ${delegate_pay_rate}, ${account_type})", ("account_name", account_name)("pay_from_account", pay_from_account)("public_data", public_data)("delegate_pay_rate", delegate_pay_rate)("account_type", account_type));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(account_name) );
    args.push_back( fc::variant(pay_from_account) );
    args.push_back( fc::variant(public_data) );
    args.push_back( fc::variant(delegate_pay_rate) );
    args.push_back( fc::variant(account_type) );
    call_id = glog->log_call_started( this, "wallet_account_register", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_account_register finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_account_register(account_name, pay_from_account, public_data, delegate_pay_rate, account_type);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_account_register", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::wallet_set_custom_data(const fbtc::wallet::wallet_record_type_enum& type, const std::string& item, const fc::variant_object& custom_data)
{
  ilog("received RPC call: wallet_set_custom_data(${type}, ${item}, ${custom_data})", ("type", type)("item", item)("custom_data", custom_data));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(type) );
    args.push_back( fc::variant(item) );
    args.push_back( fc::variant(custom_data) );
    call_id = glog->log_call_started( this, "wallet_set_custom_data", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_set_custom_data finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->wallet_set_custom_data(type, item, custom_data);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_set_custom_data", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_account_update_registration(const std::string& account_name, const std::string& pay_from_account, const fc::variant& public_data /* = fc::json::from_string("null").as<fc::variant>() */, uint8_t delegate_pay_rate /* = fc::json::from_string("-1").as<uint8_t>() */)
{
  ilog("received RPC call: wallet_account_update_registration(${account_name}, ${pay_from_account}, ${public_data}, ${delegate_pay_rate})", ("account_name", account_name)("pay_from_account", pay_from_account)("public_data", public_data)("delegate_pay_rate", delegate_pay_rate));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(account_name) );
    args.push_back( fc::variant(pay_from_account) );
    args.push_back( fc::variant(public_data) );
    args.push_back( fc::variant(delegate_pay_rate) );
    call_id = glog->log_call_started( this, "wallet_account_update_registration", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_account_update_registration finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_account_update_registration(account_name, pay_from_account, public_data, delegate_pay_rate);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_account_update_registration", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_account_update_active_key(const std::string& account_to_update, const std::string& pay_from_account, const std::string& new_active_key /* = fc::json::from_string("\"\"").as<std::string>() */)
{
  ilog("received RPC call: wallet_account_update_active_key(${account_to_update}, ${pay_from_account}, ${new_active_key})", ("account_to_update", account_to_update)("pay_from_account", pay_from_account)("new_active_key", new_active_key));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(account_to_update) );
    args.push_back( fc::variant(pay_from_account) );
    args.push_back( fc::variant(new_active_key) );
    call_id = glog->log_call_started( this, "wallet_account_update_active_key", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_account_update_active_key finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_account_update_active_key(account_to_update, pay_from_account, new_active_key);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_account_update_active_key", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::vector<fbtc::wallet::wallet_account_record> common_api_client::wallet_list_accounts() const
{
  ilog("received RPC call: wallet_list_accounts()", );
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    call_id = glog->log_call_started( this, "wallet_list_accounts", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_list_accounts finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::vector<fbtc::wallet::wallet_account_record> result = get_impl()->wallet_list_accounts();
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_list_accounts", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::owallet_account_record common_api_client::wallet_get_account(const std::string& account) const
{
  ilog("received RPC call: wallet_get_account(${account})", ("account", account));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(account) );
    call_id = glog->log_call_started( this, "wallet_get_account", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_get_account finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::owallet_account_record result = get_impl()->wallet_get_account(account);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_get_account", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::wallet_account_rename(const std::string& current_account_name, const std::string& new_account_name)
{
  ilog("received RPC call: wallet_account_rename(${current_account_name}, ${new_account_name})", ("current_account_name", current_account_name)("new_account_name", new_account_name));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(current_account_name) );
    args.push_back( fc::variant(new_account_name) );
    call_id = glog->log_call_started( this, "wallet_account_rename", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_account_rename finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->wallet_account_rename(current_account_name, new_account_name);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_account_rename", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_mia_create(const std::string& payer_account, const std::string& symbol, const std::string& name, const std::string& description, const std::string& max_divisibility)
{
  ilog("received RPC call: wallet_mia_create(${payer_account}, ${symbol}, ${name}, ${description}, ${max_divisibility})", ("payer_account", payer_account)("symbol", symbol)("name", name)("description", description)("max_divisibility", max_divisibility));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(payer_account) );
    args.push_back( fc::variant(symbol) );
    args.push_back( fc::variant(name) );
    args.push_back( fc::variant(description) );
    args.push_back( fc::variant(max_divisibility) );
    call_id = glog->log_call_started( this, "wallet_mia_create", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_mia_create finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_mia_create(payer_account, symbol, name, description, max_divisibility);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_mia_create", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_uia_create(const std::string& issuer_account, const std::string& symbol, const std::string& name, const std::string& description, const std::string& max_supply_with_trailing_decimals)
{
  ilog("received RPC call: wallet_uia_create(${issuer_account}, ${symbol}, ${name}, ${description}, ${max_supply_with_trailing_decimals})", ("issuer_account", issuer_account)("symbol", symbol)("name", name)("description", description)("max_supply_with_trailing_decimals", max_supply_with_trailing_decimals));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(issuer_account) );
    args.push_back( fc::variant(symbol) );
    args.push_back( fc::variant(name) );
    args.push_back( fc::variant(description) );
    args.push_back( fc::variant(max_supply_with_trailing_decimals) );
    call_id = glog->log_call_started( this, "wallet_uia_create", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_uia_create finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_uia_create(issuer_account, symbol, name, description, max_supply_with_trailing_decimals);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_uia_create", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_uia_issue(const std::string& asset_amount, const std::string& asset_symbol, const std::string& recipient, const std::string& memo_message /* = fc::json::from_string("\"\"").as<std::string>() */)
{
  ilog("received RPC call: wallet_uia_issue(${asset_amount}, ${asset_symbol}, ${recipient}, ${memo_message})", ("asset_amount", asset_amount)("asset_symbol", asset_symbol)("recipient", recipient)("memo_message", memo_message));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(asset_amount) );
    args.push_back( fc::variant(asset_symbol) );
    args.push_back( fc::variant(recipient) );
    args.push_back( fc::variant(memo_message) );
    call_id = glog->log_call_started( this, "wallet_uia_issue", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_uia_issue finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_uia_issue(asset_amount, asset_symbol, recipient, memo_message);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_uia_issue", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_uia_issue_to_addresses(const std::string& symbol, const std::map<std::string, fbtc::blockchain::share_type>& addresses)
{
  ilog("received RPC call: wallet_uia_issue_to_addresses(${symbol}, ${addresses})", ("symbol", symbol)("addresses", addresses));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(symbol) );
    args.push_back( fc::variant(addresses) );
    call_id = glog->log_call_started( this, "wallet_uia_issue_to_addresses", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_uia_issue_to_addresses finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_uia_issue_to_addresses(symbol, addresses);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_uia_issue_to_addresses", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_uia_collect_fees(const std::string& asset_symbol, const std::string& recipient, const std::string& memo_message /* = fc::json::from_string("\"\"").as<std::string>() */)
{
  ilog("received RPC call: wallet_uia_collect_fees(${asset_symbol}, ${recipient}, ${memo_message})", ("asset_symbol", asset_symbol)("recipient", recipient)("memo_message", memo_message));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(asset_symbol) );
    args.push_back( fc::variant(recipient) );
    args.push_back( fc::variant(memo_message) );
    call_id = glog->log_call_started( this, "wallet_uia_collect_fees", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_uia_collect_fees finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_uia_collect_fees(asset_symbol, recipient, memo_message);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_uia_collect_fees", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_uia_update_description(const std::string& paying_account, const std::string& asset_symbol, const std::string& name /* = fc::json::from_string("\"\"").as<std::string>() */, const std::string& description /* = fc::json::from_string("\"\"").as<std::string>() */, const fc::variant& public_data /* = fc::json::from_string("null").as<fc::variant>() */)
{
  ilog("received RPC call: wallet_uia_update_description(${paying_account}, ${asset_symbol}, ${name}, ${description}, ${public_data})", ("paying_account", paying_account)("asset_symbol", asset_symbol)("name", name)("description", description)("public_data", public_data));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(paying_account) );
    args.push_back( fc::variant(asset_symbol) );
    args.push_back( fc::variant(name) );
    args.push_back( fc::variant(description) );
    args.push_back( fc::variant(public_data) );
    call_id = glog->log_call_started( this, "wallet_uia_update_description", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_uia_update_description finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_uia_update_description(paying_account, asset_symbol, name, description, public_data);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_uia_update_description", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_uia_update_supply(const std::string& paying_account, const std::string& asset_symbol, const std::string& max_supply_with_trailing_decimals)
{
  ilog("received RPC call: wallet_uia_update_supply(${paying_account}, ${asset_symbol}, ${max_supply_with_trailing_decimals})", ("paying_account", paying_account)("asset_symbol", asset_symbol)("max_supply_with_trailing_decimals", max_supply_with_trailing_decimals));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(paying_account) );
    args.push_back( fc::variant(asset_symbol) );
    args.push_back( fc::variant(max_supply_with_trailing_decimals) );
    call_id = glog->log_call_started( this, "wallet_uia_update_supply", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_uia_update_supply finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_uia_update_supply(paying_account, asset_symbol, max_supply_with_trailing_decimals);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_uia_update_supply", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_uia_update_fees(const std::string& paying_account, const std::string& asset_symbol, const std::string& withdrawal_fee /* = fc::json::from_string("\"\"").as<std::string>() */, const std::string& market_fee_rate /* = fc::json::from_string("\"\"").as<std::string>() */)
{
  ilog("received RPC call: wallet_uia_update_fees(${paying_account}, ${asset_symbol}, ${withdrawal_fee}, ${market_fee_rate})", ("paying_account", paying_account)("asset_symbol", asset_symbol)("withdrawal_fee", withdrawal_fee)("market_fee_rate", market_fee_rate));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(paying_account) );
    args.push_back( fc::variant(asset_symbol) );
    args.push_back( fc::variant(withdrawal_fee) );
    args.push_back( fc::variant(market_fee_rate) );
    call_id = glog->log_call_started( this, "wallet_uia_update_fees", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_uia_update_fees finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_uia_update_fees(paying_account, asset_symbol, withdrawal_fee, market_fee_rate);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_uia_update_fees", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_uia_update_active_flags(const std::string& paying_account, const std::string& asset_symbol, const fbtc::blockchain::asset_record::flag_enum& flag, bool enable_instead_of_disable)
{
  ilog("received RPC call: wallet_uia_update_active_flags(${paying_account}, ${asset_symbol}, ${flag}, ${enable_instead_of_disable})", ("paying_account", paying_account)("asset_symbol", asset_symbol)("flag", flag)("enable_instead_of_disable", enable_instead_of_disable));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(paying_account) );
    args.push_back( fc::variant(asset_symbol) );
    args.push_back( fc::variant(flag) );
    args.push_back( fc::variant(enable_instead_of_disable) );
    call_id = glog->log_call_started( this, "wallet_uia_update_active_flags", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_uia_update_active_flags finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_uia_update_active_flags(paying_account, asset_symbol, flag, enable_instead_of_disable);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_uia_update_active_flags", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_uia_update_authority_permissions(const std::string& paying_account, const std::string& asset_symbol, const fbtc::blockchain::asset_record::flag_enum& permission, bool add_instead_of_remove)
{
  ilog("received RPC call: wallet_uia_update_authority_permissions(${paying_account}, ${asset_symbol}, ${permission}, ${add_instead_of_remove})", ("paying_account", paying_account)("asset_symbol", asset_symbol)("permission", permission)("add_instead_of_remove", add_instead_of_remove));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(paying_account) );
    args.push_back( fc::variant(asset_symbol) );
    args.push_back( fc::variant(permission) );
    args.push_back( fc::variant(add_instead_of_remove) );
    call_id = glog->log_call_started( this, "wallet_uia_update_authority_permissions", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_uia_update_authority_permissions finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_uia_update_authority_permissions(paying_account, asset_symbol, permission, add_instead_of_remove);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_uia_update_authority_permissions", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_uia_update_whitelist(const std::string& paying_account, const std::string& asset_symbol, const std::string& account_name, bool add_to_whitelist)
{
  ilog("received RPC call: wallet_uia_update_whitelist(${paying_account}, ${asset_symbol}, ${account_name}, ${add_to_whitelist})", ("paying_account", paying_account)("asset_symbol", asset_symbol)("account_name", account_name)("add_to_whitelist", add_to_whitelist));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(paying_account) );
    args.push_back( fc::variant(asset_symbol) );
    args.push_back( fc::variant(account_name) );
    args.push_back( fc::variant(add_to_whitelist) );
    call_id = glog->log_call_started( this, "wallet_uia_update_whitelist", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_uia_update_whitelist finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_uia_update_whitelist(paying_account, asset_symbol, account_name, add_to_whitelist);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_uia_update_whitelist", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_uia_retract_balance(const fbtc::blockchain::address& balance_id, const std::string& account_name)
{
  ilog("received RPC call: wallet_uia_retract_balance(${balance_id}, ${account_name})", ("balance_id", balance_id)("account_name", account_name));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(balance_id) );
    args.push_back( fc::variant(account_name) );
    call_id = glog->log_call_started( this, "wallet_uia_retract_balance", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_uia_retract_balance finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_uia_retract_balance(balance_id, account_name);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_uia_retract_balance", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::vector<fbtc::wallet::escrow_summary> common_api_client::wallet_escrow_summary(const std::string& account_name /* = fc::json::from_string("\"\"").as<std::string>() */) const
{
  ilog("received RPC call: wallet_escrow_summary(${account_name})", ("account_name", account_name));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(account_name) );
    call_id = glog->log_call_started( this, "wallet_escrow_summary", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_escrow_summary finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::vector<fbtc::wallet::escrow_summary> result = get_impl()->wallet_escrow_summary(account_name);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_escrow_summary", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::account_balance_summary_type common_api_client::wallet_account_balance(const std::string& account_name /* = fc::json::from_string("\"\"").as<std::string>() */) const
{
  ilog("received RPC call: wallet_account_balance(${account_name})", ("account_name", account_name));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(account_name) );
    call_id = glog->log_call_started( this, "wallet_account_balance", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_account_balance finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::account_balance_summary_type result = get_impl()->wallet_account_balance(account_name);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_account_balance", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::account_balance_id_summary_type common_api_client::wallet_account_balance_ids(const std::string& account_name /* = fc::json::from_string("\"\"").as<std::string>() */) const
{
  ilog("received RPC call: wallet_account_balance_ids(${account_name})", ("account_name", account_name));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(account_name) );
    call_id = glog->log_call_started( this, "wallet_account_balance_ids", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_account_balance_ids finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::account_balance_id_summary_type result = get_impl()->wallet_account_balance_ids(account_name);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_account_balance_ids", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::account_extended_balance_type common_api_client::wallet_account_balance_extended(const std::string& account_name /* = fc::json::from_string("\"\"").as<std::string>() */) const
{
  ilog("received RPC call: wallet_account_balance_extended(${account_name})", ("account_name", account_name));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(account_name) );
    call_id = glog->log_call_started( this, "wallet_account_balance_extended", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_account_balance_extended finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::account_extended_balance_type result = get_impl()->wallet_account_balance_extended(account_name);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_account_balance_extended", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::account_vesting_balance_summary_type common_api_client::wallet_account_vesting_balances(const std::string& account_name /* = fc::json::from_string("\"\"").as<std::string>() */) const
{
  ilog("received RPC call: wallet_account_vesting_balances(${account_name})", ("account_name", account_name));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(account_name) );
    call_id = glog->log_call_started( this, "wallet_account_vesting_balances", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_account_vesting_balances finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::account_vesting_balance_summary_type result = get_impl()->wallet_account_vesting_balances(account_name);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_account_vesting_balances", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::account_balance_summary_type common_api_client::wallet_account_yield(const std::string& account_name /* = fc::json::from_string("\"\"").as<std::string>() */) const
{
  ilog("received RPC call: wallet_account_yield(${account_name})", ("account_name", account_name));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(account_name) );
    call_id = glog->log_call_started( this, "wallet_account_yield", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_account_yield finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::account_balance_summary_type result = get_impl()->wallet_account_yield(account_name);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_account_yield", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::vector<fbtc::wallet::public_key_summary> common_api_client::wallet_account_list_public_keys(const std::string& account_name)
{
  ilog("received RPC call: wallet_account_list_public_keys(${account_name})", ("account_name", account_name));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(account_name) );
    call_id = glog->log_call_started( this, "wallet_account_list_public_keys", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_account_list_public_keys finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::vector<fbtc::wallet::public_key_summary> result = get_impl()->wallet_account_list_public_keys(account_name);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_account_list_public_keys", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_delegate_withdraw_pay(const std::string& delegate_name, const std::string& to_account_name, const std::string& amount_to_withdraw)
{
  ilog("received RPC call: wallet_delegate_withdraw_pay(${delegate_name}, ${to_account_name}, ${amount_to_withdraw})", ("delegate_name", delegate_name)("to_account_name", to_account_name)("amount_to_withdraw", amount_to_withdraw));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(delegate_name) );
    args.push_back( fc::variant(to_account_name) );
    args.push_back( fc::variant(amount_to_withdraw) );
    call_id = glog->log_call_started( this, "wallet_delegate_withdraw_pay", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_delegate_withdraw_pay finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_delegate_withdraw_pay(delegate_name, to_account_name, amount_to_withdraw);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_delegate_withdraw_pay", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::blockchain::asset common_api_client::wallet_set_transaction_fee(const std::string& fee)
{
  ilog("received RPC call: wallet_set_transaction_fee(${fee})", ("fee", fee));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(fee) );
    call_id = glog->log_call_started( this, "wallet_set_transaction_fee", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_set_transaction_fee finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::blockchain::asset result = get_impl()->wallet_set_transaction_fee(fee);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_set_transaction_fee", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::blockchain::asset common_api_client::wallet_get_transaction_fee(const std::string& symbol /* = fc::json::from_string("\"\"").as<std::string>() */)
{
  ilog("received RPC call: wallet_get_transaction_fee(${symbol})", ("symbol", symbol));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(symbol) );
    call_id = glog->log_call_started( this, "wallet_get_transaction_fee", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_get_transaction_fee finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::blockchain::asset result = get_impl()->wallet_get_transaction_fee(symbol);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_get_transaction_fee", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_market_submit_bid(const std::string& from_account_name, const std::string& quantity, const std::string& quantity_symbol, const std::string& base_price, const std::string& base_symbol, bool allow_stupid_bid /* = fc::json::from_string("\"false\"").as<bool>() */)
{
  ilog("received RPC call: wallet_market_submit_bid(${from_account_name}, ${quantity}, ${quantity_symbol}, ${base_price}, ${base_symbol}, ${allow_stupid_bid})", ("from_account_name", from_account_name)("quantity", quantity)("quantity_symbol", quantity_symbol)("base_price", base_price)("base_symbol", base_symbol)("allow_stupid_bid", allow_stupid_bid));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(from_account_name) );
    args.push_back( fc::variant(quantity) );
    args.push_back( fc::variant(quantity_symbol) );
    args.push_back( fc::variant(base_price) );
    args.push_back( fc::variant(base_symbol) );
    args.push_back( fc::variant(allow_stupid_bid) );
    call_id = glog->log_call_started( this, "wallet_market_submit_bid", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_market_submit_bid finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_market_submit_bid(from_account_name, quantity, quantity_symbol, base_price, base_symbol, allow_stupid_bid);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_market_submit_bid", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_market_submit_ask(const std::string& from_account_name, const std::string& sell_quantity, const std::string& sell_quantity_symbol, const std::string& ask_price, const std::string& ask_price_symbol, bool allow_stupid_ask /* = fc::json::from_string("\"false\"").as<bool>() */)
{
  ilog("received RPC call: wallet_market_submit_ask(${from_account_name}, ${sell_quantity}, ${sell_quantity_symbol}, ${ask_price}, ${ask_price_symbol}, ${allow_stupid_ask})", ("from_account_name", from_account_name)("sell_quantity", sell_quantity)("sell_quantity_symbol", sell_quantity_symbol)("ask_price", ask_price)("ask_price_symbol", ask_price_symbol)("allow_stupid_ask", allow_stupid_ask));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(from_account_name) );
    args.push_back( fc::variant(sell_quantity) );
    args.push_back( fc::variant(sell_quantity_symbol) );
    args.push_back( fc::variant(ask_price) );
    args.push_back( fc::variant(ask_price_symbol) );
    args.push_back( fc::variant(allow_stupid_ask) );
    call_id = glog->log_call_started( this, "wallet_market_submit_ask", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_market_submit_ask finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_market_submit_ask(from_account_name, sell_quantity, sell_quantity_symbol, ask_price, ask_price_symbol, allow_stupid_ask);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_market_submit_ask", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_market_submit_short(const std::string& from_account_name, const std::string& short_collateral, const std::string& collateral_symbol, const std::string& interest_rate, const std::string& quote_symbol, const std::string& short_price_limit /* = fc::json::from_string("0").as<std::string>() */)
{
  ilog("received RPC call: wallet_market_submit_short(${from_account_name}, ${short_collateral}, ${collateral_symbol}, ${interest_rate}, ${quote_symbol}, ${short_price_limit})", ("from_account_name", from_account_name)("short_collateral", short_collateral)("collateral_symbol", collateral_symbol)("interest_rate", interest_rate)("quote_symbol", quote_symbol)("short_price_limit", short_price_limit));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(from_account_name) );
    args.push_back( fc::variant(short_collateral) );
    args.push_back( fc::variant(collateral_symbol) );
    args.push_back( fc::variant(interest_rate) );
    args.push_back( fc::variant(quote_symbol) );
    args.push_back( fc::variant(short_price_limit) );
    call_id = glog->log_call_started( this, "wallet_market_submit_short", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_market_submit_short finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_market_submit_short(from_account_name, short_collateral, collateral_symbol, interest_rate, quote_symbol, short_price_limit);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_market_submit_short", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_market_cover(const std::string& from_account_name, const std::string& quantity, const std::string& quantity_symbol, const fbtc::blockchain::order_id_type& cover_id)
{
  ilog("received RPC call: wallet_market_cover(${from_account_name}, ${quantity}, ${quantity_symbol}, ${cover_id})", ("from_account_name", from_account_name)("quantity", quantity)("quantity_symbol", quantity_symbol)("cover_id", cover_id));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(from_account_name) );
    args.push_back( fc::variant(quantity) );
    args.push_back( fc::variant(quantity_symbol) );
    args.push_back( fc::variant(cover_id) );
    call_id = glog->log_call_started( this, "wallet_market_cover", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_market_cover finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_market_cover(from_account_name, quantity, quantity_symbol, cover_id);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_market_cover", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_market_batch_update(const std::vector<fbtc::blockchain::order_id_type>& cancel_order_ids, const std::vector<fbtc::wallet::order_description>& new_orders, bool sign)
{
  ilog("received RPC call: wallet_market_batch_update(${cancel_order_ids}, ${new_orders}, ${sign})", ("cancel_order_ids", cancel_order_ids)("new_orders", new_orders)("sign", sign));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(cancel_order_ids) );
    args.push_back( fc::variant(new_orders) );
    args.push_back( fc::variant(sign) );
    call_id = glog->log_call_started( this, "wallet_market_batch_update", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_market_batch_update finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_market_batch_update(cancel_order_ids, new_orders, sign);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_market_batch_update", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_market_add_collateral(const std::string& from_account_name, const fbtc::blockchain::order_id_type& cover_id, const std::string& real_quantity_collateral_to_add)
{
  ilog("received RPC call: wallet_market_add_collateral(${from_account_name}, ${cover_id}, ${real_quantity_collateral_to_add})", ("from_account_name", from_account_name)("cover_id", cover_id)("real_quantity_collateral_to_add", real_quantity_collateral_to_add));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(from_account_name) );
    args.push_back( fc::variant(cover_id) );
    args.push_back( fc::variant(real_quantity_collateral_to_add) );
    call_id = glog->log_call_started( this, "wallet_market_add_collateral", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_market_add_collateral finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_market_add_collateral(from_account_name, cover_id, real_quantity_collateral_to_add);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_market_add_collateral", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::map<fbtc::blockchain::order_id_type, fbtc::blockchain::market_order> common_api_client::wallet_market_order_list(const std::string& base_symbol, const std::string& quote_symbol, uint32_t limit /* = fc::json::from_string("-1").as<uint32_t>() */, const std::string& account_name /* = fc::json::from_string("\"\"").as<std::string>() */)
{
  ilog("received RPC call: wallet_market_order_list(${base_symbol}, ${quote_symbol}, ${limit}, ${account_name})", ("base_symbol", base_symbol)("quote_symbol", quote_symbol)("limit", limit)("account_name", account_name));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(base_symbol) );
    args.push_back( fc::variant(quote_symbol) );
    args.push_back( fc::variant(limit) );
    args.push_back( fc::variant(account_name) );
    call_id = glog->log_call_started( this, "wallet_market_order_list", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_market_order_list finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::map<fbtc::blockchain::order_id_type, fbtc::blockchain::market_order> result = get_impl()->wallet_market_order_list(base_symbol, quote_symbol, limit, account_name);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_market_order_list", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::map<fbtc::blockchain::order_id_type, fbtc::blockchain::market_order> common_api_client::wallet_account_order_list(const std::string& account_name /* = fc::json::from_string("\"\"").as<std::string>() */, uint32_t limit /* = fc::json::from_string("-1").as<uint32_t>() */)
{
  ilog("received RPC call: wallet_account_order_list(${account_name}, ${limit})", ("account_name", account_name)("limit", limit));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(account_name) );
    args.push_back( fc::variant(limit) );
    call_id = glog->log_call_started( this, "wallet_account_order_list", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_account_order_list finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::map<fbtc::blockchain::order_id_type, fbtc::blockchain::market_order> result = get_impl()->wallet_account_order_list(account_name, limit);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_account_order_list", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_market_cancel_order(const fbtc::blockchain::order_id_type& order_id)
{
  ilog("received RPC call: wallet_market_cancel_order(${order_id})", ("order_id", order_id));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(order_id) );
    call_id = glog->log_call_started( this, "wallet_market_cancel_order", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_market_cancel_order finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_market_cancel_order(order_id);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_market_cancel_order", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_market_cancel_orders(const std::vector<fbtc::blockchain::order_id_type>& order_ids)
{
  ilog("received RPC call: wallet_market_cancel_orders(${order_ids})", ("order_ids", order_ids));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(order_ids) );
    call_id = glog->log_call_started( this, "wallet_market_cancel_orders", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_market_cancel_orders finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_market_cancel_orders(order_ids);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_market_cancel_orders", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fc::optional<std::string> common_api_client::wallet_dump_private_key(const std::string& input) const
{
  ilog("received RPC call: wallet_dump_private_key(${input})", ("input", input));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(input) );
    call_id = glog->log_call_started( this, "wallet_dump_private_key", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_dump_private_key finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fc::optional<std::string> result = get_impl()->wallet_dump_private_key(input);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_dump_private_key", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fc::optional<std::string> common_api_client::wallet_dump_account_private_key(const std::string& account_name, const fbtc::wallet::account_key_type& key_type) const
{
  ilog("received RPC call: wallet_dump_account_private_key(${account_name}, ${key_type})", ("account_name", account_name)("key_type", key_type));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(account_name) );
    args.push_back( fc::variant(key_type) );
    call_id = glog->log_call_started( this, "wallet_dump_account_private_key", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_dump_account_private_key finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fc::optional<std::string> result = get_impl()->wallet_dump_account_private_key(account_name, key_type);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_dump_account_private_key", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::account_vote_summary_type common_api_client::wallet_account_vote_summary(const std::string& account_name /* = fc::json::from_string("\"\"").as<std::string>() */) const
{
  ilog("received RPC call: wallet_account_vote_summary(${account_name})", ("account_name", account_name));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(account_name) );
    call_id = glog->log_call_started( this, "wallet_account_vote_summary", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_account_vote_summary finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::account_vote_summary_type result = get_impl()->wallet_account_vote_summary(account_name);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_account_vote_summary", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::wallet_set_setting(const std::string& name, const fc::variant& value)
{
  ilog("received RPC call: wallet_set_setting(${name}, ${value})", ("name", name)("value", value));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(name) );
    args.push_back( fc::variant(value) );
    call_id = glog->log_call_started( this, "wallet_set_setting", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_set_setting finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->wallet_set_setting(name, value);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_set_setting", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fc::optional<fc::variant> common_api_client::wallet_get_setting(const std::string& name)
{
  ilog("received RPC call: wallet_get_setting(${name})", ("name", name));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(name) );
    call_id = glog->log_call_started( this, "wallet_get_setting", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_get_setting finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fc::optional<fc::variant> result = get_impl()->wallet_get_setting(name);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_get_setting", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::wallet_delegate_set_block_production(const std::string& delegate_name, bool enabled)
{
  ilog("received RPC call: wallet_delegate_set_block_production(${delegate_name}, ${enabled})", ("delegate_name", delegate_name)("enabled", enabled));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(delegate_name) );
    args.push_back( fc::variant(enabled) );
    call_id = glog->log_call_started( this, "wallet_delegate_set_block_production", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_delegate_set_block_production finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->wallet_delegate_set_block_production(delegate_name, enabled);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_delegate_set_block_production", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

bool common_api_client::wallet_set_transaction_scanning(bool enabled)
{
  ilog("received RPC call: wallet_set_transaction_scanning(${enabled})", ("enabled", enabled));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(enabled) );
    call_id = glog->log_call_started( this, "wallet_set_transaction_scanning", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_set_transaction_scanning finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    bool result = get_impl()->wallet_set_transaction_scanning(enabled);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_set_transaction_scanning", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fc::ecc::compact_signature common_api_client::wallet_sign_hash(const std::string& signer, const fc::sha256& hash)
{
  ilog("received RPC call: wallet_sign_hash(${signer}, ${hash})", ("signer", signer)("hash", hash));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(signer) );
    args.push_back( fc::variant(hash) );
    call_id = glog->log_call_started( this, "wallet_sign_hash", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_sign_hash finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fc::ecc::compact_signature result = get_impl()->wallet_sign_hash(signer, hash);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_sign_hash", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::string common_api_client::wallet_login_start(const std::string& server_account)
{
  ilog("received RPC call: wallet_login_start(${server_account})", ("server_account", server_account));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(server_account) );
    call_id = glog->log_call_started( this, "wallet_login_start", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_login_start finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::string result = get_impl()->wallet_login_start(server_account);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_login_start", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fc::variant common_api_client::wallet_login_finish(const fbtc::blockchain::public_key_type& server_key, const fbtc::blockchain::public_key_type& client_key, const fc::ecc::compact_signature& client_signature)
{
  ilog("received RPC call: wallet_login_finish(${server_key}, ${client_key}, ${client_signature})", ("server_key", server_key)("client_key", client_key)("client_signature", client_signature));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(server_key) );
    args.push_back( fc::variant(client_key) );
    args.push_back( fc::variant(client_signature) );
    call_id = glog->log_call_started( this, "wallet_login_finish", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_login_finish finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fc::variant result = get_impl()->wallet_login_finish(server_key, client_key, client_signature);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_login_finish", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::transaction_builder common_api_client::wallet_balance_set_vote_info(const fbtc::blockchain::address& balance_id, const std::string& voter_address /* = fc::json::from_string("\"\"").as<std::string>() */, const fbtc::wallet::vote_strategy& strategy /* = fc::json::from_string("\"vote_all\"").as<fbtc::wallet::vote_strategy>() */, bool sign_and_broadcast /* = fc::json::from_string("\"true\"").as<bool>() */, const std::string& builder_path /* = fc::json::from_string("\"\"").as<std::string>() */)
{
  ilog("received RPC call: wallet_balance_set_vote_info(${balance_id}, ${voter_address}, ${strategy}, ${sign_and_broadcast}, ${builder_path})", ("balance_id", balance_id)("voter_address", voter_address)("strategy", strategy)("sign_and_broadcast", sign_and_broadcast)("builder_path", builder_path));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(balance_id) );
    args.push_back( fc::variant(voter_address) );
    args.push_back( fc::variant(strategy) );
    args.push_back( fc::variant(sign_and_broadcast) );
    args.push_back( fc::variant(builder_path) );
    call_id = glog->log_call_started( this, "wallet_balance_set_vote_info", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_balance_set_vote_info finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::transaction_builder result = get_impl()->wallet_balance_set_vote_info(balance_id, voter_address, strategy, sign_and_broadcast, builder_path);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_balance_set_vote_info", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_publish_slate(const std::string& publishing_account_name, const std::string& paying_account_name /* = fc::json::from_string("\"\"").as<std::string>() */)
{
  ilog("received RPC call: wallet_publish_slate(${publishing_account_name}, ${paying_account_name})", ("publishing_account_name", publishing_account_name)("paying_account_name", paying_account_name));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(publishing_account_name) );
    args.push_back( fc::variant(paying_account_name) );
    call_id = glog->log_call_started( this, "wallet_publish_slate", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_publish_slate finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_publish_slate(publishing_account_name, paying_account_name);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_publish_slate", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_publish_version(const std::string& publishing_account_name, const std::string& paying_account_name /* = fc::json::from_string("\"\"").as<std::string>() */)
{
  ilog("received RPC call: wallet_publish_version(${publishing_account_name}, ${paying_account_name})", ("publishing_account_name", publishing_account_name)("paying_account_name", paying_account_name));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(publishing_account_name) );
    args.push_back( fc::variant(paying_account_name) );
    call_id = glog->log_call_started( this, "wallet_publish_version", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_publish_version finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_publish_version(publishing_account_name, paying_account_name);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_publish_version", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_collect_genesis_balances(const std::string& account_name)
{
  ilog("received RPC call: wallet_collect_genesis_balances(${account_name})", ("account_name", account_name));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(account_name) );
    call_id = glog->log_call_started( this, "wallet_collect_genesis_balances", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_collect_genesis_balances finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_collect_genesis_balances(account_name);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_collect_genesis_balances", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_collect_vested_balances(const std::string& account_name)
{
  ilog("received RPC call: wallet_collect_vested_balances(${account_name})", ("account_name", account_name));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(account_name) );
    call_id = glog->log_call_started( this, "wallet_collect_vested_balances", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_collect_vested_balances finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_collect_vested_balances(account_name);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_collect_vested_balances", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_delegate_update_signing_key(const std::string& authorizing_account_name, const std::string& delegate_name, const fbtc::blockchain::public_key_type& signing_key)
{
  ilog("received RPC call: wallet_delegate_update_signing_key(${authorizing_account_name}, ${delegate_name}, ${signing_key})", ("authorizing_account_name", authorizing_account_name)("delegate_name", delegate_name)("signing_key", signing_key));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(authorizing_account_name) );
    args.push_back( fc::variant(delegate_name) );
    args.push_back( fc::variant(signing_key) );
    call_id = glog->log_call_started( this, "wallet_delegate_update_signing_key", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_delegate_update_signing_key finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_delegate_update_signing_key(authorizing_account_name, delegate_name, signing_key);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_delegate_update_signing_key", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

int32_t common_api_client::wallet_recover_accounts(int32_t accounts_to_recover, int32_t maximum_number_of_attempts /* = fc::json::from_string("1000").as<int32_t>() */)
{
  ilog("received RPC call: wallet_recover_accounts(${accounts_to_recover}, ${maximum_number_of_attempts})", ("accounts_to_recover", accounts_to_recover)("maximum_number_of_attempts", maximum_number_of_attempts));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(accounts_to_recover) );
    args.push_back( fc::variant(maximum_number_of_attempts) );
    call_id = glog->log_call_started( this, "wallet_recover_accounts", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_recover_accounts finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    int32_t result = get_impl()->wallet_recover_accounts(accounts_to_recover, maximum_number_of_attempts);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_recover_accounts", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_recover_titan_deposit_info(const std::string& transaction_id_prefix, const std::string& recipient_account /* = fc::json::from_string("\"\"").as<std::string>() */)
{
  ilog("received RPC call: wallet_recover_titan_deposit_info(${transaction_id_prefix}, ${recipient_account})", ("transaction_id_prefix", transaction_id_prefix)("recipient_account", recipient_account));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(transaction_id_prefix) );
    args.push_back( fc::variant(recipient_account) );
    call_id = glog->log_call_started( this, "wallet_recover_titan_deposit_info", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_recover_titan_deposit_info finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_recover_titan_deposit_info(transaction_id_prefix, recipient_account);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_recover_titan_deposit_info", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fc::optional<fc::variant_object> common_api_client::wallet_verify_titan_deposit(const std::string& transaction_id_prefix)
{
  ilog("received RPC call: wallet_verify_titan_deposit(${transaction_id_prefix})", ("transaction_id_prefix", transaction_id_prefix));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(transaction_id_prefix) );
    call_id = glog->log_call_started( this, "wallet_verify_titan_deposit", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_verify_titan_deposit finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fc::optional<fc::variant_object> result = get_impl()->wallet_verify_titan_deposit(transaction_id_prefix);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_verify_titan_deposit", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_publish_price_feed(const std::string& delegate_account, const std::string& price, const std::string& asset_symbol)
{
  ilog("received RPC call: wallet_publish_price_feed(${delegate_account}, ${price}, ${asset_symbol})", ("delegate_account", delegate_account)("price", price)("asset_symbol", asset_symbol));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(delegate_account) );
    args.push_back( fc::variant(price) );
    args.push_back( fc::variant(asset_symbol) );
    call_id = glog->log_call_started( this, "wallet_publish_price_feed", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_publish_price_feed finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_publish_price_feed(delegate_account, price, asset_symbol);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_publish_price_feed", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_publish_feeds(const std::string& delegate_account, const std::map<std::string, std::string>& symbol_to_price_map)
{
  ilog("received RPC call: wallet_publish_feeds(${delegate_account}, ${symbol_to_price_map})", ("delegate_account", delegate_account)("symbol_to_price_map", symbol_to_price_map));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(delegate_account) );
    args.push_back( fc::variant(symbol_to_price_map) );
    call_id = glog->log_call_started( this, "wallet_publish_feeds", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_publish_feeds finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_publish_feeds(delegate_account, symbol_to_price_map);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_publish_feeds", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::vector<std::pair<std::string, fbtc::wallet::wallet_transaction_record>> common_api_client::wallet_publish_feeds_multi_experimental(const std::map<std::string, std::string>& symbol_to_price_map)
{
  ilog("received RPC call: wallet_publish_feeds_multi_experimental(${symbol_to_price_map})", ("symbol_to_price_map", symbol_to_price_map));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(symbol_to_price_map) );
    call_id = glog->log_call_started( this, "wallet_publish_feeds_multi_experimental", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_publish_feeds_multi_experimental finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::vector<std::pair<std::string, fbtc::wallet::wallet_transaction_record>> result = get_impl()->wallet_publish_feeds_multi_experimental(symbol_to_price_map);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_publish_feeds_multi_experimental", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::wallet_repair_records(const std::string& collecting_account_name /* = fc::json::from_string("\"\"").as<std::string>() */)
{
  ilog("received RPC call: wallet_repair_records(${collecting_account_name})", ("collecting_account_name", collecting_account_name));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(collecting_account_name) );
    call_id = glog->log_call_started( this, "wallet_repair_records", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_repair_records finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->wallet_repair_records(collecting_account_name);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_repair_records", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

int32_t common_api_client::wallet_regenerate_keys(const std::string& account_name, uint32_t max_key_number)
{
  ilog("received RPC call: wallet_regenerate_keys(${account_name}, ${max_key_number})", ("account_name", account_name)("max_key_number", max_key_number));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(account_name) );
    args.push_back( fc::variant(max_key_number) );
    call_id = glog->log_call_started( this, "wallet_regenerate_keys", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_regenerate_keys finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    int32_t result = get_impl()->wallet_regenerate_keys(account_name, max_key_number);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_regenerate_keys", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fbtc::wallet::wallet_transaction_record common_api_client::wallet_account_retract(const std::string& account_to_retract, const std::string& pay_from_account)
{
  ilog("received RPC call: wallet_account_retract(${account_to_retract}, ${pay_from_account})", ("account_to_retract", account_to_retract)("pay_from_account", pay_from_account));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(account_to_retract) );
    args.push_back( fc::variant(pay_from_account) );
    call_id = glog->log_call_started( this, "wallet_account_retract", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_account_retract finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fbtc::wallet::wallet_transaction_record result = get_impl()->wallet_account_retract(account_to_retract, pay_from_account);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_account_retract", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::string common_api_client::wallet_generate_brain_seed() const
{
  ilog("received RPC call: wallet_generate_brain_seed()", );
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    call_id = glog->log_call_started( this, "wallet_generate_brain_seed", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call wallet_generate_brain_seed finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::string result = get_impl()->wallet_generate_brain_seed();
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "wallet_generate_brain_seed", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fc::variant_object common_api_client::fetch_welcome_package(const fc::variant_object& arguments)
{
  ilog("received RPC call: fetch_welcome_package(${arguments})", ("arguments", arguments));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(arguments) );
    call_id = glog->log_call_started( this, "fetch_welcome_package", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call fetch_welcome_package finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fc::variant_object result = get_impl()->fetch_welcome_package(arguments);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "fetch_welcome_package", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

bool common_api_client::request_register_account(const fbtc::blockchain::account_record& account)
{
  ilog("received RPC call: request_register_account(${account})", ("account", account));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(account) );
    call_id = glog->log_call_started( this, "request_register_account", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call request_register_account finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    bool result = get_impl()->request_register_account(account);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "request_register_account", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

bool common_api_client::approve_register_account(const std::string& account_salt, const std::string& paying_account_name)
{
  ilog("received RPC call: approve_register_account(${account_salt}, ${paying_account_name})", ("account_salt", account_salt)("paying_account_name", paying_account_name));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(account_salt) );
    args.push_back( fc::variant(paying_account_name) );
    call_id = glog->log_call_started( this, "approve_register_account", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call approve_register_account finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    bool result = get_impl()->approve_register_account(account_salt, paying_account_name);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "approve_register_account", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::debug_start_simulated_time(const fc::time_point& new_simulated_time)
{
  ilog("received RPC call: debug_start_simulated_time(${new_simulated_time})", ("new_simulated_time", new_simulated_time));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(new_simulated_time) );
    call_id = glog->log_call_started( this, "debug_start_simulated_time", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call debug_start_simulated_time finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->debug_start_simulated_time(new_simulated_time);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "debug_start_simulated_time", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::debug_advance_time(int32_t delta_time_seconds, const std::string& unit /* = fc::json::from_string("\"seconds\"").as<std::string>() */)
{
  ilog("received RPC call: debug_advance_time(${delta_time_seconds}, ${unit})", ("delta_time_seconds", delta_time_seconds)("unit", unit));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(delta_time_seconds) );
    args.push_back( fc::variant(unit) );
    call_id = glog->log_call_started( this, "debug_advance_time", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call debug_advance_time finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->debug_advance_time(delta_time_seconds, unit);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "debug_advance_time", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::debug_trap(uint32_t block_number)
{
  ilog("received RPC call: debug_trap(${block_number})", ("block_number", block_number));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(block_number) );
    call_id = glog->log_call_started( this, "debug_trap", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call debug_trap finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->debug_trap(block_number);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "debug_trap", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::debug_wait(uint32_t wait_time) const
{
  ilog("received RPC call: debug_wait(${wait_time})", ("wait_time", wait_time));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(wait_time) );
    call_id = glog->log_call_started( this, "debug_wait", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call debug_wait finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->debug_wait(wait_time);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "debug_wait", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::debug_wait_for_block_by_number(uint32_t block_number, const std::string& type /* = fc::json::from_string("\"absolute\"").as<std::string>() */)
{
  ilog("received RPC call: debug_wait_for_block_by_number(${block_number}, ${type})", ("block_number", block_number)("type", type));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(block_number) );
    args.push_back( fc::variant(type) );
    call_id = glog->log_call_started( this, "debug_wait_for_block_by_number", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call debug_wait_for_block_by_number finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->debug_wait_for_block_by_number(block_number, type);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "debug_wait_for_block_by_number", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::debug_wait_block_interval(uint32_t wait_time_in_block_intervals) const
{
  ilog("received RPC call: debug_wait_block_interval(${wait_time_in_block_intervals})", ("wait_time_in_block_intervals", wait_time_in_block_intervals));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(wait_time_in_block_intervals) );
    call_id = glog->log_call_started( this, "debug_wait_block_interval", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call debug_wait_block_interval finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->debug_wait_block_interval(wait_time_in_block_intervals);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "debug_wait_block_interval", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::debug_enable_output(bool enable_flag)
{
  ilog("received RPC call: debug_enable_output(${enable_flag})", ("enable_flag", enable_flag));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(enable_flag) );
    call_id = glog->log_call_started( this, "debug_enable_output", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call debug_enable_output finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->debug_enable_output(enable_flag);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "debug_enable_output", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::debug_filter_output_for_tests(bool enable_flag)
{
  ilog("received RPC call: debug_filter_output_for_tests(${enable_flag})", ("enable_flag", enable_flag));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(enable_flag) );
    call_id = glog->log_call_started( this, "debug_filter_output_for_tests", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call debug_filter_output_for_tests finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->debug_filter_output_for_tests(enable_flag);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "debug_filter_output_for_tests", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::debug_update_logging_config()
{
  ilog("received RPC call: debug_update_logging_config()", );
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    call_id = glog->log_call_started( this, "debug_update_logging_config", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call debug_update_logging_config finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->debug_update_logging_config();
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "debug_update_logging_config", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fc::variant_object common_api_client::debug_get_call_statistics() const
{
  ilog("received RPC call: debug_get_call_statistics()", );
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    call_id = glog->log_call_started( this, "debug_get_call_statistics", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call debug_get_call_statistics finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fc::variant_object result = get_impl()->debug_get_call_statistics();
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "debug_get_call_statistics", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

std::string common_api_client::debug_get_client_name() const
{
  ilog("received RPC call: debug_get_client_name()", );
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    call_id = glog->log_call_started( this, "debug_get_client_name", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call debug_get_client_name finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::string result = get_impl()->debug_get_client_name();
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "debug_get_client_name", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fc::variants common_api_client::debug_deterministic_private_keys(int32_t start /* = fc::json::from_string("\"-1\"").as<int32_t>() */, int32_t count /* = fc::json::from_string("\"1\"").as<int32_t>() */, const std::string& prefix /* = fc::json::from_string("\"\"").as<std::string>() */, bool import /* = fc::json::from_string("\"false\"").as<bool>() */, const std::string& account_name /* = fc::json::from_string("null").as<std::string>() */, bool create_new_account /* = fc::json::from_string("false").as<bool>() */, bool rescan /* = fc::json::from_string("false").as<bool>() */)
{
  ilog("received RPC call: debug_deterministic_private_keys(${start}, ${count}, ${prefix}, ${import}, ${account_name}, ${create_new_account}, ${rescan})", ("start", start)("count", count)("prefix", prefix)("import", import)("account_name", account_name)("create_new_account", create_new_account)("rescan", rescan));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(start) );
    args.push_back( fc::variant(count) );
    args.push_back( fc::variant(prefix) );
    args.push_back( fc::variant(import) );
    args.push_back( fc::variant(account_name) );
    args.push_back( fc::variant(create_new_account) );
    args.push_back( fc::variant(rescan) );
    call_id = glog->log_call_started( this, "debug_deterministic_private_keys", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call debug_deterministic_private_keys finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fc::variants result = get_impl()->debug_deterministic_private_keys(start, count, prefix, import, account_name, create_new_account, rescan);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "debug_deterministic_private_keys", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::debug_stop_before_block(uint32_t block_number)
{
  ilog("received RPC call: debug_stop_before_block(${block_number})", ("block_number", block_number));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(block_number) );
    call_id = glog->log_call_started( this, "debug_stop_before_block", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call debug_stop_before_block finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->debug_stop_before_block(block_number);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "debug_stop_before_block", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

void common_api_client::debug_verify_market_matching(bool enable_flag)
{
  ilog("received RPC call: debug_verify_market_matching(${enable_flag})", ("enable_flag", enable_flag));
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    args.push_back( fc::variant(enable_flag) );
    call_id = glog->log_call_started( this, "debug_verify_market_matching", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call debug_verify_market_matching finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    std::nullptr_t result = nullptr;
    get_impl()->debug_verify_market_matching(enable_flag);
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "debug_verify_market_matching", args, fc::variant(result) );

    return;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

fc::variants common_api_client::debug_list_matching_errors() const
{
  ilog("received RPC call: debug_list_matching_errors()", );
  fbtc::api::global_api_logger* glog = fbtc::api::global_api_logger::get_instance();
  uint64_t call_id = 0;
  fc::variants args;
  if( glog != NULL )
  {
    call_id = glog->log_call_started( this, "debug_list_matching_errors", args );
  }

  struct scope_exit
  {
    fc::time_point start_time;
    scope_exit() : start_time(fc::time_point::now()) {}
    ~scope_exit() { dlog("RPC call debug_list_matching_errors finished in ${time} ms", ("time", (fc::time_point::now() - start_time).count() / 1000)); }
  } execution_time_logger;
  try
  {
    fc::variants result = get_impl()->debug_list_matching_errors();
    if( call_id != 0 )
      glog->log_call_finished( call_id, this, "debug_list_matching_errors", args, fc::variant(result) );

    return result;
  }
  FC_RETHROW_EXCEPTIONS(warn, "")
}

} } // end namespace fbtc::rpc_stubs
