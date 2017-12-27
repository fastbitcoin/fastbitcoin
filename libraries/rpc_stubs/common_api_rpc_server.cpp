//                                   _           _    __ _ _      
//                                  | |         | |  / _(_) |     
//    __ _  ___ _ __   ___ _ __ __ _| |_ ___  __| | | |_ _| | ___ 
//   / _` |/ _ \ '_ \ / _ \ '__/ _` | __/ _ \/ _` | |  _| | |/ _ \`
//  | (_| |  __/ | | |  __/ | | (_| | ||  __/ (_| | | | | | |  __/
//   \__, |\___|_| |_|\___|_|  \__,_|\__\___|\__,_| |_| |_|_|\___|
//    __/ |                                                       
//   |___/                                                        
//
//
// Warning: this is a generated file, any changes made here will be
//          overwritten by the build process.  If you need to change what is
//          generated here, you should either modify the input json files
//          (network_api.json, wallet_api.json, etc) or modify the code
//          generator (fbtc_api_generator.cpp) itself
//
#define DEFAULT_LOGGER "rpc"
#include <fbtc/rpc_stubs/common_api_rpc_server.hpp>
#include <fbtc/api/api_metadata.hpp>
#include <fbtc/api/conversion_functions.hpp>
#include <boost/bind.hpp>
#include <fbtc/api/api_metadata.hpp>
#include <fbtc/blockchain/address.hpp>
#include <fbtc/blockchain/asset_record.hpp>
#include <fbtc/blockchain/block.hpp>
#include <fbtc/blockchain/block_record.hpp>
#include <fbtc/blockchain/chain_database.hpp>
#include <fbtc/blockchain/feed_operations.hpp>
#include <fbtc/blockchain/market_records.hpp>
#include <fbtc/blockchain/operations.hpp>
#include <fbtc/blockchain/pts_address.hpp>
#include <fbtc/blockchain/transaction.hpp>
#include <fbtc/blockchain/types.hpp>
#include <fbtc/net/node.hpp>
#include <fbtc/wallet/pretty.hpp>
#include <fbtc/wallet/transaction_builder.hpp>
#include <fbtc/wallet/wallet.hpp>
#include <fbtc/wallet/wallet_records.hpp>
#include <fc/crypto/elliptic.hpp>
#include <fc/crypto/sha256.hpp>
#include <fc/exception/exception.hpp>
#include <fc/filesystem.hpp>
#include <fc/network/ip.hpp>
#include <fc/optional.hpp>
#include <fc/time.hpp>
#include <stdint.h>
#include <string>

namespace fbtc { namespace rpc_stubs {

fc::variant common_api_rpc_server::about_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites


  fc::variant_object result = get_client()->about();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::about_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites


  fc::variant_object result = get_client()->about();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::get_info_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites


  fc::variant_object result = get_client()->get_info();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::get_info_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites


  fc::variant_object result = get_client()->get_info();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::stop_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites


  get_client()->stop();
  return fc::variant();
}

fc::variant common_api_rpc_server::stop_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites


  get_client()->stop();
  return fc::variant();
}

fc::variant common_api_rpc_server::help_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  std::string command_name = (parameters.size() <= 0) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[0].as<std::string>();

  std::string result = get_client()->help(command_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::help_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  std::string command_name = parameters.contains("command_name") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["command_name"].as<std::string>();

  std::string result = get_client()->help(command_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::validate_address_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (address)");
  std::string address = parameters[0].as<std::string>();

  fc::variant_object result = get_client()->validate_address(address);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::validate_address_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("address"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'address'");
  std::string address = parameters["address"].as<std::string>();

  fc::variant_object result = get_client()->validate_address(address);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::convert_to_native_address_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (raw_address)");
  std::string raw_address = parameters[0].as<std::string>();

  fbtc::blockchain::address result = get_client()->convert_to_native_address(raw_address);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::convert_to_native_address_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("raw_address"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'raw_address'");
  std::string raw_address = parameters["raw_address"].as<std::string>();

  fbtc::blockchain::address result = get_client()->convert_to_native_address(raw_address);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::execute_command_line_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (input)");
  std::string input = parameters[0].as<std::string>();

  std::string result = get_client()->execute_command_line(input);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::execute_command_line_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (!parameters.contains("input"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'input'");
  std::string input = parameters["input"].as<std::string>();

  std::string result = get_client()->execute_command_line(input);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::execute_script_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (script)");
  fc::path script = parameters[0].as<fc::path>();

  get_client()->execute_script(script);
  return fc::variant();
}

fc::variant common_api_rpc_server::execute_script_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (!parameters.contains("script"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'script'");
  fc::path script = parameters["script"].as<fc::path>();

  get_client()->execute_script(script);
  return fc::variant();
}

fc::variant common_api_rpc_server::batch_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (method_name)");
  std::string method_name = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (parameters_list)");
  std::vector<fc::variants> parameters_list = parameters[1].as<std::vector<fc::variants>>();

  fc::variants result = get_client()->batch(method_name, parameters_list);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::batch_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("method_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'method_name'");
  std::string method_name = parameters["method_name"].as<std::string>();
  if (!parameters.contains("parameters_list"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'parameters_list'");
  std::vector<fc::variants> parameters_list = parameters["parameters_list"].as<std::vector<fc::variants>>();

  fc::variants result = get_client()->batch(method_name, parameters_list);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::batch_authenticated_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (method_name)");
  std::string method_name = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (parameters_list)");
  std::vector<fc::variants> parameters_list = parameters[1].as<std::vector<fc::variants>>();

  fc::variants result = get_client()->batch_authenticated(method_name, parameters_list);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::batch_authenticated_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (!parameters.contains("method_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'method_name'");
  std::string method_name = parameters["method_name"].as<std::string>();
  if (!parameters.contains("parameters_list"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'parameters_list'");
  std::vector<fc::variants> parameters_list = parameters["parameters_list"].as<std::vector<fc::variants>>();

  fc::variants result = get_client()->batch_authenticated(method_name, parameters_list);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::builder_finalize_and_sign_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (builder)");
  fbtc::wallet::transaction_builder builder = parameters[0].as<fbtc::wallet::transaction_builder>();

  fbtc::wallet::wallet_transaction_record result = get_client()->builder_finalize_and_sign(builder);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::builder_finalize_and_sign_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("builder"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'builder'");
  fbtc::wallet::transaction_builder builder = parameters["builder"].as<fbtc::wallet::transaction_builder>();

  fbtc::wallet::wallet_transaction_record result = get_client()->builder_finalize_and_sign(builder);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::meta_help_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites


  std::map<std::string, fbtc::api::method_data> result = get_client()->meta_help();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::meta_help_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites


  std::map<std::string, fbtc::api::method_data> result = get_client()->meta_help();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::rpc_set_username_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  std::string username = (parameters.size() <= 0) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[0].as<std::string>();

  get_client()->rpc_set_username(username);
  return fc::variant();
}

fc::variant common_api_rpc_server::rpc_set_username_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  std::string username = parameters.contains("username") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["username"].as<std::string>();

  get_client()->rpc_set_username(username);
  return fc::variant();
}

fc::variant common_api_rpc_server::rpc_set_password_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  std::string password = (parameters.size() <= 0) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[0].as<std::string>();

  get_client()->rpc_set_password(password);
  return fc::variant();
}

fc::variant common_api_rpc_server::rpc_set_password_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  std::string password = parameters.contains("password") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["password"].as<std::string>();

  get_client()->rpc_set_password(password);
  return fc::variant();
}

fc::variant common_api_rpc_server::rpc_start_server_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  uint32_t port = (parameters.size() <= 0) ?
    (fc::json::from_string("\"65065\"").as<uint32_t>()) :
    parameters[0].as<uint32_t>();

  get_client()->rpc_start_server(port);
  return fc::variant();
}

fc::variant common_api_rpc_server::rpc_start_server_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  uint32_t port = parameters.contains("port") ? 
    (fc::json::from_string("\"65065\"").as<uint32_t>()) :
    parameters["port"].as<uint32_t>();

  get_client()->rpc_start_server(port);
  return fc::variant();
}

fc::variant common_api_rpc_server::http_start_server_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  uint32_t port = (parameters.size() <= 0) ?
    (fc::json::from_string("\"65066\"").as<uint32_t>()) :
    parameters[0].as<uint32_t>();

  get_client()->http_start_server(port);
  return fc::variant();
}

fc::variant common_api_rpc_server::http_start_server_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  uint32_t port = parameters.contains("port") ? 
    (fc::json::from_string("\"65066\"").as<uint32_t>()) :
    parameters["port"].as<uint32_t>();

  get_client()->http_start_server(port);
  return fc::variant();
}

fc::variant common_api_rpc_server::ntp_update_time_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites


  get_client()->ntp_update_time();
  return fc::variant();
}

fc::variant common_api_rpc_server::ntp_update_time_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites


  get_client()->ntp_update_time();
  return fc::variant();
}

fc::variant common_api_rpc_server::disk_usage_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites


  fc::variant result = get_client()->disk_usage();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::disk_usage_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites


  fc::variant result = get_client()->disk_usage();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::network_add_node_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (node)");
  std::string node = parameters[0].as<std::string>();
  std::string command = (parameters.size() <= 1) ?
    (fc::json::from_string("\"add\"").as<std::string>()) :
    parameters[1].as<std::string>();

  get_client()->network_add_node(node, command);
  return fc::variant();
}

fc::variant common_api_rpc_server::network_add_node_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (!parameters.contains("node"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'node'");
  std::string node = parameters["node"].as<std::string>();
  std::string command = parameters.contains("command") ? 
    (fc::json::from_string("\"add\"").as<std::string>()) :
    parameters["command"].as<std::string>();

  get_client()->network_add_node(node, command);
  return fc::variant();
}

fc::variant common_api_rpc_server::network_get_connection_count_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites


  uint32_t result = get_client()->network_get_connection_count();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::network_get_connection_count_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites


  uint32_t result = get_client()->network_get_connection_count();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::network_get_peer_info_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  bool not_firewalled = (parameters.size() <= 0) ?
    (fc::json::from_string("false").as<bool>()) :
    parameters[0].as<bool>();

  std::vector<fc::variant_object> result = get_client()->network_get_peer_info(not_firewalled);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::network_get_peer_info_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  bool not_firewalled = parameters.contains("not_firewalled") ? 
    (fc::json::from_string("false").as<bool>()) :
    parameters["not_firewalled"].as<bool>();

  std::vector<fc::variant_object> result = get_client()->network_get_peer_info(not_firewalled);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::network_broadcast_transaction_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_connected_to_network();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (transaction_to_broadcast)");
  fbtc::blockchain::signed_transaction transaction_to_broadcast = parameters[0].as<fbtc::blockchain::signed_transaction>();

  fbtc::blockchain::transaction_id_type result = get_client()->network_broadcast_transaction(transaction_to_broadcast);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::network_broadcast_transaction_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_connected_to_network();
  // done checking prerequisites

  if (!parameters.contains("transaction_to_broadcast"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'transaction_to_broadcast'");
  fbtc::blockchain::signed_transaction transaction_to_broadcast = parameters["transaction_to_broadcast"].as<fbtc::blockchain::signed_transaction>();

  fbtc::blockchain::transaction_id_type result = get_client()->network_broadcast_transaction(transaction_to_broadcast);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::network_set_advanced_node_parameters_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (params)");
  fc::variant_object params = parameters[0].as<fc::variant_object>();

  get_client()->network_set_advanced_node_parameters(params);
  return fc::variant();
}

fc::variant common_api_rpc_server::network_set_advanced_node_parameters_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (!parameters.contains("params"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'params'");
  fc::variant_object params = parameters["params"].as<fc::variant_object>();

  get_client()->network_set_advanced_node_parameters(params);
  return fc::variant();
}

fc::variant common_api_rpc_server::network_get_advanced_node_parameters_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites


  fc::variant_object result = get_client()->network_get_advanced_node_parameters();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::network_get_advanced_node_parameters_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites


  fc::variant_object result = get_client()->network_get_advanced_node_parameters();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::network_get_transaction_propagation_data_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (transaction_id)");
  fbtc::blockchain::transaction_id_type transaction_id = parameters[0].as<fbtc::blockchain::transaction_id_type>();

  fbtc::net::message_propagation_data result = get_client()->network_get_transaction_propagation_data(transaction_id);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::network_get_transaction_propagation_data_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (!parameters.contains("transaction_id"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'transaction_id'");
  fbtc::blockchain::transaction_id_type transaction_id = parameters["transaction_id"].as<fbtc::blockchain::transaction_id_type>();

  fbtc::net::message_propagation_data result = get_client()->network_get_transaction_propagation_data(transaction_id);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::network_get_block_propagation_data_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (block_hash)");
  fbtc::blockchain::block_id_type block_hash = parameters[0].as<fbtc::blockchain::block_id_type>();

  fbtc::net::message_propagation_data result = get_client()->network_get_block_propagation_data(block_hash);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::network_get_block_propagation_data_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (!parameters.contains("block_hash"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'block_hash'");
  fbtc::blockchain::block_id_type block_hash = parameters["block_hash"].as<fbtc::blockchain::block_id_type>();

  fbtc::net::message_propagation_data result = get_client()->network_get_block_propagation_data(block_hash);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::network_set_allowed_peers_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (allowed_peers)");
  std::vector<fbtc::net::node_id_t> allowed_peers = parameters[0].as<std::vector<fbtc::net::node_id_t>>();

  get_client()->network_set_allowed_peers(allowed_peers);
  return fc::variant();
}

fc::variant common_api_rpc_server::network_set_allowed_peers_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (!parameters.contains("allowed_peers"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'allowed_peers'");
  std::vector<fbtc::net::node_id_t> allowed_peers = parameters["allowed_peers"].as<std::vector<fbtc::net::node_id_t>>();

  get_client()->network_set_allowed_peers(allowed_peers);
  return fc::variant();
}

fc::variant common_api_rpc_server::network_get_info_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites


  fc::variant_object result = get_client()->network_get_info();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::network_get_info_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites


  fc::variant_object result = get_client()->network_get_info();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::network_list_potential_peers_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites


  std::vector<fbtc::net::potential_peer_record> result = get_client()->network_list_potential_peers();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::network_list_potential_peers_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites


  std::vector<fbtc::net::potential_peer_record> result = get_client()->network_list_potential_peers();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::network_get_upnp_info_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites


  fc::variant_object result = get_client()->network_get_upnp_info();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::network_get_upnp_info_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites


  fc::variant_object result = get_client()->network_get_upnp_info();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::network_get_usage_stats_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites


  fc::variant_object result = get_client()->network_get_usage_stats();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::network_get_usage_stats_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites


  fc::variant_object result = get_client()->network_get_usage_stats();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::delegate_get_config_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites


  fc::variant result = get_client()->delegate_get_config();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::delegate_get_config_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites


  fc::variant result = get_client()->delegate_get_config();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::delegate_set_network_min_connection_count_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (count)");
  uint32_t count = parameters[0].as<uint32_t>();

  get_client()->delegate_set_network_min_connection_count(count);
  return fc::variant();
}

fc::variant common_api_rpc_server::delegate_set_network_min_connection_count_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("count"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'count'");
  uint32_t count = parameters["count"].as<uint32_t>();

  get_client()->delegate_set_network_min_connection_count(count);
  return fc::variant();
}

fc::variant common_api_rpc_server::delegate_set_block_max_transaction_count_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (count)");
  uint32_t count = parameters[0].as<uint32_t>();

  get_client()->delegate_set_block_max_transaction_count(count);
  return fc::variant();
}

fc::variant common_api_rpc_server::delegate_set_block_max_transaction_count_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("count"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'count'");
  uint32_t count = parameters["count"].as<uint32_t>();

  get_client()->delegate_set_block_max_transaction_count(count);
  return fc::variant();
}

fc::variant common_api_rpc_server::delegate_set_block_max_size_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (size)");
  uint32_t size = parameters[0].as<uint32_t>();

  get_client()->delegate_set_block_max_size(size);
  return fc::variant();
}

fc::variant common_api_rpc_server::delegate_set_block_max_size_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("size"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'size'");
  uint32_t size = parameters["size"].as<uint32_t>();

  get_client()->delegate_set_block_max_size(size);
  return fc::variant();
}

fc::variant common_api_rpc_server::delegate_set_block_max_production_time_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (time)");
  uint64_t time = parameters[0].as<uint64_t>();

  get_client()->delegate_set_block_max_production_time(time);
  return fc::variant();
}

fc::variant common_api_rpc_server::delegate_set_block_max_production_time_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("time"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'time'");
  uint64_t time = parameters["time"].as<uint64_t>();

  get_client()->delegate_set_block_max_production_time(time);
  return fc::variant();
}

fc::variant common_api_rpc_server::delegate_set_transaction_max_size_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (size)");
  uint32_t size = parameters[0].as<uint32_t>();

  get_client()->delegate_set_transaction_max_size(size);
  return fc::variant();
}

fc::variant common_api_rpc_server::delegate_set_transaction_max_size_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("size"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'size'");
  uint32_t size = parameters["size"].as<uint32_t>();

  get_client()->delegate_set_transaction_max_size(size);
  return fc::variant();
}

fc::variant common_api_rpc_server::delegate_set_transaction_canonical_signatures_required_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (required)");
  bool required = parameters[0].as<bool>();

  get_client()->delegate_set_transaction_canonical_signatures_required(required);
  return fc::variant();
}

fc::variant common_api_rpc_server::delegate_set_transaction_canonical_signatures_required_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("required"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'required'");
  bool required = parameters["required"].as<bool>();

  get_client()->delegate_set_transaction_canonical_signatures_required(required);
  return fc::variant();
}

fc::variant common_api_rpc_server::delegate_set_transaction_min_fee_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (fee)");
  uint64_t fee = parameters[0].as<uint64_t>();

  get_client()->delegate_set_transaction_min_fee(fee);
  return fc::variant();
}

fc::variant common_api_rpc_server::delegate_set_transaction_min_fee_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("fee"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'fee'");
  uint64_t fee = parameters["fee"].as<uint64_t>();

  get_client()->delegate_set_transaction_min_fee(fee);
  return fc::variant();
}

fc::variant common_api_rpc_server::delegate_blacklist_add_transaction_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (id)");
  fbtc::blockchain::transaction_id_type id = parameters[0].as<fbtc::blockchain::transaction_id_type>();

  get_client()->delegate_blacklist_add_transaction(id);
  return fc::variant();
}

fc::variant common_api_rpc_server::delegate_blacklist_add_transaction_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("id"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'id'");
  fbtc::blockchain::transaction_id_type id = parameters["id"].as<fbtc::blockchain::transaction_id_type>();

  get_client()->delegate_blacklist_add_transaction(id);
  return fc::variant();
}

fc::variant common_api_rpc_server::delegate_blacklist_remove_transaction_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (id)");
  fbtc::blockchain::transaction_id_type id = parameters[0].as<fbtc::blockchain::transaction_id_type>();

  get_client()->delegate_blacklist_remove_transaction(id);
  return fc::variant();
}

fc::variant common_api_rpc_server::delegate_blacklist_remove_transaction_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("id"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'id'");
  fbtc::blockchain::transaction_id_type id = parameters["id"].as<fbtc::blockchain::transaction_id_type>();

  get_client()->delegate_blacklist_remove_transaction(id);
  return fc::variant();
}

fc::variant common_api_rpc_server::delegate_blacklist_add_operation_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (id)");
  fbtc::blockchain::operation_type_enum id = parameters[0].as<fbtc::blockchain::operation_type_enum>();

  get_client()->delegate_blacklist_add_operation(id);
  return fc::variant();
}

fc::variant common_api_rpc_server::delegate_blacklist_add_operation_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("id"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'id'");
  fbtc::blockchain::operation_type_enum id = parameters["id"].as<fbtc::blockchain::operation_type_enum>();

  get_client()->delegate_blacklist_add_operation(id);
  return fc::variant();
}

fc::variant common_api_rpc_server::delegate_blacklist_remove_operation_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (id)");
  fbtc::blockchain::operation_type_enum id = parameters[0].as<fbtc::blockchain::operation_type_enum>();

  get_client()->delegate_blacklist_remove_operation(id);
  return fc::variant();
}

fc::variant common_api_rpc_server::delegate_blacklist_remove_operation_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("id"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'id'");
  fbtc::blockchain::operation_type_enum id = parameters["id"].as<fbtc::blockchain::operation_type_enum>();

  get_client()->delegate_blacklist_remove_operation(id);
  return fc::variant();
}

fc::variant common_api_rpc_server::blockchain_get_info_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites


  fc::variant_object result = get_client()->blockchain_get_info();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_get_info_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites


  fc::variant_object result = get_client()->blockchain_get_info();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_generate_snapshot_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (filename)");
  std::string filename = parameters[0].as<std::string>();

  get_client()->blockchain_generate_snapshot(filename);
  return fc::variant();
}

fc::variant common_api_rpc_server::blockchain_generate_snapshot_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("filename"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'filename'");
  std::string filename = parameters["filename"].as<std::string>();

  get_client()->blockchain_generate_snapshot(filename);
  return fc::variant();
}

fc::variant common_api_rpc_server::blockchain_graphene_snapshot_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (filename)");
  std::string filename = parameters[0].as<std::string>();
  std::string whitelist_filename = (parameters.size() <= 1) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[1].as<std::string>();

  get_client()->blockchain_graphene_snapshot(filename, whitelist_filename);
  return fc::variant();
}

fc::variant common_api_rpc_server::blockchain_graphene_snapshot_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("filename"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'filename'");
  std::string filename = parameters["filename"].as<std::string>();
  std::string whitelist_filename = parameters.contains("whitelist_filename") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["whitelist_filename"].as<std::string>();

  get_client()->blockchain_graphene_snapshot(filename, whitelist_filename);
  return fc::variant();
}

fc::variant common_api_rpc_server::blockchain_generate_issuance_map_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (symbol)");
  std::string symbol = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (filename)");
  std::string filename = parameters[1].as<std::string>();

  get_client()->blockchain_generate_issuance_map(symbol, filename);
  return fc::variant();
}

fc::variant common_api_rpc_server::blockchain_generate_issuance_map_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'symbol'");
  std::string symbol = parameters["symbol"].as<std::string>();
  if (!parameters.contains("filename"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'filename'");
  std::string filename = parameters["filename"].as<std::string>();

  get_client()->blockchain_generate_issuance_map(symbol, filename);
  return fc::variant();
}

fc::variant common_api_rpc_server::blockchain_calculate_supply_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (asset)");
  std::string asset = parameters[0].as<std::string>();

  fbtc::blockchain::asset result = get_client()->blockchain_calculate_supply(asset);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_calculate_supply_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("asset"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'asset'");
  std::string asset = parameters["asset"].as<std::string>();

  fbtc::blockchain::asset result = get_client()->blockchain_calculate_supply(asset);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_calculate_debt_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (asset)");
  std::string asset = parameters[0].as<std::string>();
  bool include_interest = (parameters.size() <= 1) ?
    (fc::json::from_string("\"false\"").as<bool>()) :
    parameters[1].as<bool>();

  fbtc::blockchain::asset result = get_client()->blockchain_calculate_debt(asset, include_interest);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_calculate_debt_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("asset"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'asset'");
  std::string asset = parameters["asset"].as<std::string>();
  bool include_interest = parameters.contains("include_interest") ? 
    (fc::json::from_string("\"false\"").as<bool>()) :
    parameters["include_interest"].as<bool>();

  fbtc::blockchain::asset result = get_client()->blockchain_calculate_debt(asset, include_interest);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_calculate_max_supply_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  uint8_t average_delegate_pay_rate = (parameters.size() <= 0) ?
    (fc::json::from_string("100").as<uint8_t>()) :
    parameters[0].as<uint8_t>();

  fbtc::blockchain::asset result = get_client()->blockchain_calculate_max_supply(average_delegate_pay_rate);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_calculate_max_supply_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  uint8_t average_delegate_pay_rate = parameters.contains("average_delegate_pay_rate") ? 
    (fc::json::from_string("100").as<uint8_t>()) :
    parameters["average_delegate_pay_rate"].as<uint8_t>();

  fbtc::blockchain::asset result = get_client()->blockchain_calculate_max_supply(average_delegate_pay_rate);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_get_block_count_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites


  uint32_t result = get_client()->blockchain_get_block_count();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_get_block_count_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites


  uint32_t result = get_client()->blockchain_get_block_count();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_list_accounts_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  std::string first_account_name = (parameters.size() <= 0) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[0].as<std::string>();
  uint32_t limit = (parameters.size() <= 1) ?
    (fc::json::from_string("20").as<uint32_t>()) :
    parameters[1].as<uint32_t>();

  std::vector<fbtc::blockchain::account_record> result = get_client()->blockchain_list_accounts(first_account_name, limit);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_list_accounts_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  std::string first_account_name = parameters.contains("first_account_name") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["first_account_name"].as<std::string>();
  uint32_t limit = parameters.contains("limit") ? 
    (fc::json::from_string("20").as<uint32_t>()) :
    parameters["limit"].as<uint32_t>();

  std::vector<fbtc::blockchain::account_record> result = get_client()->blockchain_list_accounts(first_account_name, limit);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_list_recently_updated_accounts_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites


  std::vector<fbtc::blockchain::account_record> result = get_client()->blockchain_list_recently_updated_accounts();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_list_recently_updated_accounts_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites


  std::vector<fbtc::blockchain::account_record> result = get_client()->blockchain_list_recently_updated_accounts();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_list_recently_registered_accounts_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites


  std::vector<fbtc::blockchain::account_record> result = get_client()->blockchain_list_recently_registered_accounts();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_list_recently_registered_accounts_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites


  std::vector<fbtc::blockchain::account_record> result = get_client()->blockchain_list_recently_registered_accounts();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_list_assets_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  std::string first_symbol = (parameters.size() <= 0) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[0].as<std::string>();
  uint32_t limit = (parameters.size() <= 1) ?
    (fc::json::from_string("20").as<uint32_t>()) :
    parameters[1].as<uint32_t>();

  std::vector<fbtc::blockchain::asset_record> result = get_client()->blockchain_list_assets(first_symbol, limit);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_list_assets_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  std::string first_symbol = parameters.contains("first_symbol") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["first_symbol"].as<std::string>();
  uint32_t limit = parameters.contains("limit") ? 
    (fc::json::from_string("20").as<uint32_t>()) :
    parameters["limit"].as<uint32_t>();

  std::vector<fbtc::blockchain::asset_record> result = get_client()->blockchain_list_assets(first_symbol, limit);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_list_feed_prices_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites


  std::map<std::string, std::string> result = get_client()->blockchain_list_feed_prices();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_list_feed_prices_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites


  std::map<std::string, std::string> result = get_client()->blockchain_list_feed_prices();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_get_account_wall_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  std::string account_name = (parameters.size() <= 0) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[0].as<std::string>();

  std::vector<fbtc::blockchain::burn_record> result = get_client()->blockchain_get_account_wall(account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_get_account_wall_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  std::string account_name = parameters.contains("account_name") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["account_name"].as<std::string>();

  std::vector<fbtc::blockchain::burn_record> result = get_client()->blockchain_get_account_wall(account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_list_pending_transactions_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites


  std::vector<fbtc::blockchain::signed_transaction> result = get_client()->blockchain_list_pending_transactions();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_list_pending_transactions_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites


  std::vector<fbtc::blockchain::signed_transaction> result = get_client()->blockchain_list_pending_transactions();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_get_pending_transactions_count_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites


  int32_t result = get_client()->blockchain_get_pending_transactions_count();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_get_pending_transactions_count_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites


  int32_t result = get_client()->blockchain_get_pending_transactions_count();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_get_transaction_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (transaction_id_prefix)");
  std::string transaction_id_prefix = parameters[0].as<std::string>();
  bool exact = (parameters.size() <= 1) ?
    (fc::json::from_string("false").as<bool>()) :
    parameters[1].as<bool>();

  std::pair<fbtc::blockchain::transaction_id_type, fbtc::blockchain::transaction_record> result = get_client()->blockchain_get_transaction(transaction_id_prefix, exact);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_get_transaction_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("transaction_id_prefix"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'transaction_id_prefix'");
  std::string transaction_id_prefix = parameters["transaction_id_prefix"].as<std::string>();
  bool exact = parameters.contains("exact") ? 
    (fc::json::from_string("false").as<bool>()) :
    parameters["exact"].as<bool>();

  std::pair<fbtc::blockchain::transaction_id_type, fbtc::blockchain::transaction_record> result = get_client()->blockchain_get_transaction(transaction_id_prefix, exact);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_get_block_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (block)");
  std::string block = parameters[0].as<std::string>();

  fc::optional<fbtc::blockchain::block_record> result = get_client()->blockchain_get_block(block);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_get_block_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("block"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'block'");
  std::string block = parameters["block"].as<std::string>();

  fc::optional<fbtc::blockchain::block_record> result = get_client()->blockchain_get_block(block);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_get_block_transactions_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (block)");
  std::string block = parameters[0].as<std::string>();

  std::map<fbtc::blockchain::transaction_id_type, fbtc::blockchain::transaction_record> result = get_client()->blockchain_get_block_transactions(block);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_get_block_transactions_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("block"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'block'");
  std::string block = parameters["block"].as<std::string>();

  std::map<fbtc::blockchain::transaction_id_type, fbtc::blockchain::transaction_record> result = get_client()->blockchain_get_block_transactions(block);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_get_account_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (account)");
  std::string account = parameters[0].as<std::string>();

  fc::optional<fbtc::blockchain::account_record> result = get_client()->blockchain_get_account(account);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_get_account_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("account"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'account'");
  std::string account = parameters["account"].as<std::string>();

  fc::optional<fbtc::blockchain::account_record> result = get_client()->blockchain_get_account(account);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_get_slate_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (slate)");
  std::string slate = parameters[0].as<std::string>();

  std::map<fbtc::blockchain::account_id_type, std::string> result = get_client()->blockchain_get_slate(slate);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_get_slate_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("slate"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'slate'");
  std::string slate = parameters["slate"].as<std::string>();

  std::map<fbtc::blockchain::account_id_type, std::string> result = get_client()->blockchain_get_slate(slate);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_get_balance_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (balance_id)");
  fbtc::blockchain::address balance_id = parameters[0].as<fbtc::blockchain::address>();

  fbtc::blockchain::balance_record result = get_client()->blockchain_get_balance(balance_id);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_get_balance_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("balance_id"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'balance_id'");
  fbtc::blockchain::address balance_id = parameters["balance_id"].as<fbtc::blockchain::address>();

  fbtc::blockchain::balance_record result = get_client()->blockchain_get_balance(balance_id);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_list_balances_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  std::string asset = (parameters.size() <= 0) ?
    (fc::json::from_string("\"0\"").as<std::string>()) :
    parameters[0].as<std::string>();
  uint32_t limit = (parameters.size() <= 1) ?
    (fc::json::from_string("20").as<uint32_t>()) :
    parameters[1].as<uint32_t>();

  std::unordered_map<fbtc::blockchain::balance_id_type, fbtc::blockchain::balance_record> result = get_client()->blockchain_list_balances(asset, limit);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_list_balances_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  std::string asset = parameters.contains("asset") ? 
    (fc::json::from_string("\"0\"").as<std::string>()) :
    parameters["asset"].as<std::string>();
  uint32_t limit = parameters.contains("limit") ? 
    (fc::json::from_string("20").as<uint32_t>()) :
    parameters["limit"].as<uint32_t>();

  std::unordered_map<fbtc::blockchain::balance_id_type, fbtc::blockchain::balance_record> result = get_client()->blockchain_list_balances(asset, limit);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_list_address_balances_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (addr)");
  std::string addr = parameters[0].as<std::string>();
  fc::time_point chanced_since = (parameters.size() <= 1) ?
    (fc::json::from_string("\"1970-1-1T00:00:01\"").as<fc::time_point>()) :
    parameters[1].as<fc::time_point>();

  std::unordered_map<fbtc::blockchain::balance_id_type, fbtc::blockchain::balance_record> result = get_client()->blockchain_list_address_balances(addr, chanced_since);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_list_address_balances_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("addr"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'addr'");
  std::string addr = parameters["addr"].as<std::string>();
  fc::time_point chanced_since = parameters.contains("chanced_since") ? 
    (fc::json::from_string("\"1970-1-1T00:00:01\"").as<fc::time_point>()) :
    parameters["chanced_since"].as<fc::time_point>();

  std::unordered_map<fbtc::blockchain::balance_id_type, fbtc::blockchain::balance_record> result = get_client()->blockchain_list_address_balances(addr, chanced_since);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_list_address_transactions_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (addr)");
  std::string addr = parameters[0].as<std::string>();
  uint32_t filter_before = (parameters.size() <= 1) ?
    (fc::json::from_string("\"0\"").as<uint32_t>()) :
    parameters[1].as<uint32_t>();

  fc::variant_object result = get_client()->blockchain_list_address_transactions(addr, filter_before);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_list_address_transactions_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("addr"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'addr'");
  std::string addr = parameters["addr"].as<std::string>();
  uint32_t filter_before = parameters.contains("filter_before") ? 
    (fc::json::from_string("\"0\"").as<uint32_t>()) :
    parameters["filter_before"].as<uint32_t>();

  fc::variant_object result = get_client()->blockchain_list_address_transactions(addr, filter_before);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_get_account_public_balance_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (account_name)");
  std::string account_name = parameters[0].as<std::string>();

  std::map<fbtc::blockchain::asset_id_type, fbtc::blockchain::share_type> result = get_client()->blockchain_get_account_public_balance(account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_get_account_public_balance_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("account_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'account_name'");
  std::string account_name = parameters["account_name"].as<std::string>();

  std::map<fbtc::blockchain::asset_id_type, fbtc::blockchain::share_type> result = get_client()->blockchain_get_account_public_balance(account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_median_feed_price_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (symbol)");
  std::string symbol = parameters[0].as<std::string>();

  std::string result = get_client()->blockchain_median_feed_price(symbol);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_median_feed_price_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'symbol'");
  std::string symbol = parameters["symbol"].as<std::string>();

  std::string result = get_client()->blockchain_median_feed_price(symbol);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_list_key_balances_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (key)");
  fbtc::blockchain::public_key_type key = parameters[0].as<fbtc::blockchain::public_key_type>();

  std::unordered_map<fbtc::blockchain::balance_id_type, fbtc::blockchain::balance_record> result = get_client()->blockchain_list_key_balances(key);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_list_key_balances_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("key"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'key'");
  fbtc::blockchain::public_key_type key = parameters["key"].as<fbtc::blockchain::public_key_type>();

  std::unordered_map<fbtc::blockchain::balance_id_type, fbtc::blockchain::balance_record> result = get_client()->blockchain_list_key_balances(key);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_get_asset_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (asset)");
  std::string asset = parameters[0].as<std::string>();

  fc::optional<fbtc::blockchain::asset_record> result = get_client()->blockchain_get_asset(asset);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_get_asset_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("asset"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'asset'");
  std::string asset = parameters["asset"].as<std::string>();

  fc::optional<fbtc::blockchain::asset_record> result = get_client()->blockchain_get_asset(asset);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_get_feeds_for_asset_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (asset)");
  std::string asset = parameters[0].as<std::string>();

  std::vector<fbtc::blockchain::feed_entry> result = get_client()->blockchain_get_feeds_for_asset(asset);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_get_feeds_for_asset_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("asset"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'asset'");
  std::string asset = parameters["asset"].as<std::string>();

  std::vector<fbtc::blockchain::feed_entry> result = get_client()->blockchain_get_feeds_for_asset(asset);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_get_feeds_from_delegate_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (delegate_name)");
  std::string delegate_name = parameters[0].as<std::string>();

  std::vector<fbtc::blockchain::feed_entry> result = get_client()->blockchain_get_feeds_from_delegate(delegate_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_get_feeds_from_delegate_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("delegate_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'delegate_name'");
  std::string delegate_name = parameters["delegate_name"].as<std::string>();

  std::vector<fbtc::blockchain::feed_entry> result = get_client()->blockchain_get_feeds_from_delegate(delegate_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_market_list_bids_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (quote_symbol)");
  std::string quote_symbol = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (base_symbol)");
  std::string base_symbol = parameters[1].as<std::string>();
  uint32_t limit = (parameters.size() <= 2) ?
    (fc::json::from_string("\"-1\"").as<uint32_t>()) :
    parameters[2].as<uint32_t>();

  std::vector<fbtc::blockchain::market_order> result = get_client()->blockchain_market_list_bids(quote_symbol, base_symbol, limit);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_market_list_bids_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("quote_symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'quote_symbol'");
  std::string quote_symbol = parameters["quote_symbol"].as<std::string>();
  if (!parameters.contains("base_symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'base_symbol'");
  std::string base_symbol = parameters["base_symbol"].as<std::string>();
  uint32_t limit = parameters.contains("limit") ? 
    (fc::json::from_string("\"-1\"").as<uint32_t>()) :
    parameters["limit"].as<uint32_t>();

  std::vector<fbtc::blockchain::market_order> result = get_client()->blockchain_market_list_bids(quote_symbol, base_symbol, limit);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_market_list_asks_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (quote_symbol)");
  std::string quote_symbol = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (base_symbol)");
  std::string base_symbol = parameters[1].as<std::string>();
  uint32_t limit = (parameters.size() <= 2) ?
    (fc::json::from_string("\"-1\"").as<uint32_t>()) :
    parameters[2].as<uint32_t>();

  std::vector<fbtc::blockchain::market_order> result = get_client()->blockchain_market_list_asks(quote_symbol, base_symbol, limit);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_market_list_asks_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("quote_symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'quote_symbol'");
  std::string quote_symbol = parameters["quote_symbol"].as<std::string>();
  if (!parameters.contains("base_symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'base_symbol'");
  std::string base_symbol = parameters["base_symbol"].as<std::string>();
  uint32_t limit = parameters.contains("limit") ? 
    (fc::json::from_string("\"-1\"").as<uint32_t>()) :
    parameters["limit"].as<uint32_t>();

  std::vector<fbtc::blockchain::market_order> result = get_client()->blockchain_market_list_asks(quote_symbol, base_symbol, limit);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_market_list_shorts_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (quote_symbol)");
  std::string quote_symbol = parameters[0].as<std::string>();
  uint32_t limit = (parameters.size() <= 1) ?
    (fc::json::from_string("\"-1\"").as<uint32_t>()) :
    parameters[1].as<uint32_t>();

  std::vector<fbtc::blockchain::market_order> result = get_client()->blockchain_market_list_shorts(quote_symbol, limit);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_market_list_shorts_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("quote_symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'quote_symbol'");
  std::string quote_symbol = parameters["quote_symbol"].as<std::string>();
  uint32_t limit = parameters.contains("limit") ? 
    (fc::json::from_string("\"-1\"").as<uint32_t>()) :
    parameters["limit"].as<uint32_t>();

  std::vector<fbtc::blockchain::market_order> result = get_client()->blockchain_market_list_shorts(quote_symbol, limit);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_market_list_covers_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (quote_symbol)");
  std::string quote_symbol = parameters[0].as<std::string>();
  std::string base_symbol = (parameters.size() <= 1) ?
    (fc::json::from_string("\"XTS\"").as<std::string>()) :
    parameters[1].as<std::string>();
  uint32_t limit = (parameters.size() <= 2) ?
    (fc::json::from_string("\"-1\"").as<uint32_t>()) :
    parameters[2].as<uint32_t>();

  std::vector<fbtc::blockchain::market_order> result = get_client()->blockchain_market_list_covers(quote_symbol, base_symbol, limit);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_market_list_covers_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("quote_symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'quote_symbol'");
  std::string quote_symbol = parameters["quote_symbol"].as<std::string>();
  std::string base_symbol = parameters.contains("base_symbol") ? 
    (fc::json::from_string("\"XTS\"").as<std::string>()) :
    parameters["base_symbol"].as<std::string>();
  uint32_t limit = parameters.contains("limit") ? 
    (fc::json::from_string("\"-1\"").as<uint32_t>()) :
    parameters["limit"].as<uint32_t>();

  std::vector<fbtc::blockchain::market_order> result = get_client()->blockchain_market_list_covers(quote_symbol, base_symbol, limit);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_market_get_asset_collateral_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (symbol)");
  std::string symbol = parameters[0].as<std::string>();

  fbtc::blockchain::share_type result = get_client()->blockchain_market_get_asset_collateral(symbol);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_market_get_asset_collateral_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'symbol'");
  std::string symbol = parameters["symbol"].as<std::string>();

  fbtc::blockchain::share_type result = get_client()->blockchain_market_get_asset_collateral(symbol);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_market_order_book_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (quote_symbol)");
  std::string quote_symbol = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (base_symbol)");
  std::string base_symbol = parameters[1].as<std::string>();
  uint32_t limit = (parameters.size() <= 2) ?
    (fc::json::from_string("\"10\"").as<uint32_t>()) :
    parameters[2].as<uint32_t>();

  std::pair<std::vector<fbtc::blockchain::market_order>,std::vector<fbtc::blockchain::market_order>> result = get_client()->blockchain_market_order_book(quote_symbol, base_symbol, limit);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_market_order_book_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("quote_symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'quote_symbol'");
  std::string quote_symbol = parameters["quote_symbol"].as<std::string>();
  if (!parameters.contains("base_symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'base_symbol'");
  std::string base_symbol = parameters["base_symbol"].as<std::string>();
  uint32_t limit = parameters.contains("limit") ? 
    (fc::json::from_string("\"10\"").as<uint32_t>()) :
    parameters["limit"].as<uint32_t>();

  std::pair<std::vector<fbtc::blockchain::market_order>,std::vector<fbtc::blockchain::market_order>> result = get_client()->blockchain_market_order_book(quote_symbol, base_symbol, limit);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_get_market_order_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (order_id)");
  std::string order_id = parameters[0].as<std::string>();

  fbtc::blockchain::market_order result = get_client()->blockchain_get_market_order(order_id);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_get_market_order_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("order_id"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'order_id'");
  std::string order_id = parameters["order_id"].as<std::string>();

  fbtc::blockchain::market_order result = get_client()->blockchain_get_market_order(order_id);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_list_address_orders_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (base_symbol)");
  std::string base_symbol = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (quote_symbol)");
  std::string quote_symbol = parameters[1].as<std::string>();
  if (parameters.size() <= 2)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 3 (account_address)");
  std::string account_address = parameters[2].as<std::string>();
  uint32_t limit = (parameters.size() <= 3) ?
    (fc::json::from_string("\"10\"").as<uint32_t>()) :
    parameters[3].as<uint32_t>();

  std::map<fbtc::blockchain::order_id_type, fbtc::blockchain::market_order> result = get_client()->blockchain_list_address_orders(base_symbol, quote_symbol, account_address, limit);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_list_address_orders_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("base_symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'base_symbol'");
  std::string base_symbol = parameters["base_symbol"].as<std::string>();
  if (!parameters.contains("quote_symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'quote_symbol'");
  std::string quote_symbol = parameters["quote_symbol"].as<std::string>();
  if (!parameters.contains("account_address"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'account_address'");
  std::string account_address = parameters["account_address"].as<std::string>();
  uint32_t limit = parameters.contains("limit") ? 
    (fc::json::from_string("\"10\"").as<uint32_t>()) :
    parameters["limit"].as<uint32_t>();

  std::map<fbtc::blockchain::order_id_type, fbtc::blockchain::market_order> result = get_client()->blockchain_list_address_orders(base_symbol, quote_symbol, account_address, limit);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_market_order_history_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (quote_symbol)");
  std::string quote_symbol = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (base_symbol)");
  std::string base_symbol = parameters[1].as<std::string>();
  uint32_t skip_count = (parameters.size() <= 2) ?
    (fc::json::from_string("\"0\"").as<uint32_t>()) :
    parameters[2].as<uint32_t>();
  uint32_t limit = (parameters.size() <= 3) ?
    (fc::json::from_string("\"20\"").as<uint32_t>()) :
    parameters[3].as<uint32_t>();
  std::string owner = (parameters.size() <= 4) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[4].as<std::string>();

  std::vector<fbtc::blockchain::order_history_record> result = get_client()->blockchain_market_order_history(quote_symbol, base_symbol, skip_count, limit, owner);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_market_order_history_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("quote_symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'quote_symbol'");
  std::string quote_symbol = parameters["quote_symbol"].as<std::string>();
  if (!parameters.contains("base_symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'base_symbol'");
  std::string base_symbol = parameters["base_symbol"].as<std::string>();
  uint32_t skip_count = parameters.contains("skip_count") ? 
    (fc::json::from_string("\"0\"").as<uint32_t>()) :
    parameters["skip_count"].as<uint32_t>();
  uint32_t limit = parameters.contains("limit") ? 
    (fc::json::from_string("\"20\"").as<uint32_t>()) :
    parameters["limit"].as<uint32_t>();
  std::string owner = parameters.contains("owner") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["owner"].as<std::string>();

  std::vector<fbtc::blockchain::order_history_record> result = get_client()->blockchain_market_order_history(quote_symbol, base_symbol, skip_count, limit, owner);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_market_price_history_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (quote_symbol)");
  std::string quote_symbol = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (base_symbol)");
  std::string base_symbol = parameters[1].as<std::string>();
  if (parameters.size() <= 2)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 3 (start_time)");
  fc::time_point start_time = parameters[2].as<fc::time_point>();
  if (parameters.size() <= 3)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 4 (duration)");
  fc::microseconds duration = fbtc::api::variant_to_time_interval_in_seconds(parameters[3]);
  fbtc::blockchain::market_history_key::time_granularity_enum granularity = (parameters.size() <= 4) ?
    (fc::json::from_string("\"each_block\"").as<fbtc::blockchain::market_history_key::time_granularity_enum>()) :
    parameters[4].as<fbtc::blockchain::market_history_key::time_granularity_enum>();

  fbtc::blockchain::market_history_points result = get_client()->blockchain_market_price_history(quote_symbol, base_symbol, start_time, duration, granularity);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_market_price_history_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("quote_symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'quote_symbol'");
  std::string quote_symbol = parameters["quote_symbol"].as<std::string>();
  if (!parameters.contains("base_symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'base_symbol'");
  std::string base_symbol = parameters["base_symbol"].as<std::string>();
  if (!parameters.contains("start_time"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'start_time'");
  fc::time_point start_time = parameters["start_time"].as<fc::time_point>();
  if (!parameters.contains("duration"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'duration'");
  fc::microseconds duration = fbtc::api::variant_to_time_interval_in_seconds(parameters["duration"]);
  fbtc::blockchain::market_history_key::time_granularity_enum granularity = parameters.contains("granularity") ? 
    (fc::json::from_string("\"each_block\"").as<fbtc::blockchain::market_history_key::time_granularity_enum>()) :
    parameters["granularity"].as<fbtc::blockchain::market_history_key::time_granularity_enum>();

  fbtc::blockchain::market_history_points result = get_client()->blockchain_market_price_history(quote_symbol, base_symbol, start_time, duration, granularity);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_list_active_delegates_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  uint32_t first = (parameters.size() <= 0) ?
    (fc::json::from_string("0").as<uint32_t>()) :
    parameters[0].as<uint32_t>();
  uint32_t count = (parameters.size() <= 1) ?
    (fc::json::from_string("20").as<uint32_t>()) :
    parameters[1].as<uint32_t>();

  std::vector<fbtc::blockchain::account_record> result = get_client()->blockchain_list_active_delegates(first, count);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_list_active_delegates_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  uint32_t first = parameters.contains("first") ? 
    (fc::json::from_string("0").as<uint32_t>()) :
    parameters["first"].as<uint32_t>();
  uint32_t count = parameters.contains("count") ? 
    (fc::json::from_string("20").as<uint32_t>()) :
    parameters["count"].as<uint32_t>();

  std::vector<fbtc::blockchain::account_record> result = get_client()->blockchain_list_active_delegates(first, count);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_list_delegates_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  uint32_t first = (parameters.size() <= 0) ?
    (fc::json::from_string("0").as<uint32_t>()) :
    parameters[0].as<uint32_t>();
  uint32_t count = (parameters.size() <= 1) ?
    (fc::json::from_string("20").as<uint32_t>()) :
    parameters[1].as<uint32_t>();

  std::vector<fbtc::blockchain::account_record> result = get_client()->blockchain_list_delegates(first, count);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_list_delegates_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  uint32_t first = parameters.contains("first") ? 
    (fc::json::from_string("0").as<uint32_t>()) :
    parameters["first"].as<uint32_t>();
  uint32_t count = parameters.contains("count") ? 
    (fc::json::from_string("20").as<uint32_t>()) :
    parameters["count"].as<uint32_t>();

  std::vector<fbtc::blockchain::account_record> result = get_client()->blockchain_list_delegates(first, count);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_list_blocks_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  uint32_t max_block_num = (parameters.size() <= 0) ?
    (fc::json::from_string("-1").as<uint32_t>()) :
    parameters[0].as<uint32_t>();
  uint32_t limit = (parameters.size() <= 1) ?
    (fc::json::from_string("20").as<uint32_t>()) :
    parameters[1].as<uint32_t>();

  std::vector<fbtc::blockchain::block_record> result = get_client()->blockchain_list_blocks(max_block_num, limit);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_list_blocks_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  uint32_t max_block_num = parameters.contains("max_block_num") ? 
    (fc::json::from_string("-1").as<uint32_t>()) :
    parameters["max_block_num"].as<uint32_t>();
  uint32_t limit = parameters.contains("limit") ? 
    (fc::json::from_string("20").as<uint32_t>()) :
    parameters["limit"].as<uint32_t>();

  std::vector<fbtc::blockchain::block_record> result = get_client()->blockchain_list_blocks(max_block_num, limit);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_list_missing_block_delegates_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (block_number)");
  uint32_t block_number = parameters[0].as<uint32_t>();

  std::vector<std::string> result = get_client()->blockchain_list_missing_block_delegates(block_number);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_list_missing_block_delegates_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("block_number"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'block_number'");
  uint32_t block_number = parameters["block_number"].as<uint32_t>();

  std::vector<std::string> result = get_client()->blockchain_list_missing_block_delegates(block_number);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_export_fork_graph_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  uint32_t start_block = (parameters.size() <= 0) ?
    (fc::json::from_string("1").as<uint32_t>()) :
    parameters[0].as<uint32_t>();
  uint32_t end_block = (parameters.size() <= 1) ?
    (fc::json::from_string("-1").as<uint32_t>()) :
    parameters[1].as<uint32_t>();
  std::string filename = (parameters.size() <= 2) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[2].as<std::string>();

  std::string result = get_client()->blockchain_export_fork_graph(start_block, end_block, filename);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_export_fork_graph_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  uint32_t start_block = parameters.contains("start_block") ? 
    (fc::json::from_string("1").as<uint32_t>()) :
    parameters["start_block"].as<uint32_t>();
  uint32_t end_block = parameters.contains("end_block") ? 
    (fc::json::from_string("-1").as<uint32_t>()) :
    parameters["end_block"].as<uint32_t>();
  std::string filename = parameters.contains("filename") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["filename"].as<std::string>();

  std::string result = get_client()->blockchain_export_fork_graph(start_block, end_block, filename);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_list_forks_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites


  std::map<uint32_t, std::vector<fbtc::blockchain::fork_record>> result = get_client()->blockchain_list_forks();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_list_forks_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites


  std::map<uint32_t, std::vector<fbtc::blockchain::fork_record>> result = get_client()->blockchain_list_forks();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_get_delegate_slot_records_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (delegate_name)");
  std::string delegate_name = parameters[0].as<std::string>();
  uint32_t limit = (parameters.size() <= 1) ?
    (fc::json::from_string("\"10\"").as<uint32_t>()) :
    parameters[1].as<uint32_t>();

  std::vector<fbtc::blockchain::slot_record> result = get_client()->blockchain_get_delegate_slot_records(delegate_name, limit);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_get_delegate_slot_records_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("delegate_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'delegate_name'");
  std::string delegate_name = parameters["delegate_name"].as<std::string>();
  uint32_t limit = parameters.contains("limit") ? 
    (fc::json::from_string("\"10\"").as<uint32_t>()) :
    parameters["limit"].as<uint32_t>();

  std::vector<fbtc::blockchain::slot_record> result = get_client()->blockchain_get_delegate_slot_records(delegate_name, limit);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_get_block_signee_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (block)");
  std::string block = parameters[0].as<std::string>();

  std::string result = get_client()->blockchain_get_block_signee(block);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_get_block_signee_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("block"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'block'");
  std::string block = parameters["block"].as<std::string>();

  std::string result = get_client()->blockchain_get_block_signee(block);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_list_markets_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites


  std::vector<fbtc::blockchain::string_status_record> result = get_client()->blockchain_list_markets();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_list_markets_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites


  std::vector<fbtc::blockchain::string_status_record> result = get_client()->blockchain_list_markets();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_list_market_transactions_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (block_number)");
  uint32_t block_number = parameters[0].as<uint32_t>();

  std::vector<fbtc::blockchain::market_transaction> result = get_client()->blockchain_list_market_transactions(block_number);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_list_market_transactions_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("block_number"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'block_number'");
  uint32_t block_number = parameters["block_number"].as<uint32_t>();

  std::vector<fbtc::blockchain::market_transaction> result = get_client()->blockchain_list_market_transactions(block_number);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_market_status_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (quote_symbol)");
  std::string quote_symbol = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (base_symbol)");
  std::string base_symbol = parameters[1].as<std::string>();

  fbtc::blockchain::string_status_record result = get_client()->blockchain_market_status(quote_symbol, base_symbol);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_market_status_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("quote_symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'quote_symbol'");
  std::string quote_symbol = parameters["quote_symbol"].as<std::string>();
  if (!parameters.contains("base_symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'base_symbol'");
  std::string base_symbol = parameters["base_symbol"].as<std::string>();

  fbtc::blockchain::string_status_record result = get_client()->blockchain_market_status(quote_symbol, base_symbol);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_unclaimed_genesis_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites


  fbtc::blockchain::asset result = get_client()->blockchain_unclaimed_genesis();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_unclaimed_genesis_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites


  fbtc::blockchain::asset result = get_client()->blockchain_unclaimed_genesis();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_verify_signature_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (signer)");
  std::string signer = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (hash)");
  fc::sha256 hash = parameters[1].as<fc::sha256>();
  if (parameters.size() <= 2)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 3 (signature)");
  fc::ecc::compact_signature signature = parameters[2].as<fc::ecc::compact_signature>();

  bool result = get_client()->blockchain_verify_signature(signer, hash, signature);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_verify_signature_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("signer"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'signer'");
  std::string signer = parameters["signer"].as<std::string>();
  if (!parameters.contains("hash"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'hash'");
  fc::sha256 hash = parameters["hash"].as<fc::sha256>();
  if (!parameters.contains("signature"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'signature'");
  fc::ecc::compact_signature signature = parameters["signature"].as<fc::ecc::compact_signature>();

  bool result = get_client()->blockchain_verify_signature(signer, hash, signature);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::blockchain_broadcast_transaction_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (trx)");
  fbtc::blockchain::signed_transaction trx = parameters[0].as<fbtc::blockchain::signed_transaction>();

  get_client()->blockchain_broadcast_transaction(trx);
  return fc::variant();
}

fc::variant common_api_rpc_server::blockchain_broadcast_transaction_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("trx"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'trx'");
  fbtc::blockchain::signed_transaction trx = parameters["trx"].as<fbtc::blockchain::signed_transaction>();

  get_client()->blockchain_broadcast_transaction(trx);
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_get_info_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites


  fc::variant_object result = get_client()->wallet_get_info();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_get_info_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites


  fc::variant_object result = get_client()->wallet_get_info();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_open_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (wallet_name)");
  std::string wallet_name = parameters[0].as<std::string>();

  get_client()->wallet_open(wallet_name);
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_open_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (!parameters.contains("wallet_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'wallet_name'");
  std::string wallet_name = parameters["wallet_name"].as<std::string>();

  get_client()->wallet_open(wallet_name);
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_get_account_public_address_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (account_name)");
  std::string account_name = parameters[0].as<std::string>();

  std::string result = get_client()->wallet_get_account_public_address(account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_get_account_public_address_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (!parameters.contains("account_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'account_name'");
  std::string account_name = parameters["account_name"].as<std::string>();

  std::string result = get_client()->wallet_get_account_public_address(account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_list_my_addresses_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites


  std::vector<fbtc::wallet::account_address_data> result = get_client()->wallet_list_my_addresses();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_list_my_addresses_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites


  std::vector<fbtc::wallet::account_address_data> result = get_client()->wallet_list_my_addresses();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_create_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (wallet_name)");
  std::string wallet_name = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (new_passphrase)");
  std::string new_passphrase = parameters[1].as<std::string>();
  std::string brain_key = (parameters.size() <= 2) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[2].as<std::string>();
  std::string new_passphrase_verify = (parameters.size() <= 3) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[3].as<std::string>();

  get_client()->wallet_create(wallet_name, new_passphrase, brain_key, new_passphrase_verify);
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_create_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (!parameters.contains("wallet_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'wallet_name'");
  std::string wallet_name = parameters["wallet_name"].as<std::string>();
  if (!parameters.contains("new_passphrase"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'new_passphrase'");
  std::string new_passphrase = parameters["new_passphrase"].as<std::string>();
  std::string brain_key = parameters.contains("brain_key") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["brain_key"].as<std::string>();
  std::string new_passphrase_verify = parameters.contains("new_passphrase_verify") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["new_passphrase_verify"].as<std::string>();

  get_client()->wallet_create(wallet_name, new_passphrase, brain_key, new_passphrase_verify);
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_import_private_key_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (wif_key)");
  std::string wif_key = parameters[0].as<std::string>();
  std::string account_name = (parameters.size() <= 1) ?
    (fc::json::from_string("null").as<std::string>()) :
    parameters[1].as<std::string>();
  bool create_new_account = (parameters.size() <= 2) ?
    (fc::json::from_string("false").as<bool>()) :
    parameters[2].as<bool>();
  bool rescan = (parameters.size() <= 3) ?
    (fc::json::from_string("false").as<bool>()) :
    parameters[3].as<bool>();

  std::string result = get_client()->wallet_import_private_key(wif_key, account_name, create_new_account, rescan);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_import_private_key_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("wif_key"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'wif_key'");
  std::string wif_key = parameters["wif_key"].as<std::string>();
  std::string account_name = parameters.contains("account_name") ? 
    (fc::json::from_string("null").as<std::string>()) :
    parameters["account_name"].as<std::string>();
  bool create_new_account = parameters.contains("create_new_account") ? 
    (fc::json::from_string("false").as<bool>()) :
    parameters["create_new_account"].as<bool>();
  bool rescan = parameters.contains("rescan") ? 
    (fc::json::from_string("false").as<bool>()) :
    parameters["rescan"].as<bool>();

  std::string result = get_client()->wallet_import_private_key(wif_key, account_name, create_new_account, rescan);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_import_bitcoin_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (wallet_filename)");
  fc::path wallet_filename = parameters[0].as<fc::path>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (passphrase)");
  std::string passphrase = parameters[1].as<std::string>();
  if (parameters.size() <= 2)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 3 (account_name)");
  std::string account_name = parameters[2].as<std::string>();

  uint32_t result = get_client()->wallet_import_bitcoin(wallet_filename, passphrase, account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_import_bitcoin_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("wallet_filename"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'wallet_filename'");
  fc::path wallet_filename = parameters["wallet_filename"].as<fc::path>();
  if (!parameters.contains("passphrase"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'passphrase'");
  std::string passphrase = parameters["passphrase"].as<std::string>();
  if (!parameters.contains("account_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'account_name'");
  std::string account_name = parameters["account_name"].as<std::string>();

  uint32_t result = get_client()->wallet_import_bitcoin(wallet_filename, passphrase, account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_import_electrum_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (wallet_filename)");
  fc::path wallet_filename = parameters[0].as<fc::path>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (passphrase)");
  std::string passphrase = parameters[1].as<std::string>();
  if (parameters.size() <= 2)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 3 (account_name)");
  std::string account_name = parameters[2].as<std::string>();

  uint32_t result = get_client()->wallet_import_electrum(wallet_filename, passphrase, account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_import_electrum_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("wallet_filename"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'wallet_filename'");
  fc::path wallet_filename = parameters["wallet_filename"].as<fc::path>();
  if (!parameters.contains("passphrase"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'passphrase'");
  std::string passphrase = parameters["passphrase"].as<std::string>();
  if (!parameters.contains("account_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'account_name'");
  std::string account_name = parameters["account_name"].as<std::string>();

  uint32_t result = get_client()->wallet_import_electrum(wallet_filename, passphrase, account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_import_keyhotee_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (firstname)");
  std::string firstname = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (middlename)");
  std::string middlename = parameters[1].as<std::string>();
  if (parameters.size() <= 2)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 3 (lastname)");
  std::string lastname = parameters[2].as<std::string>();
  if (parameters.size() <= 3)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 4 (brainkey)");
  std::string brainkey = parameters[3].as<std::string>();
  if (parameters.size() <= 4)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 5 (keyhoteeid)");
  std::string keyhoteeid = parameters[4].as<std::string>();

  get_client()->wallet_import_keyhotee(firstname, middlename, lastname, brainkey, keyhoteeid);
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_import_keyhotee_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("firstname"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'firstname'");
  std::string firstname = parameters["firstname"].as<std::string>();
  if (!parameters.contains("middlename"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'middlename'");
  std::string middlename = parameters["middlename"].as<std::string>();
  if (!parameters.contains("lastname"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'lastname'");
  std::string lastname = parameters["lastname"].as<std::string>();
  if (!parameters.contains("brainkey"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'brainkey'");
  std::string brainkey = parameters["brainkey"].as<std::string>();
  if (!parameters.contains("keyhoteeid"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'keyhoteeid'");
  std::string keyhoteeid = parameters["keyhoteeid"].as<std::string>();

  get_client()->wallet_import_keyhotee(firstname, middlename, lastname, brainkey, keyhoteeid);
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_import_keys_from_json_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (json_filename)");
  fc::path json_filename = parameters[0].as<fc::path>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (imported_wallet_passphrase)");
  std::string imported_wallet_passphrase = parameters[1].as<std::string>();
  if (parameters.size() <= 2)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 3 (account)");
  std::string account = parameters[2].as<std::string>();

  uint32_t result = get_client()->wallet_import_keys_from_json(json_filename, imported_wallet_passphrase, account);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_import_keys_from_json_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (!parameters.contains("json_filename"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'json_filename'");
  fc::path json_filename = parameters["json_filename"].as<fc::path>();
  if (!parameters.contains("imported_wallet_passphrase"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'imported_wallet_passphrase'");
  std::string imported_wallet_passphrase = parameters["imported_wallet_passphrase"].as<std::string>();
  if (!parameters.contains("account"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'account'");
  std::string account = parameters["account"].as<std::string>();

  uint32_t result = get_client()->wallet_import_keys_from_json(json_filename, imported_wallet_passphrase, account);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_close_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites


  get_client()->wallet_close();
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_close_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites


  get_client()->wallet_close();
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_backup_create_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (json_filename)");
  fc::path json_filename = parameters[0].as<fc::path>();

  get_client()->wallet_backup_create(json_filename);
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_backup_create_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (!parameters.contains("json_filename"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'json_filename'");
  fc::path json_filename = parameters["json_filename"].as<fc::path>();

  get_client()->wallet_backup_create(json_filename);
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_backup_restore_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (json_filename)");
  fc::path json_filename = parameters[0].as<fc::path>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (wallet_name)");
  std::string wallet_name = parameters[1].as<std::string>();
  if (parameters.size() <= 2)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 3 (imported_wallet_passphrase)");
  std::string imported_wallet_passphrase = parameters[2].as<std::string>();

  get_client()->wallet_backup_restore(json_filename, wallet_name, imported_wallet_passphrase);
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_backup_restore_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (!parameters.contains("json_filename"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'json_filename'");
  fc::path json_filename = parameters["json_filename"].as<fc::path>();
  if (!parameters.contains("wallet_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'wallet_name'");
  std::string wallet_name = parameters["wallet_name"].as<std::string>();
  if (!parameters.contains("imported_wallet_passphrase"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'imported_wallet_passphrase'");
  std::string imported_wallet_passphrase = parameters["imported_wallet_passphrase"].as<std::string>();

  get_client()->wallet_backup_restore(json_filename, wallet_name, imported_wallet_passphrase);
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_export_keys_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (json_filename)");
  fc::path json_filename = parameters[0].as<fc::path>();

  get_client()->wallet_export_keys(json_filename);
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_export_keys_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (!parameters.contains("json_filename"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'json_filename'");
  fc::path json_filename = parameters["json_filename"].as<fc::path>();

  get_client()->wallet_export_keys(json_filename);
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_set_automatic_backups_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (enabled)");
  bool enabled = parameters[0].as<bool>();

  bool result = get_client()->wallet_set_automatic_backups(enabled);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_set_automatic_backups_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (!parameters.contains("enabled"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'enabled'");
  bool enabled = parameters["enabled"].as<bool>();

  bool result = get_client()->wallet_set_automatic_backups(enabled);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_set_transaction_expiration_time_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (seconds)");
  uint32_t seconds = parameters[0].as<uint32_t>();

  uint32_t result = get_client()->wallet_set_transaction_expiration_time(seconds);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_set_transaction_expiration_time_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (!parameters.contains("seconds"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'seconds'");
  uint32_t seconds = parameters["seconds"].as<uint32_t>();

  uint32_t result = get_client()->wallet_set_transaction_expiration_time(seconds);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_account_transaction_history_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  std::string account_name = (parameters.size() <= 0) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[0].as<std::string>();
  std::string asset_symbol = (parameters.size() <= 1) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[1].as<std::string>();
  int32_t limit = (parameters.size() <= 2) ?
    (fc::json::from_string("0").as<int32_t>()) :
    parameters[2].as<int32_t>();
  uint32_t start_block_num = (parameters.size() <= 3) ?
    (fc::json::from_string("0").as<uint32_t>()) :
    parameters[3].as<uint32_t>();
  uint32_t end_block_num = (parameters.size() <= 4) ?
    (fc::json::from_string("-1").as<uint32_t>()) :
    parameters[4].as<uint32_t>();

  std::vector<fbtc::wallet::pretty_transaction> result = get_client()->wallet_account_transaction_history(account_name, asset_symbol, limit, start_block_num, end_block_num);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_account_transaction_history_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  std::string account_name = parameters.contains("account_name") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["account_name"].as<std::string>();
  std::string asset_symbol = parameters.contains("asset_symbol") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["asset_symbol"].as<std::string>();
  int32_t limit = parameters.contains("limit") ? 
    (fc::json::from_string("0").as<int32_t>()) :
    parameters["limit"].as<int32_t>();
  uint32_t start_block_num = parameters.contains("start_block_num") ? 
    (fc::json::from_string("0").as<uint32_t>()) :
    parameters["start_block_num"].as<uint32_t>();
  uint32_t end_block_num = parameters.contains("end_block_num") ? 
    (fc::json::from_string("-1").as<uint32_t>()) :
    parameters["end_block_num"].as<uint32_t>();

  std::vector<fbtc::wallet::pretty_transaction> result = get_client()->wallet_account_transaction_history(account_name, asset_symbol, limit, start_block_num, end_block_num);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_account_historic_balance_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (time)");
  fc::time_point time = parameters[0].as<fc::time_point>();
  std::string account_name = (parameters.size() <= 1) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[1].as<std::string>();

  fbtc::wallet::account_balance_summary_type result = get_client()->wallet_account_historic_balance(time, account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_account_historic_balance_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (!parameters.contains("time"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'time'");
  fc::time_point time = parameters["time"].as<fc::time_point>();
  std::string account_name = parameters.contains("account_name") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["account_name"].as<std::string>();

  fbtc::wallet::account_balance_summary_type result = get_client()->wallet_account_historic_balance(time, account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_transaction_history_experimental_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  std::string account_name = (parameters.size() <= 0) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[0].as<std::string>();

  std::set<fbtc::wallet::pretty_transaction_experimental> result = get_client()->wallet_transaction_history_experimental(account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_transaction_history_experimental_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  std::string account_name = parameters.contains("account_name") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["account_name"].as<std::string>();

  std::set<fbtc::wallet::pretty_transaction_experimental> result = get_client()->wallet_transaction_history_experimental(account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_remove_transaction_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (transaction_id)");
  std::string transaction_id = parameters[0].as<std::string>();

  get_client()->wallet_remove_transaction(transaction_id);
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_remove_transaction_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("transaction_id"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'transaction_id'");
  std::string transaction_id = parameters["transaction_id"].as<std::string>();

  get_client()->wallet_remove_transaction(transaction_id);
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_get_pending_transaction_errors_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  std::string filename = (parameters.size() <= 0) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[0].as<std::string>();

  std::map<fbtc::blockchain::transaction_id_type, fc::exception> result = get_client()->wallet_get_pending_transaction_errors(filename);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_get_pending_transaction_errors_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  std::string filename = parameters.contains("filename") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["filename"].as<std::string>();

  std::map<fbtc::blockchain::transaction_id_type, fc::exception> result = get_client()->wallet_get_pending_transaction_errors(filename);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_lock_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites


  get_client()->wallet_lock();
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_lock_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites


  get_client()->wallet_lock();
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_unlock_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (timeout)");
  uint32_t timeout = parameters[0].as<uint32_t>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (passphrase)");
  std::string passphrase = parameters[1].as<std::string>();

  get_client()->wallet_unlock(timeout, passphrase);
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_unlock_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (!parameters.contains("timeout"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'timeout'");
  uint32_t timeout = parameters["timeout"].as<uint32_t>();
  if (!parameters.contains("passphrase"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'passphrase'");
  std::string passphrase = parameters["passphrase"].as<std::string>();

  get_client()->wallet_unlock(timeout, passphrase);
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_change_passphrase_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (new_passphrase)");
  std::string new_passphrase = parameters[0].as<std::string>();
  std::string new_passphrase_verify = (parameters.size() <= 1) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[1].as<std::string>();

  get_client()->wallet_change_passphrase(new_passphrase, new_passphrase_verify);
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_change_passphrase_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("new_passphrase"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'new_passphrase'");
  std::string new_passphrase = parameters["new_passphrase"].as<std::string>();
  std::string new_passphrase_verify = parameters.contains("new_passphrase_verify") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["new_passphrase_verify"].as<std::string>();

  get_client()->wallet_change_passphrase(new_passphrase, new_passphrase_verify);
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_list_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites


  std::vector<std::string> result = get_client()->wallet_list();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_list_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites


  std::vector<std::string> result = get_client()->wallet_list();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_account_create_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (account_name)");
  std::string account_name = parameters[0].as<std::string>();

  fbtc::blockchain::public_key_type result = get_client()->wallet_account_create(account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_account_create_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("account_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'account_name'");
  std::string account_name = parameters["account_name"].as<std::string>();

  fbtc::blockchain::public_key_type result = get_client()->wallet_account_create(account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_list_contacts_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites


  std::vector<fbtc::wallet::wallet_contact_record> result = get_client()->wallet_list_contacts();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_list_contacts_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites


  std::vector<fbtc::wallet::wallet_contact_record> result = get_client()->wallet_list_contacts();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_get_contact_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (contact)");
  std::string contact = parameters[0].as<std::string>();

  fbtc::wallet::owallet_contact_record result = get_client()->wallet_get_contact(contact);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_get_contact_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (!parameters.contains("contact"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'contact'");
  std::string contact = parameters["contact"].as<std::string>();

  fbtc::wallet::owallet_contact_record result = get_client()->wallet_get_contact(contact);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_add_contact_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (contact)");
  std::string contact = parameters[0].as<std::string>();
  std::string label = (parameters.size() <= 1) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[1].as<std::string>();

  fbtc::wallet::wallet_contact_record result = get_client()->wallet_add_contact(contact, label);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_add_contact_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (!parameters.contains("contact"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'contact'");
  std::string contact = parameters["contact"].as<std::string>();
  std::string label = parameters.contains("label") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["label"].as<std::string>();

  fbtc::wallet::wallet_contact_record result = get_client()->wallet_add_contact(contact, label);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_remove_contact_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (contact)");
  std::string contact = parameters[0].as<std::string>();

  fbtc::wallet::owallet_contact_record result = get_client()->wallet_remove_contact(contact);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_remove_contact_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (!parameters.contains("contact"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'contact'");
  std::string contact = parameters["contact"].as<std::string>();

  fbtc::wallet::owallet_contact_record result = get_client()->wallet_remove_contact(contact);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_list_approvals_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites


  std::vector<fbtc::wallet::wallet_approval_record> result = get_client()->wallet_list_approvals();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_list_approvals_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites


  std::vector<fbtc::wallet::wallet_approval_record> result = get_client()->wallet_list_approvals();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_get_approval_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (approval)");
  std::string approval = parameters[0].as<std::string>();

  fbtc::wallet::owallet_approval_record result = get_client()->wallet_get_approval(approval);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_get_approval_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (!parameters.contains("approval"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'approval'");
  std::string approval = parameters["approval"].as<std::string>();

  fbtc::wallet::owallet_approval_record result = get_client()->wallet_get_approval(approval);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_approve_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (name)");
  std::string name = parameters[0].as<std::string>();
  int8_t approval = (parameters.size() <= 1) ?
    (fc::json::from_string("1").as<int8_t>()) :
    parameters[1].as<int8_t>();

  fbtc::wallet::wallet_approval_record result = get_client()->wallet_approve(name, approval);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_approve_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (!parameters.contains("name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'name'");
  std::string name = parameters["name"].as<std::string>();
  int8_t approval = parameters.contains("approval") ? 
    (fc::json::from_string("1").as<int8_t>()) :
    parameters["approval"].as<int8_t>();

  fbtc::wallet::wallet_approval_record result = get_client()->wallet_approve(name, approval);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_burn_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (amount_to_burn)");
  std::string amount_to_burn = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (asset_symbol)");
  std::string asset_symbol = parameters[1].as<std::string>();
  if (parameters.size() <= 2)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 3 (from_account_name)");
  std::string from_account_name = parameters[2].as<std::string>();
  if (parameters.size() <= 3)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 4 (for_or_against)");
  std::string for_or_against = parameters[3].as<std::string>();
  if (parameters.size() <= 4)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 5 (to_account_name)");
  std::string to_account_name = parameters[4].as<std::string>();
  std::string public_message = (parameters.size() <= 5) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[5].as<std::string>();
  bool anonymous = (parameters.size() <= 6) ?
    (fc::json::from_string("\"false\"").as<bool>()) :
    parameters[6].as<bool>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_burn(amount_to_burn, asset_symbol, from_account_name, for_or_against, to_account_name, public_message, anonymous);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_burn_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("amount_to_burn"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'amount_to_burn'");
  std::string amount_to_burn = parameters["amount_to_burn"].as<std::string>();
  if (!parameters.contains("asset_symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'asset_symbol'");
  std::string asset_symbol = parameters["asset_symbol"].as<std::string>();
  if (!parameters.contains("from_account_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'from_account_name'");
  std::string from_account_name = parameters["from_account_name"].as<std::string>();
  if (!parameters.contains("for_or_against"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'for_or_against'");
  std::string for_or_against = parameters["for_or_against"].as<std::string>();
  if (!parameters.contains("to_account_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'to_account_name'");
  std::string to_account_name = parameters["to_account_name"].as<std::string>();
  std::string public_message = parameters.contains("public_message") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["public_message"].as<std::string>();
  bool anonymous = parameters.contains("anonymous") ? 
    (fc::json::from_string("\"false\"").as<bool>()) :
    parameters["anonymous"].as<bool>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_burn(amount_to_burn, asset_symbol, from_account_name, for_or_against, to_account_name, public_message, anonymous);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_address_create_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (account_name)");
  std::string account_name = parameters[0].as<std::string>();
  std::string label = (parameters.size() <= 1) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[1].as<std::string>();
  int32_t legacy_network_byte = (parameters.size() <= 2) ?
    (fc::json::from_string("-1").as<int32_t>()) :
    parameters[2].as<int32_t>();

  std::string result = get_client()->wallet_address_create(account_name, label, legacy_network_byte);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_address_create_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (!parameters.contains("account_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'account_name'");
  std::string account_name = parameters["account_name"].as<std::string>();
  std::string label = parameters.contains("label") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["label"].as<std::string>();
  int32_t legacy_network_byte = parameters.contains("legacy_network_byte") ? 
    (fc::json::from_string("-1").as<int32_t>()) :
    parameters["legacy_network_byte"].as<int32_t>();

  std::string result = get_client()->wallet_address_create(account_name, label, legacy_network_byte);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_transfer_to_address_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (amount_to_transfer)");
  std::string amount_to_transfer = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (asset_symbol)");
  std::string asset_symbol = parameters[1].as<std::string>();
  if (parameters.size() <= 2)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 3 (from_account_name)");
  std::string from_account_name = parameters[2].as<std::string>();
  if (parameters.size() <= 3)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 4 (to_address)");
  std::string to_address = parameters[3].as<std::string>();
  std::string memo_message = (parameters.size() <= 4) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[4].as<std::string>();
  fbtc::wallet::vote_strategy strategy = (parameters.size() <= 5) ?
    (fc::json::from_string("\"vote_recommended\"").as<fbtc::wallet::vote_strategy>()) :
    parameters[5].as<fbtc::wallet::vote_strategy>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_transfer_to_address(amount_to_transfer, asset_symbol, from_account_name, to_address, memo_message, strategy);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_transfer_to_address_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (!parameters.contains("amount_to_transfer"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'amount_to_transfer'");
  std::string amount_to_transfer = parameters["amount_to_transfer"].as<std::string>();
  if (!parameters.contains("asset_symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'asset_symbol'");
  std::string asset_symbol = parameters["asset_symbol"].as<std::string>();
  if (!parameters.contains("from_account_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'from_account_name'");
  std::string from_account_name = parameters["from_account_name"].as<std::string>();
  if (!parameters.contains("to_address"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'to_address'");
  std::string to_address = parameters["to_address"].as<std::string>();
  std::string memo_message = parameters.contains("memo_message") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["memo_message"].as<std::string>();
  fbtc::wallet::vote_strategy strategy = parameters.contains("strategy") ? 
    (fc::json::from_string("\"vote_recommended\"").as<fbtc::wallet::vote_strategy>()) :
    parameters["strategy"].as<fbtc::wallet::vote_strategy>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_transfer_to_address(amount_to_transfer, asset_symbol, from_account_name, to_address, memo_message, strategy);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_transfer_to_genesis_multisig_address_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (amount_to_transfer)");
  std::string amount_to_transfer = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (asset_symbol)");
  std::string asset_symbol = parameters[1].as<std::string>();
  if (parameters.size() <= 2)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 3 (from_account_name)");
  std::string from_account_name = parameters[2].as<std::string>();
  if (parameters.size() <= 3)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 4 (to_address)");
  std::string to_address = parameters[3].as<std::string>();
  std::string memo_message = (parameters.size() <= 4) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[4].as<std::string>();
  fbtc::wallet::vote_strategy strategy = (parameters.size() <= 5) ?
    (fc::json::from_string("\"vote_recommended\"").as<fbtc::wallet::vote_strategy>()) :
    parameters[5].as<fbtc::wallet::vote_strategy>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_transfer_to_genesis_multisig_address(amount_to_transfer, asset_symbol, from_account_name, to_address, memo_message, strategy);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_transfer_to_genesis_multisig_address_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (!parameters.contains("amount_to_transfer"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'amount_to_transfer'");
  std::string amount_to_transfer = parameters["amount_to_transfer"].as<std::string>();
  if (!parameters.contains("asset_symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'asset_symbol'");
  std::string asset_symbol = parameters["asset_symbol"].as<std::string>();
  if (!parameters.contains("from_account_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'from_account_name'");
  std::string from_account_name = parameters["from_account_name"].as<std::string>();
  if (!parameters.contains("to_address"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'to_address'");
  std::string to_address = parameters["to_address"].as<std::string>();
  std::string memo_message = parameters.contains("memo_message") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["memo_message"].as<std::string>();
  fbtc::wallet::vote_strategy strategy = parameters.contains("strategy") ? 
    (fc::json::from_string("\"vote_recommended\"").as<fbtc::wallet::vote_strategy>()) :
    parameters["strategy"].as<fbtc::wallet::vote_strategy>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_transfer_to_genesis_multisig_address(amount_to_transfer, asset_symbol, from_account_name, to_address, memo_message, strategy);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_transfer_to_address_from_file_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (from_account_name)");
  std::string from_account_name = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (file_path)");
  std::string file_path = parameters[1].as<std::string>();
  std::string memo_message = (parameters.size() <= 2) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[2].as<std::string>();
  fbtc::wallet::vote_strategy strategy = (parameters.size() <= 3) ?
    (fc::json::from_string("\"vote_recommended\"").as<fbtc::wallet::vote_strategy>()) :
    parameters[3].as<fbtc::wallet::vote_strategy>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_transfer_to_address_from_file(from_account_name, file_path, memo_message, strategy);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_transfer_to_address_from_file_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (!parameters.contains("from_account_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'from_account_name'");
  std::string from_account_name = parameters["from_account_name"].as<std::string>();
  if (!parameters.contains("file_path"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'file_path'");
  std::string file_path = parameters["file_path"].as<std::string>();
  std::string memo_message = parameters.contains("memo_message") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["memo_message"].as<std::string>();
  fbtc::wallet::vote_strategy strategy = parameters.contains("strategy") ? 
    (fc::json::from_string("\"vote_recommended\"").as<fbtc::wallet::vote_strategy>()) :
    parameters["strategy"].as<fbtc::wallet::vote_strategy>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_transfer_to_address_from_file(from_account_name, file_path, memo_message, strategy);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_transfer_to_genesis_multisig_address_from_file_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (from_account_name)");
  std::string from_account_name = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (file_path)");
  std::string file_path = parameters[1].as<std::string>();
  std::string memo_message = (parameters.size() <= 2) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[2].as<std::string>();
  fbtc::wallet::vote_strategy strategy = (parameters.size() <= 3) ?
    (fc::json::from_string("\"vote_recommended\"").as<fbtc::wallet::vote_strategy>()) :
    parameters[3].as<fbtc::wallet::vote_strategy>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_transfer_to_genesis_multisig_address_from_file(from_account_name, file_path, memo_message, strategy);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_transfer_to_genesis_multisig_address_from_file_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (!parameters.contains("from_account_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'from_account_name'");
  std::string from_account_name = parameters["from_account_name"].as<std::string>();
  if (!parameters.contains("file_path"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'file_path'");
  std::string file_path = parameters["file_path"].as<std::string>();
  std::string memo_message = parameters.contains("memo_message") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["memo_message"].as<std::string>();
  fbtc::wallet::vote_strategy strategy = parameters.contains("strategy") ? 
    (fc::json::from_string("\"vote_recommended\"").as<fbtc::wallet::vote_strategy>()) :
    parameters["strategy"].as<fbtc::wallet::vote_strategy>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_transfer_to_genesis_multisig_address_from_file(from_account_name, file_path, memo_message, strategy);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_check_passphrase_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (passphrase)");
  std::string passphrase = parameters[0].as<std::string>();

  bool result = get_client()->wallet_check_passphrase(passphrase);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_check_passphrase_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("passphrase"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'passphrase'");
  std::string passphrase = parameters["passphrase"].as<std::string>();

  bool result = get_client()->wallet_check_passphrase(passphrase);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_transfer_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (amount_to_transfer)");
  std::string amount_to_transfer = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (asset_symbol)");
  std::string asset_symbol = parameters[1].as<std::string>();
  if (parameters.size() <= 2)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 3 (from_account_name)");
  std::string from_account_name = parameters[2].as<std::string>();
  if (parameters.size() <= 3)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 4 (recipient)");
  std::string recipient = parameters[3].as<std::string>();
  std::string memo_message = (parameters.size() <= 4) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[4].as<std::string>();
  fbtc::wallet::vote_strategy strategy = (parameters.size() <= 5) ?
    (fc::json::from_string("\"vote_recommended\"").as<fbtc::wallet::vote_strategy>()) :
    parameters[5].as<fbtc::wallet::vote_strategy>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_transfer(amount_to_transfer, asset_symbol, from_account_name, recipient, memo_message, strategy);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_transfer_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("amount_to_transfer"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'amount_to_transfer'");
  std::string amount_to_transfer = parameters["amount_to_transfer"].as<std::string>();
  if (!parameters.contains("asset_symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'asset_symbol'");
  std::string asset_symbol = parameters["asset_symbol"].as<std::string>();
  if (!parameters.contains("from_account_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'from_account_name'");
  std::string from_account_name = parameters["from_account_name"].as<std::string>();
  if (!parameters.contains("recipient"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'recipient'");
  std::string recipient = parameters["recipient"].as<std::string>();
  std::string memo_message = parameters.contains("memo_message") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["memo_message"].as<std::string>();
  fbtc::wallet::vote_strategy strategy = parameters.contains("strategy") ? 
    (fc::json::from_string("\"vote_recommended\"").as<fbtc::wallet::vote_strategy>()) :
    parameters["strategy"].as<fbtc::wallet::vote_strategy>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_transfer(amount_to_transfer, asset_symbol, from_account_name, recipient, memo_message, strategy);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_multisig_get_balance_id_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (symbol)");
  std::string symbol = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (m)");
  uint32_t m = parameters[1].as<uint32_t>();
  if (parameters.size() <= 2)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 3 (addresses)");
  std::vector<fbtc::blockchain::address> addresses = parameters[2].as<std::vector<fbtc::blockchain::address>>();

  fbtc::blockchain::address result = get_client()->wallet_multisig_get_balance_id(symbol, m, addresses);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_multisig_get_balance_id_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (!parameters.contains("symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'symbol'");
  std::string symbol = parameters["symbol"].as<std::string>();
  if (!parameters.contains("m"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'm'");
  uint32_t m = parameters["m"].as<uint32_t>();
  if (!parameters.contains("addresses"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'addresses'");
  std::vector<fbtc::blockchain::address> addresses = parameters["addresses"].as<std::vector<fbtc::blockchain::address>>();

  fbtc::blockchain::address result = get_client()->wallet_multisig_get_balance_id(symbol, m, addresses);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_multisig_deposit_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (amount)");
  std::string amount = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (symbol)");
  std::string symbol = parameters[1].as<std::string>();
  if (parameters.size() <= 2)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 3 (from_name)");
  std::string from_name = parameters[2].as<std::string>();
  if (parameters.size() <= 3)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 4 (m)");
  uint32_t m = parameters[3].as<uint32_t>();
  if (parameters.size() <= 4)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 5 (addresses)");
  std::vector<fbtc::blockchain::address> addresses = parameters[4].as<std::vector<fbtc::blockchain::address>>();
  fbtc::wallet::vote_strategy strategy = (parameters.size() <= 5) ?
    (fc::json::from_string("\"vote_none\"").as<fbtc::wallet::vote_strategy>()) :
    parameters[5].as<fbtc::wallet::vote_strategy>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_multisig_deposit(amount, symbol, from_name, m, addresses, strategy);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_multisig_deposit_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (!parameters.contains("amount"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'amount'");
  std::string amount = parameters["amount"].as<std::string>();
  if (!parameters.contains("symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'symbol'");
  std::string symbol = parameters["symbol"].as<std::string>();
  if (!parameters.contains("from_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'from_name'");
  std::string from_name = parameters["from_name"].as<std::string>();
  if (!parameters.contains("m"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'm'");
  uint32_t m = parameters["m"].as<uint32_t>();
  if (!parameters.contains("addresses"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'addresses'");
  std::vector<fbtc::blockchain::address> addresses = parameters["addresses"].as<std::vector<fbtc::blockchain::address>>();
  fbtc::wallet::vote_strategy strategy = parameters.contains("strategy") ? 
    (fc::json::from_string("\"vote_none\"").as<fbtc::wallet::vote_strategy>()) :
    parameters["strategy"].as<fbtc::wallet::vote_strategy>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_multisig_deposit(amount, symbol, from_name, m, addresses, strategy);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_withdraw_from_address_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (amount)");
  std::string amount = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (symbol)");
  std::string symbol = parameters[1].as<std::string>();
  if (parameters.size() <= 2)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 3 (from_address)");
  fbtc::blockchain::address from_address = parameters[2].as<fbtc::blockchain::address>();
  if (parameters.size() <= 3)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 4 (to)");
  std::string to = parameters[3].as<std::string>();
  fbtc::wallet::vote_strategy strategy = (parameters.size() <= 4) ?
    (fc::json::from_string("\"vote_none\"").as<fbtc::wallet::vote_strategy>()) :
    parameters[4].as<fbtc::wallet::vote_strategy>();
  bool sign_and_broadcast = (parameters.size() <= 5) ?
    (fc::json::from_string("true").as<bool>()) :
    parameters[5].as<bool>();
  std::string builder_path = (parameters.size() <= 6) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[6].as<std::string>();

  fbtc::wallet::transaction_builder result = get_client()->wallet_withdraw_from_address(amount, symbol, from_address, to, strategy, sign_and_broadcast, builder_path);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_withdraw_from_address_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (!parameters.contains("amount"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'amount'");
  std::string amount = parameters["amount"].as<std::string>();
  if (!parameters.contains("symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'symbol'");
  std::string symbol = parameters["symbol"].as<std::string>();
  if (!parameters.contains("from_address"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'from_address'");
  fbtc::blockchain::address from_address = parameters["from_address"].as<fbtc::blockchain::address>();
  if (!parameters.contains("to"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'to'");
  std::string to = parameters["to"].as<std::string>();
  fbtc::wallet::vote_strategy strategy = parameters.contains("strategy") ? 
    (fc::json::from_string("\"vote_none\"").as<fbtc::wallet::vote_strategy>()) :
    parameters["strategy"].as<fbtc::wallet::vote_strategy>();
  bool sign_and_broadcast = parameters.contains("sign_and_broadcast") ? 
    (fc::json::from_string("true").as<bool>()) :
    parameters["sign_and_broadcast"].as<bool>();
  std::string builder_path = parameters.contains("builder_path") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["builder_path"].as<std::string>();

  fbtc::wallet::transaction_builder result = get_client()->wallet_withdraw_from_address(amount, symbol, from_address, to, strategy, sign_and_broadcast, builder_path);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_receive_genesis_multisig_blanace_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (from_address)");
  fbtc::blockchain::address from_address = parameters[0].as<fbtc::blockchain::address>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (from_address_redeemscript)");
  std::string from_address_redeemscript = parameters[1].as<std::string>();
  if (parameters.size() <= 2)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 3 (to)");
  std::string to = parameters[2].as<std::string>();
  fbtc::wallet::vote_strategy strategy = (parameters.size() <= 3) ?
    (fc::json::from_string("\"vote_none\"").as<fbtc::wallet::vote_strategy>()) :
    parameters[3].as<fbtc::wallet::vote_strategy>();
  bool sign_and_broadcast = (parameters.size() <= 4) ?
    (fc::json::from_string("true").as<bool>()) :
    parameters[4].as<bool>();
  std::string builder_path = (parameters.size() <= 5) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[5].as<std::string>();

  fbtc::wallet::transaction_builder result = get_client()->wallet_receive_genesis_multisig_blanace(from_address, from_address_redeemscript, to, strategy, sign_and_broadcast, builder_path);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_receive_genesis_multisig_blanace_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (!parameters.contains("from_address"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'from_address'");
  fbtc::blockchain::address from_address = parameters["from_address"].as<fbtc::blockchain::address>();
  if (!parameters.contains("from_address_redeemscript"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'from_address_redeemscript'");
  std::string from_address_redeemscript = parameters["from_address_redeemscript"].as<std::string>();
  if (!parameters.contains("to"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'to'");
  std::string to = parameters["to"].as<std::string>();
  fbtc::wallet::vote_strategy strategy = parameters.contains("strategy") ? 
    (fc::json::from_string("\"vote_none\"").as<fbtc::wallet::vote_strategy>()) :
    parameters["strategy"].as<fbtc::wallet::vote_strategy>();
  bool sign_and_broadcast = parameters.contains("sign_and_broadcast") ? 
    (fc::json::from_string("true").as<bool>()) :
    parameters["sign_and_broadcast"].as<bool>();
  std::string builder_path = parameters.contains("builder_path") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["builder_path"].as<std::string>();

  fbtc::wallet::transaction_builder result = get_client()->wallet_receive_genesis_multisig_blanace(from_address, from_address_redeemscript, to, strategy, sign_and_broadcast, builder_path);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_withdraw_from_legacy_address_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (amount)");
  std::string amount = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (symbol)");
  std::string symbol = parameters[1].as<std::string>();
  if (parameters.size() <= 2)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 3 (from_address)");
  fbtc::blockchain::pts_address from_address = parameters[2].as<fbtc::blockchain::pts_address>();
  if (parameters.size() <= 3)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 4 (to)");
  std::string to = parameters[3].as<std::string>();
  fbtc::wallet::vote_strategy strategy = (parameters.size() <= 4) ?
    (fc::json::from_string("\"vote_none\"").as<fbtc::wallet::vote_strategy>()) :
    parameters[4].as<fbtc::wallet::vote_strategy>();
  bool sign_and_broadcast = (parameters.size() <= 5) ?
    (fc::json::from_string("true").as<bool>()) :
    parameters[5].as<bool>();
  std::string builder_path = (parameters.size() <= 6) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[6].as<std::string>();

  fbtc::wallet::transaction_builder result = get_client()->wallet_withdraw_from_legacy_address(amount, symbol, from_address, to, strategy, sign_and_broadcast, builder_path);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_withdraw_from_legacy_address_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (!parameters.contains("amount"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'amount'");
  std::string amount = parameters["amount"].as<std::string>();
  if (!parameters.contains("symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'symbol'");
  std::string symbol = parameters["symbol"].as<std::string>();
  if (!parameters.contains("from_address"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'from_address'");
  fbtc::blockchain::pts_address from_address = parameters["from_address"].as<fbtc::blockchain::pts_address>();
  if (!parameters.contains("to"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'to'");
  std::string to = parameters["to"].as<std::string>();
  fbtc::wallet::vote_strategy strategy = parameters.contains("strategy") ? 
    (fc::json::from_string("\"vote_none\"").as<fbtc::wallet::vote_strategy>()) :
    parameters["strategy"].as<fbtc::wallet::vote_strategy>();
  bool sign_and_broadcast = parameters.contains("sign_and_broadcast") ? 
    (fc::json::from_string("true").as<bool>()) :
    parameters["sign_and_broadcast"].as<bool>();
  std::string builder_path = parameters.contains("builder_path") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["builder_path"].as<std::string>();

  fbtc::wallet::transaction_builder result = get_client()->wallet_withdraw_from_legacy_address(amount, symbol, from_address, to, strategy, sign_and_broadcast, builder_path);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_multisig_withdraw_start_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (amount)");
  std::string amount = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (symbol)");
  std::string symbol = parameters[1].as<std::string>();
  if (parameters.size() <= 2)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 3 (from)");
  fbtc::blockchain::address from = parameters[2].as<fbtc::blockchain::address>();
  if (parameters.size() <= 3)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 4 (to_address)");
  fbtc::blockchain::address to_address = parameters[3].as<fbtc::blockchain::address>();
  fbtc::wallet::vote_strategy strategy = (parameters.size() <= 4) ?
    (fc::json::from_string("\"vote_none\"").as<fbtc::wallet::vote_strategy>()) :
    parameters[4].as<fbtc::wallet::vote_strategy>();
  std::string builder_path = (parameters.size() <= 5) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[5].as<std::string>();

  fbtc::wallet::transaction_builder result = get_client()->wallet_multisig_withdraw_start(amount, symbol, from, to_address, strategy, builder_path);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_multisig_withdraw_start_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (!parameters.contains("amount"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'amount'");
  std::string amount = parameters["amount"].as<std::string>();
  if (!parameters.contains("symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'symbol'");
  std::string symbol = parameters["symbol"].as<std::string>();
  if (!parameters.contains("from"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'from'");
  fbtc::blockchain::address from = parameters["from"].as<fbtc::blockchain::address>();
  if (!parameters.contains("to_address"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'to_address'");
  fbtc::blockchain::address to_address = parameters["to_address"].as<fbtc::blockchain::address>();
  fbtc::wallet::vote_strategy strategy = parameters.contains("strategy") ? 
    (fc::json::from_string("\"vote_none\"").as<fbtc::wallet::vote_strategy>()) :
    parameters["strategy"].as<fbtc::wallet::vote_strategy>();
  std::string builder_path = parameters.contains("builder_path") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["builder_path"].as<std::string>();

  fbtc::wallet::transaction_builder result = get_client()->wallet_multisig_withdraw_start(amount, symbol, from, to_address, strategy, builder_path);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_builder_add_signature_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (builder)");
  fbtc::wallet::transaction_builder builder = parameters[0].as<fbtc::wallet::transaction_builder>();
  bool broadcast = (parameters.size() <= 1) ?
    (fc::json::from_string("false").as<bool>()) :
    parameters[1].as<bool>();

  fbtc::wallet::transaction_builder result = get_client()->wallet_builder_add_signature(builder, broadcast);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_builder_add_signature_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (!parameters.contains("builder"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'builder'");
  fbtc::wallet::transaction_builder builder = parameters["builder"].as<fbtc::wallet::transaction_builder>();
  bool broadcast = parameters.contains("broadcast") ? 
    (fc::json::from_string("false").as<bool>()) :
    parameters["broadcast"].as<bool>();

  fbtc::wallet::transaction_builder result = get_client()->wallet_builder_add_signature(builder, broadcast);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_builder_file_add_signature_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  std::string builder_path = (parameters.size() <= 0) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[0].as<std::string>();
  bool broadcast = (parameters.size() <= 1) ?
    (fc::json::from_string("false").as<bool>()) :
    parameters[1].as<bool>();

  fbtc::wallet::transaction_builder result = get_client()->wallet_builder_file_add_signature(builder_path, broadcast);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_builder_file_add_signature_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  std::string builder_path = parameters.contains("builder_path") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["builder_path"].as<std::string>();
  bool broadcast = parameters.contains("broadcast") ? 
    (fc::json::from_string("false").as<bool>()) :
    parameters["broadcast"].as<bool>();

  fbtc::wallet::transaction_builder result = get_client()->wallet_builder_file_add_signature(builder_path, broadcast);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_release_escrow_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (pay_fee_with_account_name)");
  std::string pay_fee_with_account_name = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (escrow_balance_id)");
  fbtc::blockchain::address escrow_balance_id = parameters[1].as<fbtc::blockchain::address>();
  if (parameters.size() <= 2)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 3 (released_by_account)");
  std::string released_by_account = parameters[2].as<std::string>();
  std::string amount_to_sender = (parameters.size() <= 3) ?
    (fc::json::from_string("0").as<std::string>()) :
    parameters[3].as<std::string>();
  std::string amount_to_receiver = (parameters.size() <= 4) ?
    (fc::json::from_string("0").as<std::string>()) :
    parameters[4].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_release_escrow(pay_fee_with_account_name, escrow_balance_id, released_by_account, amount_to_sender, amount_to_receiver);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_release_escrow_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (!parameters.contains("pay_fee_with_account_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'pay_fee_with_account_name'");
  std::string pay_fee_with_account_name = parameters["pay_fee_with_account_name"].as<std::string>();
  if (!parameters.contains("escrow_balance_id"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'escrow_balance_id'");
  fbtc::blockchain::address escrow_balance_id = parameters["escrow_balance_id"].as<fbtc::blockchain::address>();
  if (!parameters.contains("released_by_account"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'released_by_account'");
  std::string released_by_account = parameters["released_by_account"].as<std::string>();
  std::string amount_to_sender = parameters.contains("amount_to_sender") ? 
    (fc::json::from_string("0").as<std::string>()) :
    parameters["amount_to_sender"].as<std::string>();
  std::string amount_to_receiver = parameters.contains("amount_to_receiver") ? 
    (fc::json::from_string("0").as<std::string>()) :
    parameters["amount_to_receiver"].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_release_escrow(pay_fee_with_account_name, escrow_balance_id, released_by_account, amount_to_sender, amount_to_receiver);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_transfer_from_with_escrow_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (amount_to_transfer)");
  std::string amount_to_transfer = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (asset_symbol)");
  std::string asset_symbol = parameters[1].as<std::string>();
  if (parameters.size() <= 2)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 3 (paying_account_name)");
  std::string paying_account_name = parameters[2].as<std::string>();
  if (parameters.size() <= 3)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 4 (from_account_name)");
  std::string from_account_name = parameters[3].as<std::string>();
  if (parameters.size() <= 4)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 5 (to_account_name)");
  std::string to_account_name = parameters[4].as<std::string>();
  if (parameters.size() <= 5)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 6 (escrow_account_name)");
  std::string escrow_account_name = parameters[5].as<std::string>();
  fbtc::blockchain::digest_type agreement = (parameters.size() <= 6) ?
    (fc::json::from_string("\"\"").as<fbtc::blockchain::digest_type>()) :
    parameters[6].as<fbtc::blockchain::digest_type>();
  std::string memo_message = (parameters.size() <= 7) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[7].as<std::string>();
  fbtc::wallet::vote_strategy strategy = (parameters.size() <= 8) ?
    (fc::json::from_string("\"vote_recommended\"").as<fbtc::wallet::vote_strategy>()) :
    parameters[8].as<fbtc::wallet::vote_strategy>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_transfer_from_with_escrow(amount_to_transfer, asset_symbol, paying_account_name, from_account_name, to_account_name, escrow_account_name, agreement, memo_message, strategy);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_transfer_from_with_escrow_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("amount_to_transfer"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'amount_to_transfer'");
  std::string amount_to_transfer = parameters["amount_to_transfer"].as<std::string>();
  if (!parameters.contains("asset_symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'asset_symbol'");
  std::string asset_symbol = parameters["asset_symbol"].as<std::string>();
  if (!parameters.contains("paying_account_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'paying_account_name'");
  std::string paying_account_name = parameters["paying_account_name"].as<std::string>();
  if (!parameters.contains("from_account_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'from_account_name'");
  std::string from_account_name = parameters["from_account_name"].as<std::string>();
  if (!parameters.contains("to_account_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'to_account_name'");
  std::string to_account_name = parameters["to_account_name"].as<std::string>();
  if (!parameters.contains("escrow_account_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'escrow_account_name'");
  std::string escrow_account_name = parameters["escrow_account_name"].as<std::string>();
  fbtc::blockchain::digest_type agreement = parameters.contains("agreement") ? 
    (fc::json::from_string("\"\"").as<fbtc::blockchain::digest_type>()) :
    parameters["agreement"].as<fbtc::blockchain::digest_type>();
  std::string memo_message = parameters.contains("memo_message") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["memo_message"].as<std::string>();
  fbtc::wallet::vote_strategy strategy = parameters.contains("strategy") ? 
    (fc::json::from_string("\"vote_recommended\"").as<fbtc::wallet::vote_strategy>()) :
    parameters["strategy"].as<fbtc::wallet::vote_strategy>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_transfer_from_with_escrow(amount_to_transfer, asset_symbol, paying_account_name, from_account_name, to_account_name, escrow_account_name, agreement, memo_message, strategy);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_rescan_blockchain_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  uint32_t start_block_num = (parameters.size() <= 0) ?
    (fc::json::from_string("0").as<uint32_t>()) :
    parameters[0].as<uint32_t>();
  uint32_t limit = (parameters.size() <= 1) ?
    (fc::json::from_string("-1").as<uint32_t>()) :
    parameters[1].as<uint32_t>();
  bool scan_in_background = (parameters.size() <= 2) ?
    (fc::json::from_string("true").as<bool>()) :
    parameters[2].as<bool>();

  get_client()->wallet_rescan_blockchain(start_block_num, limit, scan_in_background);
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_rescan_blockchain_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  uint32_t start_block_num = parameters.contains("start_block_num") ? 
    (fc::json::from_string("0").as<uint32_t>()) :
    parameters["start_block_num"].as<uint32_t>();
  uint32_t limit = parameters.contains("limit") ? 
    (fc::json::from_string("-1").as<uint32_t>()) :
    parameters["limit"].as<uint32_t>();
  bool scan_in_background = parameters.contains("scan_in_background") ? 
    (fc::json::from_string("true").as<bool>()) :
    parameters["scan_in_background"].as<bool>();

  get_client()->wallet_rescan_blockchain(start_block_num, limit, scan_in_background);
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_cancel_scan_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites


  get_client()->wallet_cancel_scan();
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_cancel_scan_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites


  get_client()->wallet_cancel_scan();
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_get_transaction_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (transaction_id)");
  std::string transaction_id = parameters[0].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_get_transaction(transaction_id);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_get_transaction_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (!parameters.contains("transaction_id"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'transaction_id'");
  std::string transaction_id = parameters["transaction_id"].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_get_transaction(transaction_id);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_scan_transaction_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (transaction_id)");
  std::string transaction_id = parameters[0].as<std::string>();
  bool overwrite_existing = (parameters.size() <= 1) ?
    (fc::json::from_string("false").as<bool>()) :
    parameters[1].as<bool>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_scan_transaction(transaction_id, overwrite_existing);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_scan_transaction_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("transaction_id"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'transaction_id'");
  std::string transaction_id = parameters["transaction_id"].as<std::string>();
  bool overwrite_existing = parameters.contains("overwrite_existing") ? 
    (fc::json::from_string("false").as<bool>()) :
    parameters["overwrite_existing"].as<bool>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_scan_transaction(transaction_id, overwrite_existing);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_scan_transaction_experimental_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (transaction_id)");
  std::string transaction_id = parameters[0].as<std::string>();
  bool overwrite_existing = (parameters.size() <= 1) ?
    (fc::json::from_string("false").as<bool>()) :
    parameters[1].as<bool>();

  get_client()->wallet_scan_transaction_experimental(transaction_id, overwrite_existing);
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_scan_transaction_experimental_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("transaction_id"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'transaction_id'");
  std::string transaction_id = parameters["transaction_id"].as<std::string>();
  bool overwrite_existing = parameters.contains("overwrite_existing") ? 
    (fc::json::from_string("false").as<bool>()) :
    parameters["overwrite_existing"].as<bool>();

  get_client()->wallet_scan_transaction_experimental(transaction_id, overwrite_existing);
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_add_transaction_note_experimental_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (transaction_id)");
  std::string transaction_id = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (note)");
  std::string note = parameters[1].as<std::string>();

  get_client()->wallet_add_transaction_note_experimental(transaction_id, note);
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_add_transaction_note_experimental_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("transaction_id"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'transaction_id'");
  std::string transaction_id = parameters["transaction_id"].as<std::string>();
  if (!parameters.contains("note"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'note'");
  std::string note = parameters["note"].as<std::string>();

  get_client()->wallet_add_transaction_note_experimental(transaction_id, note);
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_rebroadcast_transaction_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (transaction_id)");
  std::string transaction_id = parameters[0].as<std::string>();

  get_client()->wallet_rebroadcast_transaction(transaction_id);
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_rebroadcast_transaction_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (!parameters.contains("transaction_id"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'transaction_id'");
  std::string transaction_id = parameters["transaction_id"].as<std::string>();

  get_client()->wallet_rebroadcast_transaction(transaction_id);
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_account_register_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (account_name)");
  std::string account_name = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (pay_from_account)");
  std::string pay_from_account = parameters[1].as<std::string>();
  fc::variant public_data = (parameters.size() <= 2) ?
    (fc::json::from_string("null").as<fc::variant>()) :
    parameters[2].as<fc::variant>();
  uint8_t delegate_pay_rate = (parameters.size() <= 3) ?
    (fc::json::from_string("-1").as<uint8_t>()) :
    parameters[3].as<uint8_t>();
  std::string account_type = (parameters.size() <= 4) ?
    (fc::json::from_string("\"titan_account\"").as<std::string>()) :
    parameters[4].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_account_register(account_name, pay_from_account, public_data, delegate_pay_rate, account_type);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_account_register_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("account_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'account_name'");
  std::string account_name = parameters["account_name"].as<std::string>();
  if (!parameters.contains("pay_from_account"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'pay_from_account'");
  std::string pay_from_account = parameters["pay_from_account"].as<std::string>();
  fc::variant public_data = parameters.contains("public_data") ? 
    (fc::json::from_string("null").as<fc::variant>()) :
    parameters["public_data"].as<fc::variant>();
  uint8_t delegate_pay_rate = parameters.contains("delegate_pay_rate") ? 
    (fc::json::from_string("-1").as<uint8_t>()) :
    parameters["delegate_pay_rate"].as<uint8_t>();
  std::string account_type = parameters.contains("account_type") ? 
    (fc::json::from_string("\"titan_account\"").as<std::string>()) :
    parameters["account_type"].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_account_register(account_name, pay_from_account, public_data, delegate_pay_rate, account_type);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_set_custom_data_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (type)");
  fbtc::wallet::wallet_record_type_enum type = parameters[0].as<fbtc::wallet::wallet_record_type_enum>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (item)");
  std::string item = parameters[1].as<std::string>();
  if (parameters.size() <= 2)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 3 (custom_data)");
  fc::variant_object custom_data = parameters[2].as<fc::variant_object>();

  get_client()->wallet_set_custom_data(type, item, custom_data);
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_set_custom_data_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("type"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'type'");
  fbtc::wallet::wallet_record_type_enum type = parameters["type"].as<fbtc::wallet::wallet_record_type_enum>();
  if (!parameters.contains("item"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'item'");
  std::string item = parameters["item"].as<std::string>();
  if (!parameters.contains("custom_data"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'custom_data'");
  fc::variant_object custom_data = parameters["custom_data"].as<fc::variant_object>();

  get_client()->wallet_set_custom_data(type, item, custom_data);
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_account_update_registration_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (account_name)");
  std::string account_name = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (pay_from_account)");
  std::string pay_from_account = parameters[1].as<std::string>();
  fc::variant public_data = (parameters.size() <= 2) ?
    (fc::json::from_string("null").as<fc::variant>()) :
    parameters[2].as<fc::variant>();
  uint8_t delegate_pay_rate = (parameters.size() <= 3) ?
    (fc::json::from_string("-1").as<uint8_t>()) :
    parameters[3].as<uint8_t>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_account_update_registration(account_name, pay_from_account, public_data, delegate_pay_rate);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_account_update_registration_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("account_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'account_name'");
  std::string account_name = parameters["account_name"].as<std::string>();
  if (!parameters.contains("pay_from_account"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'pay_from_account'");
  std::string pay_from_account = parameters["pay_from_account"].as<std::string>();
  fc::variant public_data = parameters.contains("public_data") ? 
    (fc::json::from_string("null").as<fc::variant>()) :
    parameters["public_data"].as<fc::variant>();
  uint8_t delegate_pay_rate = parameters.contains("delegate_pay_rate") ? 
    (fc::json::from_string("-1").as<uint8_t>()) :
    parameters["delegate_pay_rate"].as<uint8_t>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_account_update_registration(account_name, pay_from_account, public_data, delegate_pay_rate);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_account_update_active_key_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (account_to_update)");
  std::string account_to_update = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (pay_from_account)");
  std::string pay_from_account = parameters[1].as<std::string>();
  std::string new_active_key = (parameters.size() <= 2) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[2].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_account_update_active_key(account_to_update, pay_from_account, new_active_key);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_account_update_active_key_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("account_to_update"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'account_to_update'");
  std::string account_to_update = parameters["account_to_update"].as<std::string>();
  if (!parameters.contains("pay_from_account"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'pay_from_account'");
  std::string pay_from_account = parameters["pay_from_account"].as<std::string>();
  std::string new_active_key = parameters.contains("new_active_key") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["new_active_key"].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_account_update_active_key(account_to_update, pay_from_account, new_active_key);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_list_accounts_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites


  std::vector<fbtc::wallet::wallet_account_record> result = get_client()->wallet_list_accounts();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_list_accounts_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites


  std::vector<fbtc::wallet::wallet_account_record> result = get_client()->wallet_list_accounts();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_get_account_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (account)");
  std::string account = parameters[0].as<std::string>();

  fbtc::wallet::owallet_account_record result = get_client()->wallet_get_account(account);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_get_account_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (!parameters.contains("account"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'account'");
  std::string account = parameters["account"].as<std::string>();

  fbtc::wallet::owallet_account_record result = get_client()->wallet_get_account(account);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_account_rename_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (current_account_name)");
  std::string current_account_name = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (new_account_name)");
  std::string new_account_name = parameters[1].as<std::string>();

  get_client()->wallet_account_rename(current_account_name, new_account_name);
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_account_rename_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (!parameters.contains("current_account_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'current_account_name'");
  std::string current_account_name = parameters["current_account_name"].as<std::string>();
  if (!parameters.contains("new_account_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'new_account_name'");
  std::string new_account_name = parameters["new_account_name"].as<std::string>();

  get_client()->wallet_account_rename(current_account_name, new_account_name);
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_mia_create_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (payer_account)");
  std::string payer_account = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (symbol)");
  std::string symbol = parameters[1].as<std::string>();
  if (parameters.size() <= 2)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 3 (name)");
  std::string name = parameters[2].as<std::string>();
  if (parameters.size() <= 3)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 4 (description)");
  std::string description = parameters[3].as<std::string>();
  if (parameters.size() <= 4)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 5 (max_divisibility)");
  std::string max_divisibility = parameters[4].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_mia_create(payer_account, symbol, name, description, max_divisibility);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_mia_create_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("payer_account"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'payer_account'");
  std::string payer_account = parameters["payer_account"].as<std::string>();
  if (!parameters.contains("symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'symbol'");
  std::string symbol = parameters["symbol"].as<std::string>();
  if (!parameters.contains("name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'name'");
  std::string name = parameters["name"].as<std::string>();
  if (!parameters.contains("description"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'description'");
  std::string description = parameters["description"].as<std::string>();
  if (!parameters.contains("max_divisibility"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'max_divisibility'");
  std::string max_divisibility = parameters["max_divisibility"].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_mia_create(payer_account, symbol, name, description, max_divisibility);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_uia_create_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (issuer_account)");
  std::string issuer_account = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (symbol)");
  std::string symbol = parameters[1].as<std::string>();
  if (parameters.size() <= 2)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 3 (name)");
  std::string name = parameters[2].as<std::string>();
  if (parameters.size() <= 3)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 4 (description)");
  std::string description = parameters[3].as<std::string>();
  if (parameters.size() <= 4)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 5 (max_supply_with_trailing_decimals)");
  std::string max_supply_with_trailing_decimals = parameters[4].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_uia_create(issuer_account, symbol, name, description, max_supply_with_trailing_decimals);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_uia_create_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("issuer_account"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'issuer_account'");
  std::string issuer_account = parameters["issuer_account"].as<std::string>();
  if (!parameters.contains("symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'symbol'");
  std::string symbol = parameters["symbol"].as<std::string>();
  if (!parameters.contains("name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'name'");
  std::string name = parameters["name"].as<std::string>();
  if (!parameters.contains("description"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'description'");
  std::string description = parameters["description"].as<std::string>();
  if (!parameters.contains("max_supply_with_trailing_decimals"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'max_supply_with_trailing_decimals'");
  std::string max_supply_with_trailing_decimals = parameters["max_supply_with_trailing_decimals"].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_uia_create(issuer_account, symbol, name, description, max_supply_with_trailing_decimals);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_uia_issue_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (asset_amount)");
  std::string asset_amount = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (asset_symbol)");
  std::string asset_symbol = parameters[1].as<std::string>();
  if (parameters.size() <= 2)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 3 (recipient)");
  std::string recipient = parameters[2].as<std::string>();
  std::string memo_message = (parameters.size() <= 3) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[3].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_uia_issue(asset_amount, asset_symbol, recipient, memo_message);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_uia_issue_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("asset_amount"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'asset_amount'");
  std::string asset_amount = parameters["asset_amount"].as<std::string>();
  if (!parameters.contains("asset_symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'asset_symbol'");
  std::string asset_symbol = parameters["asset_symbol"].as<std::string>();
  if (!parameters.contains("recipient"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'recipient'");
  std::string recipient = parameters["recipient"].as<std::string>();
  std::string memo_message = parameters.contains("memo_message") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["memo_message"].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_uia_issue(asset_amount, asset_symbol, recipient, memo_message);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_uia_issue_to_addresses_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (symbol)");
  std::string symbol = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (addresses)");
  std::map<std::string, fbtc::blockchain::share_type> addresses = parameters[1].as<std::map<std::string, fbtc::blockchain::share_type>>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_uia_issue_to_addresses(symbol, addresses);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_uia_issue_to_addresses_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'symbol'");
  std::string symbol = parameters["symbol"].as<std::string>();
  if (!parameters.contains("addresses"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'addresses'");
  std::map<std::string, fbtc::blockchain::share_type> addresses = parameters["addresses"].as<std::map<std::string, fbtc::blockchain::share_type>>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_uia_issue_to_addresses(symbol, addresses);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_uia_collect_fees_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (asset_symbol)");
  std::string asset_symbol = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (recipient)");
  std::string recipient = parameters[1].as<std::string>();
  std::string memo_message = (parameters.size() <= 2) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[2].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_uia_collect_fees(asset_symbol, recipient, memo_message);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_uia_collect_fees_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("asset_symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'asset_symbol'");
  std::string asset_symbol = parameters["asset_symbol"].as<std::string>();
  if (!parameters.contains("recipient"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'recipient'");
  std::string recipient = parameters["recipient"].as<std::string>();
  std::string memo_message = parameters.contains("memo_message") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["memo_message"].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_uia_collect_fees(asset_symbol, recipient, memo_message);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_uia_update_description_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (paying_account)");
  std::string paying_account = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (asset_symbol)");
  std::string asset_symbol = parameters[1].as<std::string>();
  std::string name = (parameters.size() <= 2) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[2].as<std::string>();
  std::string description = (parameters.size() <= 3) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[3].as<std::string>();
  fc::variant public_data = (parameters.size() <= 4) ?
    (fc::json::from_string("null").as<fc::variant>()) :
    parameters[4].as<fc::variant>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_uia_update_description(paying_account, asset_symbol, name, description, public_data);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_uia_update_description_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("paying_account"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'paying_account'");
  std::string paying_account = parameters["paying_account"].as<std::string>();
  if (!parameters.contains("asset_symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'asset_symbol'");
  std::string asset_symbol = parameters["asset_symbol"].as<std::string>();
  std::string name = parameters.contains("name") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["name"].as<std::string>();
  std::string description = parameters.contains("description") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["description"].as<std::string>();
  fc::variant public_data = parameters.contains("public_data") ? 
    (fc::json::from_string("null").as<fc::variant>()) :
    parameters["public_data"].as<fc::variant>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_uia_update_description(paying_account, asset_symbol, name, description, public_data);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_uia_update_supply_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (paying_account)");
  std::string paying_account = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (asset_symbol)");
  std::string asset_symbol = parameters[1].as<std::string>();
  if (parameters.size() <= 2)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 3 (max_supply_with_trailing_decimals)");
  std::string max_supply_with_trailing_decimals = parameters[2].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_uia_update_supply(paying_account, asset_symbol, max_supply_with_trailing_decimals);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_uia_update_supply_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("paying_account"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'paying_account'");
  std::string paying_account = parameters["paying_account"].as<std::string>();
  if (!parameters.contains("asset_symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'asset_symbol'");
  std::string asset_symbol = parameters["asset_symbol"].as<std::string>();
  if (!parameters.contains("max_supply_with_trailing_decimals"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'max_supply_with_trailing_decimals'");
  std::string max_supply_with_trailing_decimals = parameters["max_supply_with_trailing_decimals"].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_uia_update_supply(paying_account, asset_symbol, max_supply_with_trailing_decimals);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_uia_update_fees_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (paying_account)");
  std::string paying_account = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (asset_symbol)");
  std::string asset_symbol = parameters[1].as<std::string>();
  std::string withdrawal_fee = (parameters.size() <= 2) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[2].as<std::string>();
  std::string market_fee_rate = (parameters.size() <= 3) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[3].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_uia_update_fees(paying_account, asset_symbol, withdrawal_fee, market_fee_rate);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_uia_update_fees_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("paying_account"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'paying_account'");
  std::string paying_account = parameters["paying_account"].as<std::string>();
  if (!parameters.contains("asset_symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'asset_symbol'");
  std::string asset_symbol = parameters["asset_symbol"].as<std::string>();
  std::string withdrawal_fee = parameters.contains("withdrawal_fee") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["withdrawal_fee"].as<std::string>();
  std::string market_fee_rate = parameters.contains("market_fee_rate") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["market_fee_rate"].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_uia_update_fees(paying_account, asset_symbol, withdrawal_fee, market_fee_rate);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_uia_update_active_flags_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (paying_account)");
  std::string paying_account = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (asset_symbol)");
  std::string asset_symbol = parameters[1].as<std::string>();
  if (parameters.size() <= 2)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 3 (flag)");
  fbtc::blockchain::asset_record::flag_enum flag = parameters[2].as<fbtc::blockchain::asset_record::flag_enum>();
  if (parameters.size() <= 3)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 4 (enable_instead_of_disable)");
  bool enable_instead_of_disable = parameters[3].as<bool>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_uia_update_active_flags(paying_account, asset_symbol, flag, enable_instead_of_disable);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_uia_update_active_flags_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("paying_account"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'paying_account'");
  std::string paying_account = parameters["paying_account"].as<std::string>();
  if (!parameters.contains("asset_symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'asset_symbol'");
  std::string asset_symbol = parameters["asset_symbol"].as<std::string>();
  if (!parameters.contains("flag"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'flag'");
  fbtc::blockchain::asset_record::flag_enum flag = parameters["flag"].as<fbtc::blockchain::asset_record::flag_enum>();
  if (!parameters.contains("enable_instead_of_disable"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'enable_instead_of_disable'");
  bool enable_instead_of_disable = parameters["enable_instead_of_disable"].as<bool>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_uia_update_active_flags(paying_account, asset_symbol, flag, enable_instead_of_disable);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_uia_update_authority_permissions_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (paying_account)");
  std::string paying_account = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (asset_symbol)");
  std::string asset_symbol = parameters[1].as<std::string>();
  if (parameters.size() <= 2)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 3 (permission)");
  fbtc::blockchain::asset_record::flag_enum permission = parameters[2].as<fbtc::blockchain::asset_record::flag_enum>();
  if (parameters.size() <= 3)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 4 (add_instead_of_remove)");
  bool add_instead_of_remove = parameters[3].as<bool>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_uia_update_authority_permissions(paying_account, asset_symbol, permission, add_instead_of_remove);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_uia_update_authority_permissions_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("paying_account"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'paying_account'");
  std::string paying_account = parameters["paying_account"].as<std::string>();
  if (!parameters.contains("asset_symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'asset_symbol'");
  std::string asset_symbol = parameters["asset_symbol"].as<std::string>();
  if (!parameters.contains("permission"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'permission'");
  fbtc::blockchain::asset_record::flag_enum permission = parameters["permission"].as<fbtc::blockchain::asset_record::flag_enum>();
  if (!parameters.contains("add_instead_of_remove"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'add_instead_of_remove'");
  bool add_instead_of_remove = parameters["add_instead_of_remove"].as<bool>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_uia_update_authority_permissions(paying_account, asset_symbol, permission, add_instead_of_remove);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_uia_update_whitelist_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (paying_account)");
  std::string paying_account = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (asset_symbol)");
  std::string asset_symbol = parameters[1].as<std::string>();
  if (parameters.size() <= 2)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 3 (account_name)");
  std::string account_name = parameters[2].as<std::string>();
  if (parameters.size() <= 3)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 4 (add_to_whitelist)");
  bool add_to_whitelist = parameters[3].as<bool>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_uia_update_whitelist(paying_account, asset_symbol, account_name, add_to_whitelist);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_uia_update_whitelist_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("paying_account"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'paying_account'");
  std::string paying_account = parameters["paying_account"].as<std::string>();
  if (!parameters.contains("asset_symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'asset_symbol'");
  std::string asset_symbol = parameters["asset_symbol"].as<std::string>();
  if (!parameters.contains("account_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'account_name'");
  std::string account_name = parameters["account_name"].as<std::string>();
  if (!parameters.contains("add_to_whitelist"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'add_to_whitelist'");
  bool add_to_whitelist = parameters["add_to_whitelist"].as<bool>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_uia_update_whitelist(paying_account, asset_symbol, account_name, add_to_whitelist);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_uia_retract_balance_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (balance_id)");
  fbtc::blockchain::address balance_id = parameters[0].as<fbtc::blockchain::address>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (account_name)");
  std::string account_name = parameters[1].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_uia_retract_balance(balance_id, account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_uia_retract_balance_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("balance_id"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'balance_id'");
  fbtc::blockchain::address balance_id = parameters["balance_id"].as<fbtc::blockchain::address>();
  if (!parameters.contains("account_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'account_name'");
  std::string account_name = parameters["account_name"].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_uia_retract_balance(balance_id, account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_escrow_summary_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  std::string account_name = (parameters.size() <= 0) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[0].as<std::string>();

  std::vector<fbtc::wallet::escrow_summary> result = get_client()->wallet_escrow_summary(account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_escrow_summary_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  std::string account_name = parameters.contains("account_name") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["account_name"].as<std::string>();

  std::vector<fbtc::wallet::escrow_summary> result = get_client()->wallet_escrow_summary(account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_account_balance_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  std::string account_name = (parameters.size() <= 0) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[0].as<std::string>();

  fbtc::wallet::account_balance_summary_type result = get_client()->wallet_account_balance(account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_account_balance_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  std::string account_name = parameters.contains("account_name") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["account_name"].as<std::string>();

  fbtc::wallet::account_balance_summary_type result = get_client()->wallet_account_balance(account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_account_balance_ids_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  std::string account_name = (parameters.size() <= 0) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[0].as<std::string>();

  fbtc::wallet::account_balance_id_summary_type result = get_client()->wallet_account_balance_ids(account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_account_balance_ids_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  std::string account_name = parameters.contains("account_name") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["account_name"].as<std::string>();

  fbtc::wallet::account_balance_id_summary_type result = get_client()->wallet_account_balance_ids(account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_account_balance_extended_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  std::string account_name = (parameters.size() <= 0) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[0].as<std::string>();

  fbtc::wallet::account_extended_balance_type result = get_client()->wallet_account_balance_extended(account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_account_balance_extended_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  std::string account_name = parameters.contains("account_name") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["account_name"].as<std::string>();

  fbtc::wallet::account_extended_balance_type result = get_client()->wallet_account_balance_extended(account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_account_vesting_balances_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  std::string account_name = (parameters.size() <= 0) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[0].as<std::string>();

  fbtc::wallet::account_vesting_balance_summary_type result = get_client()->wallet_account_vesting_balances(account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_account_vesting_balances_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  std::string account_name = parameters.contains("account_name") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["account_name"].as<std::string>();

  fbtc::wallet::account_vesting_balance_summary_type result = get_client()->wallet_account_vesting_balances(account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_account_yield_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  std::string account_name = (parameters.size() <= 0) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[0].as<std::string>();

  fbtc::wallet::account_balance_summary_type result = get_client()->wallet_account_yield(account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_account_yield_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  std::string account_name = parameters.contains("account_name") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["account_name"].as<std::string>();

  fbtc::wallet::account_balance_summary_type result = get_client()->wallet_account_yield(account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_account_list_public_keys_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (account_name)");
  std::string account_name = parameters[0].as<std::string>();

  std::vector<fbtc::wallet::public_key_summary> result = get_client()->wallet_account_list_public_keys(account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_account_list_public_keys_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (!parameters.contains("account_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'account_name'");
  std::string account_name = parameters["account_name"].as<std::string>();

  std::vector<fbtc::wallet::public_key_summary> result = get_client()->wallet_account_list_public_keys(account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_delegate_withdraw_pay_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (delegate_name)");
  std::string delegate_name = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (to_account_name)");
  std::string to_account_name = parameters[1].as<std::string>();
  if (parameters.size() <= 2)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 3 (amount_to_withdraw)");
  std::string amount_to_withdraw = parameters[2].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_delegate_withdraw_pay(delegate_name, to_account_name, amount_to_withdraw);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_delegate_withdraw_pay_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("delegate_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'delegate_name'");
  std::string delegate_name = parameters["delegate_name"].as<std::string>();
  if (!parameters.contains("to_account_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'to_account_name'");
  std::string to_account_name = parameters["to_account_name"].as<std::string>();
  if (!parameters.contains("amount_to_withdraw"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'amount_to_withdraw'");
  std::string amount_to_withdraw = parameters["amount_to_withdraw"].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_delegate_withdraw_pay(delegate_name, to_account_name, amount_to_withdraw);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_set_transaction_fee_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (fee)");
  std::string fee = parameters[0].as<std::string>();

  fbtc::blockchain::asset result = get_client()->wallet_set_transaction_fee(fee);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_set_transaction_fee_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (!parameters.contains("fee"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'fee'");
  std::string fee = parameters["fee"].as<std::string>();

  fbtc::blockchain::asset result = get_client()->wallet_set_transaction_fee(fee);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_get_transaction_fee_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  std::string symbol = (parameters.size() <= 0) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[0].as<std::string>();

  fbtc::blockchain::asset result = get_client()->wallet_get_transaction_fee(symbol);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_get_transaction_fee_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  std::string symbol = parameters.contains("symbol") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["symbol"].as<std::string>();

  fbtc::blockchain::asset result = get_client()->wallet_get_transaction_fee(symbol);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_market_submit_bid_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (from_account_name)");
  std::string from_account_name = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (quantity)");
  std::string quantity = parameters[1].as<std::string>();
  if (parameters.size() <= 2)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 3 (quantity_symbol)");
  std::string quantity_symbol = parameters[2].as<std::string>();
  if (parameters.size() <= 3)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 4 (base_price)");
  std::string base_price = parameters[3].as<std::string>();
  if (parameters.size() <= 4)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 5 (base_symbol)");
  std::string base_symbol = parameters[4].as<std::string>();
  bool allow_stupid_bid = (parameters.size() <= 5) ?
    (fc::json::from_string("\"false\"").as<bool>()) :
    parameters[5].as<bool>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_market_submit_bid(from_account_name, quantity, quantity_symbol, base_price, base_symbol, allow_stupid_bid);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_market_submit_bid_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("from_account_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'from_account_name'");
  std::string from_account_name = parameters["from_account_name"].as<std::string>();
  if (!parameters.contains("quantity"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'quantity'");
  std::string quantity = parameters["quantity"].as<std::string>();
  if (!parameters.contains("quantity_symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'quantity_symbol'");
  std::string quantity_symbol = parameters["quantity_symbol"].as<std::string>();
  if (!parameters.contains("base_price"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'base_price'");
  std::string base_price = parameters["base_price"].as<std::string>();
  if (!parameters.contains("base_symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'base_symbol'");
  std::string base_symbol = parameters["base_symbol"].as<std::string>();
  bool allow_stupid_bid = parameters.contains("allow_stupid_bid") ? 
    (fc::json::from_string("\"false\"").as<bool>()) :
    parameters["allow_stupid_bid"].as<bool>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_market_submit_bid(from_account_name, quantity, quantity_symbol, base_price, base_symbol, allow_stupid_bid);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_market_submit_ask_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (from_account_name)");
  std::string from_account_name = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (sell_quantity)");
  std::string sell_quantity = parameters[1].as<std::string>();
  if (parameters.size() <= 2)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 3 (sell_quantity_symbol)");
  std::string sell_quantity_symbol = parameters[2].as<std::string>();
  if (parameters.size() <= 3)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 4 (ask_price)");
  std::string ask_price = parameters[3].as<std::string>();
  if (parameters.size() <= 4)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 5 (ask_price_symbol)");
  std::string ask_price_symbol = parameters[4].as<std::string>();
  bool allow_stupid_ask = (parameters.size() <= 5) ?
    (fc::json::from_string("\"false\"").as<bool>()) :
    parameters[5].as<bool>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_market_submit_ask(from_account_name, sell_quantity, sell_quantity_symbol, ask_price, ask_price_symbol, allow_stupid_ask);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_market_submit_ask_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("from_account_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'from_account_name'");
  std::string from_account_name = parameters["from_account_name"].as<std::string>();
  if (!parameters.contains("sell_quantity"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'sell_quantity'");
  std::string sell_quantity = parameters["sell_quantity"].as<std::string>();
  if (!parameters.contains("sell_quantity_symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'sell_quantity_symbol'");
  std::string sell_quantity_symbol = parameters["sell_quantity_symbol"].as<std::string>();
  if (!parameters.contains("ask_price"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'ask_price'");
  std::string ask_price = parameters["ask_price"].as<std::string>();
  if (!parameters.contains("ask_price_symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'ask_price_symbol'");
  std::string ask_price_symbol = parameters["ask_price_symbol"].as<std::string>();
  bool allow_stupid_ask = parameters.contains("allow_stupid_ask") ? 
    (fc::json::from_string("\"false\"").as<bool>()) :
    parameters["allow_stupid_ask"].as<bool>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_market_submit_ask(from_account_name, sell_quantity, sell_quantity_symbol, ask_price, ask_price_symbol, allow_stupid_ask);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_market_submit_short_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (from_account_name)");
  std::string from_account_name = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (short_collateral)");
  std::string short_collateral = parameters[1].as<std::string>();
  if (parameters.size() <= 2)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 3 (collateral_symbol)");
  std::string collateral_symbol = parameters[2].as<std::string>();
  if (parameters.size() <= 3)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 4 (interest_rate)");
  std::string interest_rate = parameters[3].as<std::string>();
  if (parameters.size() <= 4)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 5 (quote_symbol)");
  std::string quote_symbol = parameters[4].as<std::string>();
  std::string short_price_limit = (parameters.size() <= 5) ?
    (fc::json::from_string("0").as<std::string>()) :
    parameters[5].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_market_submit_short(from_account_name, short_collateral, collateral_symbol, interest_rate, quote_symbol, short_price_limit);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_market_submit_short_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("from_account_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'from_account_name'");
  std::string from_account_name = parameters["from_account_name"].as<std::string>();
  if (!parameters.contains("short_collateral"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'short_collateral'");
  std::string short_collateral = parameters["short_collateral"].as<std::string>();
  if (!parameters.contains("collateral_symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'collateral_symbol'");
  std::string collateral_symbol = parameters["collateral_symbol"].as<std::string>();
  if (!parameters.contains("interest_rate"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'interest_rate'");
  std::string interest_rate = parameters["interest_rate"].as<std::string>();
  if (!parameters.contains("quote_symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'quote_symbol'");
  std::string quote_symbol = parameters["quote_symbol"].as<std::string>();
  std::string short_price_limit = parameters.contains("short_price_limit") ? 
    (fc::json::from_string("0").as<std::string>()) :
    parameters["short_price_limit"].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_market_submit_short(from_account_name, short_collateral, collateral_symbol, interest_rate, quote_symbol, short_price_limit);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_market_cover_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (from_account_name)");
  std::string from_account_name = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (quantity)");
  std::string quantity = parameters[1].as<std::string>();
  if (parameters.size() <= 2)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 3 (quantity_symbol)");
  std::string quantity_symbol = parameters[2].as<std::string>();
  if (parameters.size() <= 3)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 4 (cover_id)");
  fbtc::blockchain::order_id_type cover_id = parameters[3].as<fbtc::blockchain::order_id_type>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_market_cover(from_account_name, quantity, quantity_symbol, cover_id);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_market_cover_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("from_account_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'from_account_name'");
  std::string from_account_name = parameters["from_account_name"].as<std::string>();
  if (!parameters.contains("quantity"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'quantity'");
  std::string quantity = parameters["quantity"].as<std::string>();
  if (!parameters.contains("quantity_symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'quantity_symbol'");
  std::string quantity_symbol = parameters["quantity_symbol"].as<std::string>();
  if (!parameters.contains("cover_id"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'cover_id'");
  fbtc::blockchain::order_id_type cover_id = parameters["cover_id"].as<fbtc::blockchain::order_id_type>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_market_cover(from_account_name, quantity, quantity_symbol, cover_id);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_market_batch_update_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (cancel_order_ids)");
  std::vector<fbtc::blockchain::order_id_type> cancel_order_ids = parameters[0].as<std::vector<fbtc::blockchain::order_id_type>>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (new_orders)");
  std::vector<fbtc::wallet::order_description> new_orders = parameters[1].as<std::vector<fbtc::wallet::order_description>>();
  if (parameters.size() <= 2)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 3 (sign)");
  bool sign = parameters[2].as<bool>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_market_batch_update(cancel_order_ids, new_orders, sign);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_market_batch_update_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("cancel_order_ids"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'cancel_order_ids'");
  std::vector<fbtc::blockchain::order_id_type> cancel_order_ids = parameters["cancel_order_ids"].as<std::vector<fbtc::blockchain::order_id_type>>();
  if (!parameters.contains("new_orders"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'new_orders'");
  std::vector<fbtc::wallet::order_description> new_orders = parameters["new_orders"].as<std::vector<fbtc::wallet::order_description>>();
  if (!parameters.contains("sign"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'sign'");
  bool sign = parameters["sign"].as<bool>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_market_batch_update(cancel_order_ids, new_orders, sign);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_market_add_collateral_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (from_account_name)");
  std::string from_account_name = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (cover_id)");
  fbtc::blockchain::order_id_type cover_id = parameters[1].as<fbtc::blockchain::order_id_type>();
  if (parameters.size() <= 2)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 3 (real_quantity_collateral_to_add)");
  std::string real_quantity_collateral_to_add = parameters[2].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_market_add_collateral(from_account_name, cover_id, real_quantity_collateral_to_add);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_market_add_collateral_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("from_account_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'from_account_name'");
  std::string from_account_name = parameters["from_account_name"].as<std::string>();
  if (!parameters.contains("cover_id"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'cover_id'");
  fbtc::blockchain::order_id_type cover_id = parameters["cover_id"].as<fbtc::blockchain::order_id_type>();
  if (!parameters.contains("real_quantity_collateral_to_add"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'real_quantity_collateral_to_add'");
  std::string real_quantity_collateral_to_add = parameters["real_quantity_collateral_to_add"].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_market_add_collateral(from_account_name, cover_id, real_quantity_collateral_to_add);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_market_order_list_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (base_symbol)");
  std::string base_symbol = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (quote_symbol)");
  std::string quote_symbol = parameters[1].as<std::string>();
  uint32_t limit = (parameters.size() <= 2) ?
    (fc::json::from_string("-1").as<uint32_t>()) :
    parameters[2].as<uint32_t>();
  std::string account_name = (parameters.size() <= 3) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[3].as<std::string>();

  std::map<fbtc::blockchain::order_id_type, fbtc::blockchain::market_order> result = get_client()->wallet_market_order_list(base_symbol, quote_symbol, limit, account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_market_order_list_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (!parameters.contains("base_symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'base_symbol'");
  std::string base_symbol = parameters["base_symbol"].as<std::string>();
  if (!parameters.contains("quote_symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'quote_symbol'");
  std::string quote_symbol = parameters["quote_symbol"].as<std::string>();
  uint32_t limit = parameters.contains("limit") ? 
    (fc::json::from_string("-1").as<uint32_t>()) :
    parameters["limit"].as<uint32_t>();
  std::string account_name = parameters.contains("account_name") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["account_name"].as<std::string>();

  std::map<fbtc::blockchain::order_id_type, fbtc::blockchain::market_order> result = get_client()->wallet_market_order_list(base_symbol, quote_symbol, limit, account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_account_order_list_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  std::string account_name = (parameters.size() <= 0) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[0].as<std::string>();
  uint32_t limit = (parameters.size() <= 1) ?
    (fc::json::from_string("-1").as<uint32_t>()) :
    parameters[1].as<uint32_t>();

  std::map<fbtc::blockchain::order_id_type, fbtc::blockchain::market_order> result = get_client()->wallet_account_order_list(account_name, limit);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_account_order_list_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  std::string account_name = parameters.contains("account_name") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["account_name"].as<std::string>();
  uint32_t limit = parameters.contains("limit") ? 
    (fc::json::from_string("-1").as<uint32_t>()) :
    parameters["limit"].as<uint32_t>();

  std::map<fbtc::blockchain::order_id_type, fbtc::blockchain::market_order> result = get_client()->wallet_account_order_list(account_name, limit);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_market_cancel_order_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (order_id)");
  fbtc::blockchain::order_id_type order_id = parameters[0].as<fbtc::blockchain::order_id_type>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_market_cancel_order(order_id);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_market_cancel_order_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("order_id"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'order_id'");
  fbtc::blockchain::order_id_type order_id = parameters["order_id"].as<fbtc::blockchain::order_id_type>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_market_cancel_order(order_id);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_market_cancel_orders_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (order_ids)");
  std::vector<fbtc::blockchain::order_id_type> order_ids = parameters[0].as<std::vector<fbtc::blockchain::order_id_type>>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_market_cancel_orders(order_ids);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_market_cancel_orders_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("order_ids"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'order_ids'");
  std::vector<fbtc::blockchain::order_id_type> order_ids = parameters["order_ids"].as<std::vector<fbtc::blockchain::order_id_type>>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_market_cancel_orders(order_ids);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_dump_private_key_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (input)");
  std::string input = parameters[0].as<std::string>();

  fc::optional<std::string> result = get_client()->wallet_dump_private_key(input);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_dump_private_key_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("input"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'input'");
  std::string input = parameters["input"].as<std::string>();

  fc::optional<std::string> result = get_client()->wallet_dump_private_key(input);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_dump_account_private_key_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (account_name)");
  std::string account_name = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (key_type)");
  fbtc::wallet::account_key_type key_type = parameters[1].as<fbtc::wallet::account_key_type>();

  fc::optional<std::string> result = get_client()->wallet_dump_account_private_key(account_name, key_type);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_dump_account_private_key_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("account_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'account_name'");
  std::string account_name = parameters["account_name"].as<std::string>();
  if (!parameters.contains("key_type"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'key_type'");
  fbtc::wallet::account_key_type key_type = parameters["key_type"].as<fbtc::wallet::account_key_type>();

  fc::optional<std::string> result = get_client()->wallet_dump_account_private_key(account_name, key_type);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_account_vote_summary_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  std::string account_name = (parameters.size() <= 0) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[0].as<std::string>();

  fbtc::wallet::account_vote_summary_type result = get_client()->wallet_account_vote_summary(account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_account_vote_summary_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  std::string account_name = parameters.contains("account_name") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["account_name"].as<std::string>();

  fbtc::wallet::account_vote_summary_type result = get_client()->wallet_account_vote_summary(account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_set_setting_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (name)");
  std::string name = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (value)");
  fc::variant value = parameters[1].as<fc::variant>();

  get_client()->wallet_set_setting(name, value);
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_set_setting_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (!parameters.contains("name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'name'");
  std::string name = parameters["name"].as<std::string>();
  if (!parameters.contains("value"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'value'");
  fc::variant value = parameters["value"].as<fc::variant>();

  get_client()->wallet_set_setting(name, value);
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_get_setting_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (name)");
  std::string name = parameters[0].as<std::string>();

  fc::optional<fc::variant> result = get_client()->wallet_get_setting(name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_get_setting_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (!parameters.contains("name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'name'");
  std::string name = parameters["name"].as<std::string>();

  fc::optional<fc::variant> result = get_client()->wallet_get_setting(name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_delegate_set_block_production_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (delegate_name)");
  std::string delegate_name = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (enabled)");
  bool enabled = parameters[1].as<bool>();

  get_client()->wallet_delegate_set_block_production(delegate_name, enabled);
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_delegate_set_block_production_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (!parameters.contains("delegate_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'delegate_name'");
  std::string delegate_name = parameters["delegate_name"].as<std::string>();
  if (!parameters.contains("enabled"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'enabled'");
  bool enabled = parameters["enabled"].as<bool>();

  get_client()->wallet_delegate_set_block_production(delegate_name, enabled);
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_set_transaction_scanning_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (enabled)");
  bool enabled = parameters[0].as<bool>();

  bool result = get_client()->wallet_set_transaction_scanning(enabled);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_set_transaction_scanning_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (!parameters.contains("enabled"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'enabled'");
  bool enabled = parameters["enabled"].as<bool>();

  bool result = get_client()->wallet_set_transaction_scanning(enabled);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_sign_hash_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (signer)");
  std::string signer = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (hash)");
  fc::sha256 hash = parameters[1].as<fc::sha256>();

  fc::ecc::compact_signature result = get_client()->wallet_sign_hash(signer, hash);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_sign_hash_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("signer"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'signer'");
  std::string signer = parameters["signer"].as<std::string>();
  if (!parameters.contains("hash"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'hash'");
  fc::sha256 hash = parameters["hash"].as<fc::sha256>();

  fc::ecc::compact_signature result = get_client()->wallet_sign_hash(signer, hash);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_login_start_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (server_account)");
  std::string server_account = parameters[0].as<std::string>();

  std::string result = get_client()->wallet_login_start(server_account);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_login_start_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("server_account"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'server_account'");
  std::string server_account = parameters["server_account"].as<std::string>();

  std::string result = get_client()->wallet_login_start(server_account);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_login_finish_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (server_key)");
  fbtc::blockchain::public_key_type server_key = parameters[0].as<fbtc::blockchain::public_key_type>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (client_key)");
  fbtc::blockchain::public_key_type client_key = parameters[1].as<fbtc::blockchain::public_key_type>();
  if (parameters.size() <= 2)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 3 (client_signature)");
  fc::ecc::compact_signature client_signature = parameters[2].as<fc::ecc::compact_signature>();

  fc::variant result = get_client()->wallet_login_finish(server_key, client_key, client_signature);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_login_finish_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("server_key"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'server_key'");
  fbtc::blockchain::public_key_type server_key = parameters["server_key"].as<fbtc::blockchain::public_key_type>();
  if (!parameters.contains("client_key"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'client_key'");
  fbtc::blockchain::public_key_type client_key = parameters["client_key"].as<fbtc::blockchain::public_key_type>();
  if (!parameters.contains("client_signature"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'client_signature'");
  fc::ecc::compact_signature client_signature = parameters["client_signature"].as<fc::ecc::compact_signature>();

  fc::variant result = get_client()->wallet_login_finish(server_key, client_key, client_signature);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_balance_set_vote_info_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (balance_id)");
  fbtc::blockchain::address balance_id = parameters[0].as<fbtc::blockchain::address>();
  std::string voter_address = (parameters.size() <= 1) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[1].as<std::string>();
  fbtc::wallet::vote_strategy strategy = (parameters.size() <= 2) ?
    (fc::json::from_string("\"vote_all\"").as<fbtc::wallet::vote_strategy>()) :
    parameters[2].as<fbtc::wallet::vote_strategy>();
  bool sign_and_broadcast = (parameters.size() <= 3) ?
    (fc::json::from_string("\"true\"").as<bool>()) :
    parameters[3].as<bool>();
  std::string builder_path = (parameters.size() <= 4) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[4].as<std::string>();

  fbtc::wallet::transaction_builder result = get_client()->wallet_balance_set_vote_info(balance_id, voter_address, strategy, sign_and_broadcast, builder_path);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_balance_set_vote_info_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  // done checking prerequisites

  if (!parameters.contains("balance_id"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'balance_id'");
  fbtc::blockchain::address balance_id = parameters["balance_id"].as<fbtc::blockchain::address>();
  std::string voter_address = parameters.contains("voter_address") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["voter_address"].as<std::string>();
  fbtc::wallet::vote_strategy strategy = parameters.contains("strategy") ? 
    (fc::json::from_string("\"vote_all\"").as<fbtc::wallet::vote_strategy>()) :
    parameters["strategy"].as<fbtc::wallet::vote_strategy>();
  bool sign_and_broadcast = parameters.contains("sign_and_broadcast") ? 
    (fc::json::from_string("\"true\"").as<bool>()) :
    parameters["sign_and_broadcast"].as<bool>();
  std::string builder_path = parameters.contains("builder_path") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["builder_path"].as<std::string>();

  fbtc::wallet::transaction_builder result = get_client()->wallet_balance_set_vote_info(balance_id, voter_address, strategy, sign_and_broadcast, builder_path);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_publish_slate_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (publishing_account_name)");
  std::string publishing_account_name = parameters[0].as<std::string>();
  std::string paying_account_name = (parameters.size() <= 1) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[1].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_publish_slate(publishing_account_name, paying_account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_publish_slate_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("publishing_account_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'publishing_account_name'");
  std::string publishing_account_name = parameters["publishing_account_name"].as<std::string>();
  std::string paying_account_name = parameters.contains("paying_account_name") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["paying_account_name"].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_publish_slate(publishing_account_name, paying_account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_publish_version_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (publishing_account_name)");
  std::string publishing_account_name = parameters[0].as<std::string>();
  std::string paying_account_name = (parameters.size() <= 1) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[1].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_publish_version(publishing_account_name, paying_account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_publish_version_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("publishing_account_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'publishing_account_name'");
  std::string publishing_account_name = parameters["publishing_account_name"].as<std::string>();
  std::string paying_account_name = parameters.contains("paying_account_name") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["paying_account_name"].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_publish_version(publishing_account_name, paying_account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_collect_genesis_balances_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (account_name)");
  std::string account_name = parameters[0].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_collect_genesis_balances(account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_collect_genesis_balances_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("account_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'account_name'");
  std::string account_name = parameters["account_name"].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_collect_genesis_balances(account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_collect_vested_balances_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (account_name)");
  std::string account_name = parameters[0].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_collect_vested_balances(account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_collect_vested_balances_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("account_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'account_name'");
  std::string account_name = parameters["account_name"].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_collect_vested_balances(account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_delegate_update_signing_key_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (authorizing_account_name)");
  std::string authorizing_account_name = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (delegate_name)");
  std::string delegate_name = parameters[1].as<std::string>();
  if (parameters.size() <= 2)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 3 (signing_key)");
  fbtc::blockchain::public_key_type signing_key = parameters[2].as<fbtc::blockchain::public_key_type>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_delegate_update_signing_key(authorizing_account_name, delegate_name, signing_key);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_delegate_update_signing_key_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("authorizing_account_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'authorizing_account_name'");
  std::string authorizing_account_name = parameters["authorizing_account_name"].as<std::string>();
  if (!parameters.contains("delegate_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'delegate_name'");
  std::string delegate_name = parameters["delegate_name"].as<std::string>();
  if (!parameters.contains("signing_key"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'signing_key'");
  fbtc::blockchain::public_key_type signing_key = parameters["signing_key"].as<fbtc::blockchain::public_key_type>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_delegate_update_signing_key(authorizing_account_name, delegate_name, signing_key);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_recover_accounts_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (accounts_to_recover)");
  int32_t accounts_to_recover = parameters[0].as<int32_t>();
  int32_t maximum_number_of_attempts = (parameters.size() <= 1) ?
    (fc::json::from_string("1000").as<int32_t>()) :
    parameters[1].as<int32_t>();

  int32_t result = get_client()->wallet_recover_accounts(accounts_to_recover, maximum_number_of_attempts);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_recover_accounts_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("accounts_to_recover"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'accounts_to_recover'");
  int32_t accounts_to_recover = parameters["accounts_to_recover"].as<int32_t>();
  int32_t maximum_number_of_attempts = parameters.contains("maximum_number_of_attempts") ? 
    (fc::json::from_string("1000").as<int32_t>()) :
    parameters["maximum_number_of_attempts"].as<int32_t>();

  int32_t result = get_client()->wallet_recover_accounts(accounts_to_recover, maximum_number_of_attempts);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_recover_titan_deposit_info_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (transaction_id_prefix)");
  std::string transaction_id_prefix = parameters[0].as<std::string>();
  std::string recipient_account = (parameters.size() <= 1) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[1].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_recover_titan_deposit_info(transaction_id_prefix, recipient_account);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_recover_titan_deposit_info_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("transaction_id_prefix"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'transaction_id_prefix'");
  std::string transaction_id_prefix = parameters["transaction_id_prefix"].as<std::string>();
  std::string recipient_account = parameters.contains("recipient_account") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["recipient_account"].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_recover_titan_deposit_info(transaction_id_prefix, recipient_account);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_verify_titan_deposit_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (transaction_id_prefix)");
  std::string transaction_id_prefix = parameters[0].as<std::string>();

  fc::optional<fc::variant_object> result = get_client()->wallet_verify_titan_deposit(transaction_id_prefix);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_verify_titan_deposit_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("transaction_id_prefix"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'transaction_id_prefix'");
  std::string transaction_id_prefix = parameters["transaction_id_prefix"].as<std::string>();

  fc::optional<fc::variant_object> result = get_client()->wallet_verify_titan_deposit(transaction_id_prefix);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_publish_price_feed_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (delegate_account)");
  std::string delegate_account = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (price)");
  std::string price = parameters[1].as<std::string>();
  if (parameters.size() <= 2)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 3 (asset_symbol)");
  std::string asset_symbol = parameters[2].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_publish_price_feed(delegate_account, price, asset_symbol);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_publish_price_feed_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("delegate_account"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'delegate_account'");
  std::string delegate_account = parameters["delegate_account"].as<std::string>();
  if (!parameters.contains("price"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'price'");
  std::string price = parameters["price"].as<std::string>();
  if (!parameters.contains("asset_symbol"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'asset_symbol'");
  std::string asset_symbol = parameters["asset_symbol"].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_publish_price_feed(delegate_account, price, asset_symbol);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_publish_feeds_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (delegate_account)");
  std::string delegate_account = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (symbol_to_price_map)");
  std::map<std::string, std::string> symbol_to_price_map = parameters[1].as<std::map<std::string, std::string>>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_publish_feeds(delegate_account, symbol_to_price_map);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_publish_feeds_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("delegate_account"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'delegate_account'");
  std::string delegate_account = parameters["delegate_account"].as<std::string>();
  if (!parameters.contains("symbol_to_price_map"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'symbol_to_price_map'");
  std::map<std::string, std::string> symbol_to_price_map = parameters["symbol_to_price_map"].as<std::map<std::string, std::string>>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_publish_feeds(delegate_account, symbol_to_price_map);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_publish_feeds_multi_experimental_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (symbol_to_price_map)");
  std::map<std::string, std::string> symbol_to_price_map = parameters[0].as<std::map<std::string, std::string>>();

  std::vector<std::pair<std::string, fbtc::wallet::wallet_transaction_record>> result = get_client()->wallet_publish_feeds_multi_experimental(symbol_to_price_map);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_publish_feeds_multi_experimental_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("symbol_to_price_map"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'symbol_to_price_map'");
  std::map<std::string, std::string> symbol_to_price_map = parameters["symbol_to_price_map"].as<std::map<std::string, std::string>>();

  std::vector<std::pair<std::string, fbtc::wallet::wallet_transaction_record>> result = get_client()->wallet_publish_feeds_multi_experimental(symbol_to_price_map);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_repair_records_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  std::string collecting_account_name = (parameters.size() <= 0) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[0].as<std::string>();

  get_client()->wallet_repair_records(collecting_account_name);
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_repair_records_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  std::string collecting_account_name = parameters.contains("collecting_account_name") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["collecting_account_name"].as<std::string>();

  get_client()->wallet_repair_records(collecting_account_name);
  return fc::variant();
}

fc::variant common_api_rpc_server::wallet_regenerate_keys_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (account_name)");
  std::string account_name = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (max_key_number)");
  uint32_t max_key_number = parameters[1].as<uint32_t>();

  int32_t result = get_client()->wallet_regenerate_keys(account_name, max_key_number);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_regenerate_keys_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("account_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'account_name'");
  std::string account_name = parameters["account_name"].as<std::string>();
  if (!parameters.contains("max_key_number"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'max_key_number'");
  uint32_t max_key_number = parameters["max_key_number"].as<uint32_t>();

  int32_t result = get_client()->wallet_regenerate_keys(account_name, max_key_number);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_account_retract_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (account_to_retract)");
  std::string account_to_retract = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (pay_from_account)");
  std::string pay_from_account = parameters[1].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_account_retract(account_to_retract, pay_from_account);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_account_retract_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("account_to_retract"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'account_to_retract'");
  std::string account_to_retract = parameters["account_to_retract"].as<std::string>();
  if (!parameters.contains("pay_from_account"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'pay_from_account'");
  std::string pay_from_account = parameters["pay_from_account"].as<std::string>();

  fbtc::wallet::wallet_transaction_record result = get_client()->wallet_account_retract(account_to_retract, pay_from_account);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_generate_brain_seed_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites


  std::string result = get_client()->wallet_generate_brain_seed();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::wallet_generate_brain_seed_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites


  std::string result = get_client()->wallet_generate_brain_seed();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::fetch_welcome_package_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (arguments)");
  fc::variant_object arguments = parameters[0].as<fc::variant_object>();

  fc::variant_object result = get_client()->fetch_welcome_package(arguments);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::fetch_welcome_package_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("arguments"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'arguments'");
  fc::variant_object arguments = parameters["arguments"].as<fc::variant_object>();

  fc::variant_object result = get_client()->fetch_welcome_package(arguments);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::request_register_account_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (account)");
  fbtc::blockchain::account_record account = parameters[0].as<fbtc::blockchain::account_record>();

  bool result = get_client()->request_register_account(account);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::request_register_account_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("account"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'account'");
  fbtc::blockchain::account_record account = parameters["account"].as<fbtc::blockchain::account_record>();

  bool result = get_client()->request_register_account(account);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::approve_register_account_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (account_salt)");
  std::string account_salt = parameters[0].as<std::string>();
  if (parameters.size() <= 1)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 2 (paying_account_name)");
  std::string paying_account_name = parameters[1].as<std::string>();

  bool result = get_client()->approve_register_account(account_salt, paying_account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::approve_register_account_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  if (!parameters.contains("account_salt"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'account_salt'");
  std::string account_salt = parameters["account_salt"].as<std::string>();
  if (!parameters.contains("paying_account_name"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'paying_account_name'");
  std::string paying_account_name = parameters["paying_account_name"].as<std::string>();

  bool result = get_client()->approve_register_account(account_salt, paying_account_name);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::debug_start_simulated_time_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (new_simulated_time)");
  fc::time_point new_simulated_time = parameters[0].as<fc::time_point>();

  get_client()->debug_start_simulated_time(new_simulated_time);
  return fc::variant();
}

fc::variant common_api_rpc_server::debug_start_simulated_time_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (!parameters.contains("new_simulated_time"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'new_simulated_time'");
  fc::time_point new_simulated_time = parameters["new_simulated_time"].as<fc::time_point>();

  get_client()->debug_start_simulated_time(new_simulated_time);
  return fc::variant();
}

fc::variant common_api_rpc_server::debug_advance_time_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (delta_time_seconds)");
  int32_t delta_time_seconds = parameters[0].as<int32_t>();
  std::string unit = (parameters.size() <= 1) ?
    (fc::json::from_string("\"seconds\"").as<std::string>()) :
    parameters[1].as<std::string>();

  get_client()->debug_advance_time(delta_time_seconds, unit);
  return fc::variant();
}

fc::variant common_api_rpc_server::debug_advance_time_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (!parameters.contains("delta_time_seconds"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'delta_time_seconds'");
  int32_t delta_time_seconds = parameters["delta_time_seconds"].as<int32_t>();
  std::string unit = parameters.contains("unit") ? 
    (fc::json::from_string("\"seconds\"").as<std::string>()) :
    parameters["unit"].as<std::string>();

  get_client()->debug_advance_time(delta_time_seconds, unit);
  return fc::variant();
}

fc::variant common_api_rpc_server::debug_trap_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (block_number)");
  uint32_t block_number = parameters[0].as<uint32_t>();

  get_client()->debug_trap(block_number);
  return fc::variant();
}

fc::variant common_api_rpc_server::debug_trap_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (!parameters.contains("block_number"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'block_number'");
  uint32_t block_number = parameters["block_number"].as<uint32_t>();

  get_client()->debug_trap(block_number);
  return fc::variant();
}

fc::variant common_api_rpc_server::debug_wait_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (wait_time)");
  uint32_t wait_time = parameters[0].as<uint32_t>();

  get_client()->debug_wait(wait_time);
  return fc::variant();
}

fc::variant common_api_rpc_server::debug_wait_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("wait_time"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'wait_time'");
  uint32_t wait_time = parameters["wait_time"].as<uint32_t>();

  get_client()->debug_wait(wait_time);
  return fc::variant();
}

fc::variant common_api_rpc_server::debug_wait_for_block_by_number_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (block_number)");
  uint32_t block_number = parameters[0].as<uint32_t>();
  std::string type = (parameters.size() <= 1) ?
    (fc::json::from_string("\"absolute\"").as<std::string>()) :
    parameters[1].as<std::string>();

  get_client()->debug_wait_for_block_by_number(block_number, type);
  return fc::variant();
}

fc::variant common_api_rpc_server::debug_wait_for_block_by_number_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (!parameters.contains("block_number"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'block_number'");
  uint32_t block_number = parameters["block_number"].as<uint32_t>();
  std::string type = parameters.contains("type") ? 
    (fc::json::from_string("\"absolute\"").as<std::string>()) :
    parameters["type"].as<std::string>();

  get_client()->debug_wait_for_block_by_number(block_number, type);
  return fc::variant();
}

fc::variant common_api_rpc_server::debug_wait_block_interval_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (wait_time_in_block_intervals)");
  uint32_t wait_time_in_block_intervals = parameters[0].as<uint32_t>();

  get_client()->debug_wait_block_interval(wait_time_in_block_intervals);
  return fc::variant();
}

fc::variant common_api_rpc_server::debug_wait_block_interval_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("wait_time_in_block_intervals"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'wait_time_in_block_intervals'");
  uint32_t wait_time_in_block_intervals = parameters["wait_time_in_block_intervals"].as<uint32_t>();

  get_client()->debug_wait_block_interval(wait_time_in_block_intervals);
  return fc::variant();
}

fc::variant common_api_rpc_server::debug_enable_output_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (enable_flag)");
  bool enable_flag = parameters[0].as<bool>();

  get_client()->debug_enable_output(enable_flag);
  return fc::variant();
}

fc::variant common_api_rpc_server::debug_enable_output_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("enable_flag"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'enable_flag'");
  bool enable_flag = parameters["enable_flag"].as<bool>();

  get_client()->debug_enable_output(enable_flag);
  return fc::variant();
}

fc::variant common_api_rpc_server::debug_filter_output_for_tests_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (enable_flag)");
  bool enable_flag = parameters[0].as<bool>();

  get_client()->debug_filter_output_for_tests(enable_flag);
  return fc::variant();
}

fc::variant common_api_rpc_server::debug_filter_output_for_tests_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("enable_flag"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'enable_flag'");
  bool enable_flag = parameters["enable_flag"].as<bool>();

  get_client()->debug_filter_output_for_tests(enable_flag);
  return fc::variant();
}

fc::variant common_api_rpc_server::debug_update_logging_config_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites


  get_client()->debug_update_logging_config();
  return fc::variant();
}

fc::variant common_api_rpc_server::debug_update_logging_config_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites


  get_client()->debug_update_logging_config();
  return fc::variant();
}

fc::variant common_api_rpc_server::debug_get_call_statistics_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites


  fc::variant_object result = get_client()->debug_get_call_statistics();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::debug_get_call_statistics_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites


  fc::variant_object result = get_client()->debug_get_call_statistics();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::debug_get_client_name_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites


  std::string result = get_client()->debug_get_client_name();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::debug_get_client_name_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites


  std::string result = get_client()->debug_get_client_name();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::debug_deterministic_private_keys_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  int32_t start = (parameters.size() <= 0) ?
    (fc::json::from_string("\"-1\"").as<int32_t>()) :
    parameters[0].as<int32_t>();
  int32_t count = (parameters.size() <= 1) ?
    (fc::json::from_string("\"1\"").as<int32_t>()) :
    parameters[1].as<int32_t>();
  std::string prefix = (parameters.size() <= 2) ?
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters[2].as<std::string>();
  bool import = (parameters.size() <= 3) ?
    (fc::json::from_string("\"false\"").as<bool>()) :
    parameters[3].as<bool>();
  std::string account_name = (parameters.size() <= 4) ?
    (fc::json::from_string("null").as<std::string>()) :
    parameters[4].as<std::string>();
  bool create_new_account = (parameters.size() <= 5) ?
    (fc::json::from_string("false").as<bool>()) :
    parameters[5].as<bool>();
  bool rescan = (parameters.size() <= 6) ?
    (fc::json::from_string("false").as<bool>()) :
    parameters[6].as<bool>();

  fc::variants result = get_client()->debug_deterministic_private_keys(start, count, prefix, import, account_name, create_new_account, rescan);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::debug_deterministic_private_keys_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  verify_wallet_is_open();
  verify_wallet_is_unlocked();
  // done checking prerequisites

  int32_t start = parameters.contains("start") ? 
    (fc::json::from_string("\"-1\"").as<int32_t>()) :
    parameters["start"].as<int32_t>();
  int32_t count = parameters.contains("count") ? 
    (fc::json::from_string("\"1\"").as<int32_t>()) :
    parameters["count"].as<int32_t>();
  std::string prefix = parameters.contains("prefix") ? 
    (fc::json::from_string("\"\"").as<std::string>()) :
    parameters["prefix"].as<std::string>();
  bool import = parameters.contains("import") ? 
    (fc::json::from_string("\"false\"").as<bool>()) :
    parameters["import"].as<bool>();
  std::string account_name = parameters.contains("account_name") ? 
    (fc::json::from_string("null").as<std::string>()) :
    parameters["account_name"].as<std::string>();
  bool create_new_account = parameters.contains("create_new_account") ? 
    (fc::json::from_string("false").as<bool>()) :
    parameters["create_new_account"].as<bool>();
  bool rescan = parameters.contains("rescan") ? 
    (fc::json::from_string("false").as<bool>()) :
    parameters["rescan"].as<bool>();

  fc::variants result = get_client()->debug_deterministic_private_keys(start, count, prefix, import, account_name, create_new_account, rescan);
  return fc::variant(result);
}

fc::variant common_api_rpc_server::debug_stop_before_block_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (block_number)");
  uint32_t block_number = parameters[0].as<uint32_t>();

  get_client()->debug_stop_before_block(block_number);
  return fc::variant();
}

fc::variant common_api_rpc_server::debug_stop_before_block_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // check all of this method's prerequisites
  verify_json_connection_is_authenticated(json_connection);
  // done checking prerequisites

  if (!parameters.contains("block_number"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'block_number'");
  uint32_t block_number = parameters["block_number"].as<uint32_t>();

  get_client()->debug_stop_before_block(block_number);
  return fc::variant();
}

fc::variant common_api_rpc_server::debug_verify_market_matching_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites

  if (parameters.size() <= 0)
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 1 (enable_flag)");
  bool enable_flag = parameters[0].as<bool>();

  get_client()->debug_verify_market_matching(enable_flag);
  return fc::variant();
}

fc::variant common_api_rpc_server::debug_verify_market_matching_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites

  if (!parameters.contains("enable_flag"))
    FC_THROW_EXCEPTION(fc::invalid_arg_exception, "missing required parameter 'enable_flag'");
  bool enable_flag = parameters["enable_flag"].as<bool>();

  get_client()->debug_verify_market_matching(enable_flag);
  return fc::variant();
}

fc::variant common_api_rpc_server::debug_list_matching_errors_positional(fc::rpc::json_connection* json_connection, const fc::variants& parameters)
{
  // this method has no prerequisites


  fc::variants result = get_client()->debug_list_matching_errors();
  return fc::variant(result);
}

fc::variant common_api_rpc_server::debug_list_matching_errors_named(fc::rpc::json_connection* json_connection, const fc::variant_object& parameters)
{
  // this method has no prerequisites


  fc::variants result = get_client()->debug_list_matching_errors();
  return fc::variant(result);
}

void common_api_rpc_server::register_common_api_methods(const fc::rpc::json_connection_ptr& json_connection)
{
  fc::rpc::json_connection::method bound_positional_method;
  fc::rpc::json_connection::named_param_method bound_named_method;
  auto capture_con = json_connection.get();
   // register method about
  bound_positional_method = boost::bind(&common_api_rpc_server::about_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("about", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::about_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("about", bound_named_method);

  // register method get_info
  bound_positional_method = boost::bind(&common_api_rpc_server::get_info_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("get_info", bound_positional_method);
  json_connection->add_method("getinfo", bound_positional_method);
  json_connection->add_method("info", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::get_info_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("get_info", bound_named_method);
  json_connection->add_named_param_method("getinfo", bound_named_method);
  json_connection->add_named_param_method("info", bound_named_method);

  // register method stop
  bound_positional_method = boost::bind(&common_api_rpc_server::stop_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("stop", bound_positional_method);
  json_connection->add_method("quit", bound_positional_method);
  json_connection->add_method("exit", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::stop_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("stop", bound_named_method);
  json_connection->add_named_param_method("quit", bound_named_method);
  json_connection->add_named_param_method("exit", bound_named_method);

  // register method help
  bound_positional_method = boost::bind(&common_api_rpc_server::help_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("help", bound_positional_method);
  json_connection->add_method("h", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::help_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("help", bound_named_method);
  json_connection->add_named_param_method("h", bound_named_method);

  // register method validate_address
  bound_positional_method = boost::bind(&common_api_rpc_server::validate_address_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("validate_address", bound_positional_method);
  json_connection->add_method("validateaddress", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::validate_address_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("validate_address", bound_named_method);
  json_connection->add_named_param_method("validateaddress", bound_named_method);

  // register method convert_to_native_address
  bound_positional_method = boost::bind(&common_api_rpc_server::convert_to_native_address_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("convert_to_native_address", bound_positional_method);
  json_connection->add_method("convertaddress", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::convert_to_native_address_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("convert_to_native_address", bound_named_method);
  json_connection->add_named_param_method("convertaddress", bound_named_method);

  // register method execute_command_line
  bound_positional_method = boost::bind(&common_api_rpc_server::execute_command_line_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("execute_command_line", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::execute_command_line_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("execute_command_line", bound_named_method);

  // register method execute_script
  bound_positional_method = boost::bind(&common_api_rpc_server::execute_script_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("execute_script", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::execute_script_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("execute_script", bound_named_method);

  // register method batch
  bound_positional_method = boost::bind(&common_api_rpc_server::batch_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("batch", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::batch_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("batch", bound_named_method);

  // register method batch_authenticated
  bound_positional_method = boost::bind(&common_api_rpc_server::batch_authenticated_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("batch_authenticated", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::batch_authenticated_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("batch_authenticated", bound_named_method);

  // register method builder_finalize_and_sign
  bound_positional_method = boost::bind(&common_api_rpc_server::builder_finalize_and_sign_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("builder_finalize_and_sign", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::builder_finalize_and_sign_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("builder_finalize_and_sign", bound_named_method);

  // register method meta_help
  bound_positional_method = boost::bind(&common_api_rpc_server::meta_help_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("meta_help", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::meta_help_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("meta_help", bound_named_method);

  // register method rpc_set_username
  bound_positional_method = boost::bind(&common_api_rpc_server::rpc_set_username_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("rpc_set_username", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::rpc_set_username_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("rpc_set_username", bound_named_method);

  // register method rpc_set_password
  bound_positional_method = boost::bind(&common_api_rpc_server::rpc_set_password_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("rpc_set_password", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::rpc_set_password_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("rpc_set_password", bound_named_method);

  // register method rpc_start_server
  bound_positional_method = boost::bind(&common_api_rpc_server::rpc_start_server_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("rpc_start_server", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::rpc_start_server_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("rpc_start_server", bound_named_method);

  // register method http_start_server
  bound_positional_method = boost::bind(&common_api_rpc_server::http_start_server_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("http_start_server", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::http_start_server_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("http_start_server", bound_named_method);

  // register method ntp_update_time
  bound_positional_method = boost::bind(&common_api_rpc_server::ntp_update_time_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("ntp_update_time", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::ntp_update_time_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("ntp_update_time", bound_named_method);

  // register method disk_usage
  bound_positional_method = boost::bind(&common_api_rpc_server::disk_usage_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("disk_usage", bound_positional_method);
  json_connection->add_method("size", bound_positional_method);
  json_connection->add_method("sizes", bound_positional_method);
  json_connection->add_method("usage", bound_positional_method);
  json_connection->add_method("diskusage", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::disk_usage_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("disk_usage", bound_named_method);
  json_connection->add_named_param_method("size", bound_named_method);
  json_connection->add_named_param_method("sizes", bound_named_method);
  json_connection->add_named_param_method("usage", bound_named_method);
  json_connection->add_named_param_method("diskusage", bound_named_method);

  // register method network_add_node
  bound_positional_method = boost::bind(&common_api_rpc_server::network_add_node_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("network_add_node", bound_positional_method);
  json_connection->add_method("addnode", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::network_add_node_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("network_add_node", bound_named_method);
  json_connection->add_named_param_method("addnode", bound_named_method);

  // register method network_get_connection_count
  bound_positional_method = boost::bind(&common_api_rpc_server::network_get_connection_count_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("network_get_connection_count", bound_positional_method);
  json_connection->add_method("getconnectioncount", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::network_get_connection_count_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("network_get_connection_count", bound_named_method);
  json_connection->add_named_param_method("getconnectioncount", bound_named_method);

  // register method network_get_peer_info
  bound_positional_method = boost::bind(&common_api_rpc_server::network_get_peer_info_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("network_get_peer_info", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::network_get_peer_info_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("network_get_peer_info", bound_named_method);

  // register method network_broadcast_transaction
  bound_positional_method = boost::bind(&common_api_rpc_server::network_broadcast_transaction_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("network_broadcast_transaction", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::network_broadcast_transaction_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("network_broadcast_transaction", bound_named_method);

  // register method network_set_advanced_node_parameters
  bound_positional_method = boost::bind(&common_api_rpc_server::network_set_advanced_node_parameters_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("network_set_advanced_node_parameters", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::network_set_advanced_node_parameters_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("network_set_advanced_node_parameters", bound_named_method);

  // register method network_get_advanced_node_parameters
  bound_positional_method = boost::bind(&common_api_rpc_server::network_get_advanced_node_parameters_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("network_get_advanced_node_parameters", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::network_get_advanced_node_parameters_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("network_get_advanced_node_parameters", bound_named_method);

  // register method network_get_transaction_propagation_data
  bound_positional_method = boost::bind(&common_api_rpc_server::network_get_transaction_propagation_data_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("network_get_transaction_propagation_data", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::network_get_transaction_propagation_data_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("network_get_transaction_propagation_data", bound_named_method);

  // register method network_get_block_propagation_data
  bound_positional_method = boost::bind(&common_api_rpc_server::network_get_block_propagation_data_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("network_get_block_propagation_data", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::network_get_block_propagation_data_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("network_get_block_propagation_data", bound_named_method);

  // register method network_set_allowed_peers
  bound_positional_method = boost::bind(&common_api_rpc_server::network_set_allowed_peers_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("network_set_allowed_peers", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::network_set_allowed_peers_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("network_set_allowed_peers", bound_named_method);

  // register method network_get_info
  bound_positional_method = boost::bind(&common_api_rpc_server::network_get_info_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("network_get_info", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::network_get_info_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("network_get_info", bound_named_method);

  // register method network_list_potential_peers
  bound_positional_method = boost::bind(&common_api_rpc_server::network_list_potential_peers_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("network_list_potential_peers", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::network_list_potential_peers_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("network_list_potential_peers", bound_named_method);

  // register method network_get_upnp_info
  bound_positional_method = boost::bind(&common_api_rpc_server::network_get_upnp_info_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("network_get_upnp_info", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::network_get_upnp_info_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("network_get_upnp_info", bound_named_method);

  // register method network_get_usage_stats
  bound_positional_method = boost::bind(&common_api_rpc_server::network_get_usage_stats_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("network_get_usage_stats", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::network_get_usage_stats_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("network_get_usage_stats", bound_named_method);

  // register method delegate_get_config
  bound_positional_method = boost::bind(&common_api_rpc_server::delegate_get_config_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("delegate_get_config", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::delegate_get_config_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("delegate_get_config", bound_named_method);

  // register method delegate_set_network_min_connection_count
  bound_positional_method = boost::bind(&common_api_rpc_server::delegate_set_network_min_connection_count_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("delegate_set_network_min_connection_count", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::delegate_set_network_min_connection_count_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("delegate_set_network_min_connection_count", bound_named_method);

  // register method delegate_set_block_max_transaction_count
  bound_positional_method = boost::bind(&common_api_rpc_server::delegate_set_block_max_transaction_count_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("delegate_set_block_max_transaction_count", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::delegate_set_block_max_transaction_count_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("delegate_set_block_max_transaction_count", bound_named_method);

  // register method delegate_set_block_max_size
  bound_positional_method = boost::bind(&common_api_rpc_server::delegate_set_block_max_size_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("delegate_set_block_max_size", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::delegate_set_block_max_size_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("delegate_set_block_max_size", bound_named_method);

  // register method delegate_set_block_max_production_time
  bound_positional_method = boost::bind(&common_api_rpc_server::delegate_set_block_max_production_time_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("delegate_set_block_max_production_time", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::delegate_set_block_max_production_time_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("delegate_set_block_max_production_time", bound_named_method);

  // register method delegate_set_transaction_max_size
  bound_positional_method = boost::bind(&common_api_rpc_server::delegate_set_transaction_max_size_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("delegate_set_transaction_max_size", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::delegate_set_transaction_max_size_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("delegate_set_transaction_max_size", bound_named_method);

  // register method delegate_set_transaction_canonical_signatures_required
  bound_positional_method = boost::bind(&common_api_rpc_server::delegate_set_transaction_canonical_signatures_required_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("delegate_set_transaction_canonical_signatures_required", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::delegate_set_transaction_canonical_signatures_required_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("delegate_set_transaction_canonical_signatures_required", bound_named_method);

  // register method delegate_set_transaction_min_fee
  bound_positional_method = boost::bind(&common_api_rpc_server::delegate_set_transaction_min_fee_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("delegate_set_transaction_min_fee", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::delegate_set_transaction_min_fee_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("delegate_set_transaction_min_fee", bound_named_method);

  // register method delegate_blacklist_add_transaction
  bound_positional_method = boost::bind(&common_api_rpc_server::delegate_blacklist_add_transaction_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("delegate_blacklist_add_transaction", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::delegate_blacklist_add_transaction_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("delegate_blacklist_add_transaction", bound_named_method);

  // register method delegate_blacklist_remove_transaction
  bound_positional_method = boost::bind(&common_api_rpc_server::delegate_blacklist_remove_transaction_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("delegate_blacklist_remove_transaction", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::delegate_blacklist_remove_transaction_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("delegate_blacklist_remove_transaction", bound_named_method);

  // register method delegate_blacklist_add_operation
  bound_positional_method = boost::bind(&common_api_rpc_server::delegate_blacklist_add_operation_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("delegate_blacklist_add_operation", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::delegate_blacklist_add_operation_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("delegate_blacklist_add_operation", bound_named_method);

  // register method delegate_blacklist_remove_operation
  bound_positional_method = boost::bind(&common_api_rpc_server::delegate_blacklist_remove_operation_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("delegate_blacklist_remove_operation", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::delegate_blacklist_remove_operation_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("delegate_blacklist_remove_operation", bound_named_method);

  // register method blockchain_get_info
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_get_info_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_get_info", bound_positional_method);
  json_connection->add_method("getconfig", bound_positional_method);
  json_connection->add_method("get_config", bound_positional_method);
  json_connection->add_method("config", bound_positional_method);
  json_connection->add_method("blockchain_get_config", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_get_info_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_get_info", bound_named_method);
  json_connection->add_named_param_method("getconfig", bound_named_method);
  json_connection->add_named_param_method("get_config", bound_named_method);
  json_connection->add_named_param_method("config", bound_named_method);
  json_connection->add_named_param_method("blockchain_get_config", bound_named_method);

  // register method blockchain_generate_snapshot
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_generate_snapshot_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_generate_snapshot", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_generate_snapshot_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_generate_snapshot", bound_named_method);

  // register method blockchain_graphene_snapshot
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_graphene_snapshot_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_graphene_snapshot", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_graphene_snapshot_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_graphene_snapshot", bound_named_method);

  // register method blockchain_generate_issuance_map
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_generate_issuance_map_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_generate_issuance_map", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_generate_issuance_map_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_generate_issuance_map", bound_named_method);

  // register method blockchain_calculate_supply
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_calculate_supply_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_calculate_supply", bound_positional_method);
  json_connection->add_method("supply", bound_positional_method);
  json_connection->add_method("calculate_supply", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_calculate_supply_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_calculate_supply", bound_named_method);
  json_connection->add_named_param_method("supply", bound_named_method);
  json_connection->add_named_param_method("calculate_supply", bound_named_method);

  // register method blockchain_calculate_debt
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_calculate_debt_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_calculate_debt", bound_positional_method);
  json_connection->add_method("debt", bound_positional_method);
  json_connection->add_method("calculate_debt", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_calculate_debt_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_calculate_debt", bound_named_method);
  json_connection->add_named_param_method("debt", bound_named_method);
  json_connection->add_named_param_method("calculate_debt", bound_named_method);

  // register method blockchain_calculate_max_supply
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_calculate_max_supply_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_calculate_max_supply", bound_positional_method);
  json_connection->add_method("max_supply", bound_positional_method);
  json_connection->add_method("calculate_max_supply", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_calculate_max_supply_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_calculate_max_supply", bound_named_method);
  json_connection->add_named_param_method("max_supply", bound_named_method);
  json_connection->add_named_param_method("calculate_max_supply", bound_named_method);

  // register method blockchain_get_block_count
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_get_block_count_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_get_block_count", bound_positional_method);
  json_connection->add_method("blockchain_get_blockcount", bound_positional_method);
  json_connection->add_method("getblockcount", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_get_block_count_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_get_block_count", bound_named_method);
  json_connection->add_named_param_method("blockchain_get_blockcount", bound_named_method);
  json_connection->add_named_param_method("getblockcount", bound_named_method);

  // register method blockchain_list_accounts
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_list_accounts_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_list_accounts", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_list_accounts_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_list_accounts", bound_named_method);

  // register method blockchain_list_recently_updated_accounts
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_list_recently_updated_accounts_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_list_recently_updated_accounts", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_list_recently_updated_accounts_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_list_recently_updated_accounts", bound_named_method);

  // register method blockchain_list_recently_registered_accounts
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_list_recently_registered_accounts_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_list_recently_registered_accounts", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_list_recently_registered_accounts_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_list_recently_registered_accounts", bound_named_method);

  // register method blockchain_list_assets
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_list_assets_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_list_assets", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_list_assets_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_list_assets", bound_named_method);

  // register method blockchain_list_feed_prices
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_list_feed_prices_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_list_feed_prices", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_list_feed_prices_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_list_feed_prices", bound_named_method);

  // register method blockchain_get_account_wall
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_get_account_wall_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_get_account_wall", bound_positional_method);
  json_connection->add_method("wall", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_get_account_wall_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_get_account_wall", bound_named_method);
  json_connection->add_named_param_method("wall", bound_named_method);

  // register method blockchain_list_pending_transactions
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_list_pending_transactions_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_list_pending_transactions", bound_positional_method);
  json_connection->add_method("blockchain_get_pending_transactions", bound_positional_method);
  json_connection->add_method("list_pending", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_list_pending_transactions_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_list_pending_transactions", bound_named_method);
  json_connection->add_named_param_method("blockchain_get_pending_transactions", bound_named_method);
  json_connection->add_named_param_method("list_pending", bound_named_method);

  // register method blockchain_get_pending_transactions_count
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_get_pending_transactions_count_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_get_pending_transactions_count", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_get_pending_transactions_count_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_get_pending_transactions_count", bound_named_method);

  // register method blockchain_get_transaction
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_get_transaction_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_get_transaction", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_get_transaction_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_get_transaction", bound_named_method);

  // register method blockchain_get_block
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_get_block_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_get_block", bound_positional_method);
  json_connection->add_method("get_block", bound_positional_method);
  json_connection->add_method("getblock", bound_positional_method);
  json_connection->add_method("blockchain_get_block_hash", bound_positional_method);
  json_connection->add_method("blockchain_get_blockhash", bound_positional_method);
  json_connection->add_method("getblockhash", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_get_block_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_get_block", bound_named_method);
  json_connection->add_named_param_method("get_block", bound_named_method);
  json_connection->add_named_param_method("getblock", bound_named_method);
  json_connection->add_named_param_method("blockchain_get_block_hash", bound_named_method);
  json_connection->add_named_param_method("blockchain_get_blockhash", bound_named_method);
  json_connection->add_named_param_method("getblockhash", bound_named_method);

  // register method blockchain_get_block_transactions
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_get_block_transactions_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_get_block_transactions", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_get_block_transactions_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_get_block_transactions", bound_named_method);

  // register method blockchain_get_account
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_get_account_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_get_account", bound_positional_method);
  json_connection->add_method("get_account", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_get_account_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_get_account", bound_named_method);
  json_connection->add_named_param_method("get_account", bound_named_method);

  // register method blockchain_get_slate
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_get_slate_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_get_slate", bound_positional_method);
  json_connection->add_method("get_slate", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_get_slate_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_get_slate", bound_named_method);
  json_connection->add_named_param_method("get_slate", bound_named_method);

  // register method blockchain_get_balance
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_get_balance_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_get_balance", bound_positional_method);
  json_connection->add_method("get_balance", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_get_balance_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_get_balance", bound_named_method);
  json_connection->add_named_param_method("get_balance", bound_named_method);

  // register method blockchain_list_balances
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_list_balances_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_list_balances", bound_positional_method);
  json_connection->add_method("list_balances", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_list_balances_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_list_balances", bound_named_method);
  json_connection->add_named_param_method("list_balances", bound_named_method);

  // register method blockchain_list_address_balances
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_list_address_balances_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_list_address_balances", bound_positional_method);
  json_connection->add_method("list_address_balances", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_list_address_balances_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_list_address_balances", bound_named_method);
  json_connection->add_named_param_method("list_address_balances", bound_named_method);

  // register method blockchain_list_address_transactions
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_list_address_transactions_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_list_address_transactions", bound_positional_method);
  json_connection->add_method("list_address_transactions", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_list_address_transactions_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_list_address_transactions", bound_named_method);
  json_connection->add_named_param_method("list_address_transactions", bound_named_method);

  // register method blockchain_get_account_public_balance
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_get_account_public_balance_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_get_account_public_balance", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_get_account_public_balance_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_get_account_public_balance", bound_named_method);

  // register method blockchain_median_feed_price
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_median_feed_price_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_median_feed_price", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_median_feed_price_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_median_feed_price", bound_named_method);

  // register method blockchain_list_key_balances
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_list_key_balances_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_list_key_balances", bound_positional_method);
  json_connection->add_method("list_key_balances", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_list_key_balances_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_list_key_balances", bound_named_method);
  json_connection->add_named_param_method("list_key_balances", bound_named_method);

  // register method blockchain_get_asset
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_get_asset_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_get_asset", bound_positional_method);
  json_connection->add_method("get_asset", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_get_asset_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_get_asset", bound_named_method);
  json_connection->add_named_param_method("get_asset", bound_named_method);

  // register method blockchain_get_feeds_for_asset
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_get_feeds_for_asset_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_get_feeds_for_asset", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_get_feeds_for_asset_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_get_feeds_for_asset", bound_named_method);

  // register method blockchain_get_feeds_from_delegate
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_get_feeds_from_delegate_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_get_feeds_from_delegate", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_get_feeds_from_delegate_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_get_feeds_from_delegate", bound_named_method);

  // register method blockchain_market_list_bids
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_market_list_bids_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_market_list_bids", bound_positional_method);
  json_connection->add_method("market_bids", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_market_list_bids_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_market_list_bids", bound_named_method);
  json_connection->add_named_param_method("market_bids", bound_named_method);

  // register method blockchain_market_list_asks
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_market_list_asks_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_market_list_asks", bound_positional_method);
  json_connection->add_method("market_asks", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_market_list_asks_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_market_list_asks", bound_named_method);
  json_connection->add_named_param_method("market_asks", bound_named_method);

  // register method blockchain_market_list_shorts
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_market_list_shorts_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_market_list_shorts", bound_positional_method);
  json_connection->add_method("market_shorts", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_market_list_shorts_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_market_list_shorts", bound_named_method);
  json_connection->add_named_param_method("market_shorts", bound_named_method);

  // register method blockchain_market_list_covers
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_market_list_covers_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_market_list_covers", bound_positional_method);
  json_connection->add_method("market_covers", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_market_list_covers_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_market_list_covers", bound_named_method);
  json_connection->add_named_param_method("market_covers", bound_named_method);

  // register method blockchain_market_get_asset_collateral
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_market_get_asset_collateral_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_market_get_asset_collateral", bound_positional_method);
  json_connection->add_method("collateral", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_market_get_asset_collateral_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_market_get_asset_collateral", bound_named_method);
  json_connection->add_named_param_method("collateral", bound_named_method);

  // register method blockchain_market_order_book
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_market_order_book_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_market_order_book", bound_positional_method);
  json_connection->add_method("market_book", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_market_order_book_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_market_order_book", bound_named_method);
  json_connection->add_named_param_method("market_book", bound_named_method);

  // register method blockchain_get_market_order
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_get_market_order_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_get_market_order", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_get_market_order_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_get_market_order", bound_named_method);

  // register method blockchain_list_address_orders
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_list_address_orders_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_list_address_orders", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_list_address_orders_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_list_address_orders", bound_named_method);

  // register method blockchain_market_order_history
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_market_order_history_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_market_order_history", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_market_order_history_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_market_order_history", bound_named_method);

  // register method blockchain_market_price_history
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_market_price_history_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_market_price_history", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_market_price_history_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_market_price_history", bound_named_method);

  // register method blockchain_list_active_delegates
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_list_active_delegates_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_list_active_delegates", bound_positional_method);
  json_connection->add_method("blockchain_get_active_delegates", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_list_active_delegates_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_list_active_delegates", bound_named_method);
  json_connection->add_named_param_method("blockchain_get_active_delegates", bound_named_method);

  // register method blockchain_list_delegates
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_list_delegates_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_list_delegates", bound_positional_method);
  json_connection->add_method("blockchain_get_delegates", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_list_delegates_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_list_delegates", bound_named_method);
  json_connection->add_named_param_method("blockchain_get_delegates", bound_named_method);

  // register method blockchain_list_blocks
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_list_blocks_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_list_blocks", bound_positional_method);
  json_connection->add_method("list_blocks", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_list_blocks_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_list_blocks", bound_named_method);
  json_connection->add_named_param_method("list_blocks", bound_named_method);

  // register method blockchain_list_missing_block_delegates
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_list_missing_block_delegates_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_list_missing_block_delegates", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_list_missing_block_delegates_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_list_missing_block_delegates", bound_named_method);

  // register method blockchain_export_fork_graph
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_export_fork_graph_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_export_fork_graph", bound_positional_method);
  json_connection->add_method("export_forks", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_export_fork_graph_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_export_fork_graph", bound_named_method);
  json_connection->add_named_param_method("export_forks", bound_named_method);

  // register method blockchain_list_forks
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_list_forks_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_list_forks", bound_positional_method);
  json_connection->add_method("list_forks", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_list_forks_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_list_forks", bound_named_method);
  json_connection->add_named_param_method("list_forks", bound_named_method);

  // register method blockchain_get_delegate_slot_records
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_get_delegate_slot_records_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_get_delegate_slot_records", bound_positional_method);
  json_connection->add_method("get_slot", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_get_delegate_slot_records_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_get_delegate_slot_records", bound_named_method);
  json_connection->add_named_param_method("get_slot", bound_named_method);

  // register method blockchain_get_block_signee
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_get_block_signee_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_get_block_signee", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_get_block_signee_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_get_block_signee", bound_named_method);

  // register method blockchain_list_markets
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_list_markets_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_list_markets", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_list_markets_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_list_markets", bound_named_method);

  // register method blockchain_list_market_transactions
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_list_market_transactions_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_list_market_transactions", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_list_market_transactions_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_list_market_transactions", bound_named_method);

  // register method blockchain_market_status
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_market_status_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_market_status", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_market_status_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_market_status", bound_named_method);

  // register method blockchain_unclaimed_genesis
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_unclaimed_genesis_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_unclaimed_genesis", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_unclaimed_genesis_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_unclaimed_genesis", bound_named_method);

  // register method blockchain_verify_signature
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_verify_signature_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_verify_signature", bound_positional_method);
  json_connection->add_method("verify_signature", bound_positional_method);
  json_connection->add_method("verify_sig", bound_positional_method);
  json_connection->add_method("blockchain_verify_sig", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_verify_signature_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_verify_signature", bound_named_method);
  json_connection->add_named_param_method("verify_signature", bound_named_method);
  json_connection->add_named_param_method("verify_sig", bound_named_method);
  json_connection->add_named_param_method("blockchain_verify_sig", bound_named_method);

  // register method blockchain_broadcast_transaction
  bound_positional_method = boost::bind(&common_api_rpc_server::blockchain_broadcast_transaction_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("blockchain_broadcast_transaction", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::blockchain_broadcast_transaction_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("blockchain_broadcast_transaction", bound_named_method);

  // register method wallet_get_info
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_get_info_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_get_info", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_get_info_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_get_info", bound_named_method);

  // register method wallet_open
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_open_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_open", bound_positional_method);
  json_connection->add_method("open", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_open_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_open", bound_named_method);
  json_connection->add_named_param_method("open", bound_named_method);

  // register method wallet_get_account_public_address
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_get_account_public_address_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_get_account_public_address", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_get_account_public_address_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_get_account_public_address", bound_named_method);

  // register method wallet_list_my_addresses
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_list_my_addresses_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_list_my_addresses", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_list_my_addresses_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_list_my_addresses", bound_named_method);

  // register method wallet_create
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_create_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_create", bound_positional_method);
  json_connection->add_method("create", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_create_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_create", bound_named_method);
  json_connection->add_named_param_method("create", bound_named_method);

  // register method wallet_import_private_key
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_import_private_key_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_import_private_key", bound_positional_method);
  json_connection->add_method("import_key", bound_positional_method);
  json_connection->add_method("importprivkey", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_import_private_key_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_import_private_key", bound_named_method);
  json_connection->add_named_param_method("import_key", bound_named_method);
  json_connection->add_named_param_method("importprivkey", bound_named_method);

  // register method wallet_import_bitcoin
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_import_bitcoin_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_import_bitcoin", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_import_bitcoin_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_import_bitcoin", bound_named_method);

  // register method wallet_import_electrum
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_import_electrum_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_import_electrum", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_import_electrum_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_import_electrum", bound_named_method);

  // register method wallet_import_keyhotee
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_import_keyhotee_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_import_keyhotee", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_import_keyhotee_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_import_keyhotee", bound_named_method);

  // register method wallet_import_keys_from_json
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_import_keys_from_json_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_import_keys_from_json", bound_positional_method);
  json_connection->add_method("import_keys_from_json", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_import_keys_from_json_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_import_keys_from_json", bound_named_method);
  json_connection->add_named_param_method("import_keys_from_json", bound_named_method);

  // register method wallet_close
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_close_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_close", bound_positional_method);
  json_connection->add_method("close", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_close_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_close", bound_named_method);
  json_connection->add_named_param_method("close", bound_named_method);

  // register method wallet_backup_create
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_backup_create_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_backup_create", bound_positional_method);
  json_connection->add_method("backupwallet", bound_positional_method);
  json_connection->add_method("wallet_export_to_json", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_backup_create_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_backup_create", bound_named_method);
  json_connection->add_named_param_method("backupwallet", bound_named_method);
  json_connection->add_named_param_method("wallet_export_to_json", bound_named_method);

  // register method wallet_backup_restore
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_backup_restore_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_backup_restore", bound_positional_method);
  json_connection->add_method("wallet_create_from_json", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_backup_restore_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_backup_restore", bound_named_method);
  json_connection->add_named_param_method("wallet_create_from_json", bound_named_method);

  // register method wallet_export_keys
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_export_keys_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_export_keys", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_export_keys_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_export_keys", bound_named_method);

  // register method wallet_set_automatic_backups
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_set_automatic_backups_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_set_automatic_backups", bound_positional_method);
  json_connection->add_method("auto_backup", bound_positional_method);
  json_connection->add_method("autobackup", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_set_automatic_backups_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_set_automatic_backups", bound_named_method);
  json_connection->add_named_param_method("auto_backup", bound_named_method);
  json_connection->add_named_param_method("autobackup", bound_named_method);

  // register method wallet_set_transaction_expiration_time
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_set_transaction_expiration_time_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_set_transaction_expiration_time", bound_positional_method);
  json_connection->add_method("set_expiration", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_set_transaction_expiration_time_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_set_transaction_expiration_time", bound_named_method);
  json_connection->add_named_param_method("set_expiration", bound_named_method);

  // register method wallet_account_transaction_history
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_account_transaction_history_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_account_transaction_history", bound_positional_method);
  json_connection->add_method("history", bound_positional_method);
  json_connection->add_method("listtransactions", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_account_transaction_history_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_account_transaction_history", bound_named_method);
  json_connection->add_named_param_method("history", bound_named_method);
  json_connection->add_named_param_method("listtransactions", bound_named_method);

  // register method wallet_account_historic_balance
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_account_historic_balance_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_account_historic_balance", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_account_historic_balance_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_account_historic_balance", bound_named_method);

  // register method wallet_transaction_history_experimental
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_transaction_history_experimental_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_transaction_history_experimental", bound_positional_method);
  json_connection->add_method("hx", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_transaction_history_experimental_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_transaction_history_experimental", bound_named_method);
  json_connection->add_named_param_method("hx", bound_named_method);

  // register method wallet_remove_transaction
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_remove_transaction_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_remove_transaction", bound_positional_method);
  json_connection->add_method("remove_transaction", bound_positional_method);
  json_connection->add_method("wallet_transaction_remove", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_remove_transaction_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_remove_transaction", bound_named_method);
  json_connection->add_named_param_method("remove_transaction", bound_named_method);
  json_connection->add_named_param_method("wallet_transaction_remove", bound_named_method);

  // register method wallet_get_pending_transaction_errors
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_get_pending_transaction_errors_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_get_pending_transaction_errors", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_get_pending_transaction_errors_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_get_pending_transaction_errors", bound_named_method);

  // register method wallet_lock
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_lock_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_lock", bound_positional_method);
  json_connection->add_method("lock", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_lock_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_lock", bound_named_method);
  json_connection->add_named_param_method("lock", bound_named_method);

  // register method wallet_unlock
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_unlock_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_unlock", bound_positional_method);
  json_connection->add_method("unlock", bound_positional_method);
  json_connection->add_method("walletpassphrase", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_unlock_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_unlock", bound_named_method);
  json_connection->add_named_param_method("unlock", bound_named_method);
  json_connection->add_named_param_method("walletpassphrase", bound_named_method);

  // register method wallet_change_passphrase
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_change_passphrase_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_change_passphrase", bound_positional_method);
  json_connection->add_method("walletpassphrasechange", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_change_passphrase_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_change_passphrase", bound_named_method);
  json_connection->add_named_param_method("walletpassphrasechange", bound_named_method);

  // register method wallet_list
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_list_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_list", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_list_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_list", bound_named_method);

  // register method wallet_account_create
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_account_create_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_account_create", bound_positional_method);
  json_connection->add_method("wallet_create_account", bound_positional_method);
  json_connection->add_method("create_account", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_account_create_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_account_create", bound_named_method);
  json_connection->add_named_param_method("wallet_create_account", bound_named_method);
  json_connection->add_named_param_method("create_account", bound_named_method);

  // register method wallet_list_contacts
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_list_contacts_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_list_contacts", bound_positional_method);
  json_connection->add_method("contacts", bound_positional_method);
  json_connection->add_method("get_contacts", bound_positional_method);
  json_connection->add_method("list_contacts", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_list_contacts_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_list_contacts", bound_named_method);
  json_connection->add_named_param_method("contacts", bound_named_method);
  json_connection->add_named_param_method("get_contacts", bound_named_method);
  json_connection->add_named_param_method("list_contacts", bound_named_method);

  // register method wallet_get_contact
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_get_contact_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_get_contact", bound_positional_method);
  json_connection->add_method("contact", bound_positional_method);
  json_connection->add_method("get_contact", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_get_contact_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_get_contact", bound_named_method);
  json_connection->add_named_param_method("contact", bound_named_method);
  json_connection->add_named_param_method("get_contact", bound_named_method);

  // register method wallet_add_contact
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_add_contact_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_add_contact", bound_positional_method);
  json_connection->add_method("add_contact", bound_positional_method);
  json_connection->add_method("update_contact", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_add_contact_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_add_contact", bound_named_method);
  json_connection->add_named_param_method("add_contact", bound_named_method);
  json_connection->add_named_param_method("update_contact", bound_named_method);

  // register method wallet_remove_contact
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_remove_contact_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_remove_contact", bound_positional_method);
  json_connection->add_method("remove_contact", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_remove_contact_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_remove_contact", bound_named_method);
  json_connection->add_named_param_method("remove_contact", bound_named_method);

  // register method wallet_list_approvals
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_list_approvals_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_list_approvals", bound_positional_method);
  json_connection->add_method("approvals", bound_positional_method);
  json_connection->add_method("get_approvals", bound_positional_method);
  json_connection->add_method("list_approvals", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_list_approvals_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_list_approvals", bound_named_method);
  json_connection->add_named_param_method("approvals", bound_named_method);
  json_connection->add_named_param_method("get_approvals", bound_named_method);
  json_connection->add_named_param_method("list_approvals", bound_named_method);

  // register method wallet_get_approval
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_get_approval_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_get_approval", bound_positional_method);
  json_connection->add_method("approval", bound_positional_method);
  json_connection->add_method("get_approval", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_get_approval_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_get_approval", bound_named_method);
  json_connection->add_named_param_method("approval", bound_named_method);
  json_connection->add_named_param_method("get_approval", bound_named_method);

  // register method wallet_approve
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_approve_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_approve", bound_positional_method);
  json_connection->add_method("approve", bound_positional_method);
  json_connection->add_method("add_approval", bound_positional_method);
  json_connection->add_method("update_approval", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_approve_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_approve", bound_named_method);
  json_connection->add_named_param_method("approve", bound_named_method);
  json_connection->add_named_param_method("add_approval", bound_named_method);
  json_connection->add_named_param_method("update_approval", bound_named_method);

  // register method wallet_burn
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_burn_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_burn", bound_positional_method);
  json_connection->add_method("burn", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_burn_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_burn", bound_named_method);
  json_connection->add_named_param_method("burn", bound_named_method);

  // register method wallet_address_create
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_address_create_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_address_create", bound_positional_method);
  json_connection->add_method("new_address", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_address_create_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_address_create", bound_named_method);
  json_connection->add_named_param_method("new_address", bound_named_method);

  // register method wallet_transfer_to_address
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_transfer_to_address_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_transfer_to_address", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_transfer_to_address_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_transfer_to_address", bound_named_method);

  // register method wallet_transfer_to_genesis_multisig_address
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_transfer_to_genesis_multisig_address_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_transfer_to_genesis_multisig_address", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_transfer_to_genesis_multisig_address_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_transfer_to_genesis_multisig_address", bound_named_method);

  // register method wallet_transfer_to_address_from_file
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_transfer_to_address_from_file_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_transfer_to_address_from_file", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_transfer_to_address_from_file_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_transfer_to_address_from_file", bound_named_method);

  // register method wallet_transfer_to_genesis_multisig_address_from_file
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_transfer_to_genesis_multisig_address_from_file_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_transfer_to_genesis_multisig_address_from_file", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_transfer_to_genesis_multisig_address_from_file_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_transfer_to_genesis_multisig_address_from_file", bound_named_method);

  // register method wallet_check_passphrase
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_check_passphrase_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_check_passphrase", bound_positional_method);
  json_connection->add_method("check_passphrase", bound_positional_method);
  json_connection->add_method("check_password", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_check_passphrase_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_check_passphrase", bound_named_method);
  json_connection->add_named_param_method("check_passphrase", bound_named_method);
  json_connection->add_named_param_method("check_password", bound_named_method);

  // register method wallet_transfer
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_transfer_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_transfer", bound_positional_method);
  json_connection->add_method("transfer", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_transfer_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_transfer", bound_named_method);
  json_connection->add_named_param_method("transfer", bound_named_method);

  // register method wallet_multisig_get_balance_id
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_multisig_get_balance_id_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_multisig_get_balance_id", bound_positional_method);
  json_connection->add_method("get_multisig_id", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_multisig_get_balance_id_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_multisig_get_balance_id", bound_named_method);
  json_connection->add_named_param_method("get_multisig_id", bound_named_method);

  // register method wallet_multisig_deposit
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_multisig_deposit_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_multisig_deposit", bound_positional_method);
  json_connection->add_method("transfer_to_multisig", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_multisig_deposit_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_multisig_deposit", bound_named_method);
  json_connection->add_named_param_method("transfer_to_multisig", bound_named_method);

  // register method wallet_withdraw_from_address
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_withdraw_from_address_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_withdraw_from_address", bound_positional_method);
  json_connection->add_method("withdraw_from_address", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_withdraw_from_address_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_withdraw_from_address", bound_named_method);
  json_connection->add_named_param_method("withdraw_from_address", bound_named_method);

  // register method wallet_receive_genesis_multisig_blanace
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_receive_genesis_multisig_blanace_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_receive_genesis_multisig_blanace", bound_positional_method);
  json_connection->add_method("receive_from_genesis_address", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_receive_genesis_multisig_blanace_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_receive_genesis_multisig_blanace", bound_named_method);
  json_connection->add_named_param_method("receive_from_genesis_address", bound_named_method);

  // register method wallet_withdraw_from_legacy_address
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_withdraw_from_legacy_address_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_withdraw_from_legacy_address", bound_positional_method);
  json_connection->add_method("withdraw_from_legacy_address", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_withdraw_from_legacy_address_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_withdraw_from_legacy_address", bound_named_method);
  json_connection->add_named_param_method("withdraw_from_legacy_address", bound_named_method);

  // register method wallet_multisig_withdraw_start
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_multisig_withdraw_start_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_multisig_withdraw_start", bound_positional_method);
  json_connection->add_method("withdraw_from_multisig", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_multisig_withdraw_start_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_multisig_withdraw_start", bound_named_method);
  json_connection->add_named_param_method("withdraw_from_multisig", bound_named_method);

  // register method wallet_builder_add_signature
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_builder_add_signature_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_builder_add_signature", bound_positional_method);
  json_connection->add_method("add_signature", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_builder_add_signature_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_builder_add_signature", bound_named_method);
  json_connection->add_named_param_method("add_signature", bound_named_method);

  // register method wallet_builder_file_add_signature
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_builder_file_add_signature_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_builder_file_add_signature", bound_positional_method);
  json_connection->add_method("add_signature_to_file", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_builder_file_add_signature_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_builder_file_add_signature", bound_named_method);
  json_connection->add_named_param_method("add_signature_to_file", bound_named_method);

  // register method wallet_release_escrow
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_release_escrow_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_release_escrow", bound_positional_method);
  json_connection->add_method("release", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_release_escrow_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_release_escrow", bound_named_method);
  json_connection->add_named_param_method("release", bound_named_method);

  // register method wallet_transfer_from_with_escrow
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_transfer_from_with_escrow_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_transfer_from_with_escrow", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_transfer_from_with_escrow_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_transfer_from_with_escrow", bound_named_method);

  // register method wallet_rescan_blockchain
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_rescan_blockchain_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_rescan_blockchain", bound_positional_method);
  json_connection->add_method("scan", bound_positional_method);
  json_connection->add_method("rescan", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_rescan_blockchain_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_rescan_blockchain", bound_named_method);
  json_connection->add_named_param_method("scan", bound_named_method);
  json_connection->add_named_param_method("rescan", bound_named_method);

  // register method wallet_cancel_scan
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_cancel_scan_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_cancel_scan", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_cancel_scan_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_cancel_scan", bound_named_method);

  // register method wallet_get_transaction
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_get_transaction_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_get_transaction", bound_positional_method);
  json_connection->add_method("get_transaction", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_get_transaction_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_get_transaction", bound_named_method);
  json_connection->add_named_param_method("get_transaction", bound_named_method);

  // register method wallet_scan_transaction
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_scan_transaction_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_scan_transaction", bound_positional_method);
  json_connection->add_method("scan_transaction", bound_positional_method);
  json_connection->add_method("wallet_transaction_scan", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_scan_transaction_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_scan_transaction", bound_named_method);
  json_connection->add_named_param_method("scan_transaction", bound_named_method);
  json_connection->add_named_param_method("wallet_transaction_scan", bound_named_method);

  // register method wallet_scan_transaction_experimental
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_scan_transaction_experimental_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_scan_transaction_experimental", bound_positional_method);
  json_connection->add_method("sx", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_scan_transaction_experimental_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_scan_transaction_experimental", bound_named_method);
  json_connection->add_named_param_method("sx", bound_named_method);

  // register method wallet_add_transaction_note_experimental
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_add_transaction_note_experimental_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_add_transaction_note_experimental", bound_positional_method);
  json_connection->add_method("nx", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_add_transaction_note_experimental_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_add_transaction_note_experimental", bound_named_method);
  json_connection->add_named_param_method("nx", bound_named_method);

  // register method wallet_rebroadcast_transaction
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_rebroadcast_transaction_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_rebroadcast_transaction", bound_positional_method);
  json_connection->add_method("rebroadcast", bound_positional_method);
  json_connection->add_method("wallet_transaction_rebroadcast", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_rebroadcast_transaction_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_rebroadcast_transaction", bound_named_method);
  json_connection->add_named_param_method("rebroadcast", bound_named_method);
  json_connection->add_named_param_method("wallet_transaction_rebroadcast", bound_named_method);

  // register method wallet_account_register
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_account_register_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_account_register", bound_positional_method);
  json_connection->add_method("register", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_account_register_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_account_register", bound_named_method);
  json_connection->add_named_param_method("register", bound_named_method);

  // register method wallet_set_custom_data
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_set_custom_data_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_set_custom_data", bound_positional_method);
  json_connection->add_method("update_private_data", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_set_custom_data_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_set_custom_data", bound_named_method);
  json_connection->add_named_param_method("update_private_data", bound_named_method);

  // register method wallet_account_update_registration
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_account_update_registration_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_account_update_registration", bound_positional_method);
  json_connection->add_method("update_registration", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_account_update_registration_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_account_update_registration", bound_named_method);
  json_connection->add_named_param_method("update_registration", bound_named_method);

  // register method wallet_account_update_active_key
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_account_update_active_key_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_account_update_active_key", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_account_update_active_key_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_account_update_active_key", bound_named_method);

  // register method wallet_list_accounts
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_list_accounts_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_list_accounts", bound_positional_method);
  json_connection->add_method("accounts", bound_positional_method);
  json_connection->add_method("get_accounts", bound_positional_method);
  json_connection->add_method("list_accounts", bound_positional_method);
  json_connection->add_method("listaccounts", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_list_accounts_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_list_accounts", bound_named_method);
  json_connection->add_named_param_method("accounts", bound_named_method);
  json_connection->add_named_param_method("get_accounts", bound_named_method);
  json_connection->add_named_param_method("list_accounts", bound_named_method);
  json_connection->add_named_param_method("listaccounts", bound_named_method);

  // register method wallet_get_account
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_get_account_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_get_account", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_get_account_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_get_account", bound_named_method);

  // register method wallet_account_rename
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_account_rename_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_account_rename", bound_positional_method);
  json_connection->add_method("wallet_rename_account", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_account_rename_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_account_rename", bound_named_method);
  json_connection->add_named_param_method("wallet_rename_account", bound_named_method);

  // register method wallet_mia_create
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_mia_create_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_mia_create", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_mia_create_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_mia_create", bound_named_method);

  // register method wallet_uia_create
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_uia_create_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_uia_create", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_uia_create_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_uia_create", bound_named_method);

  // register method wallet_uia_issue
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_uia_issue_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_uia_issue", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_uia_issue_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_uia_issue", bound_named_method);

  // register method wallet_uia_issue_to_addresses
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_uia_issue_to_addresses_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_uia_issue_to_addresses", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_uia_issue_to_addresses_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_uia_issue_to_addresses", bound_named_method);

  // register method wallet_uia_collect_fees
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_uia_collect_fees_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_uia_collect_fees", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_uia_collect_fees_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_uia_collect_fees", bound_named_method);

  // register method wallet_uia_update_description
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_uia_update_description_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_uia_update_description", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_uia_update_description_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_uia_update_description", bound_named_method);

  // register method wallet_uia_update_supply
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_uia_update_supply_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_uia_update_supply", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_uia_update_supply_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_uia_update_supply", bound_named_method);

  // register method wallet_uia_update_fees
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_uia_update_fees_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_uia_update_fees", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_uia_update_fees_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_uia_update_fees", bound_named_method);

  // register method wallet_uia_update_active_flags
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_uia_update_active_flags_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_uia_update_active_flags", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_uia_update_active_flags_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_uia_update_active_flags", bound_named_method);

  // register method wallet_uia_update_authority_permissions
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_uia_update_authority_permissions_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_uia_update_authority_permissions", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_uia_update_authority_permissions_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_uia_update_authority_permissions", bound_named_method);

  // register method wallet_uia_update_whitelist
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_uia_update_whitelist_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_uia_update_whitelist", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_uia_update_whitelist_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_uia_update_whitelist", bound_named_method);

  // register method wallet_uia_retract_balance
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_uia_retract_balance_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_uia_retract_balance", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_uia_retract_balance_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_uia_retract_balance", bound_named_method);

  // register method wallet_escrow_summary
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_escrow_summary_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_escrow_summary", bound_positional_method);
  json_connection->add_method("escrow", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_escrow_summary_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_escrow_summary", bound_named_method);
  json_connection->add_named_param_method("escrow", bound_named_method);

  // register method wallet_account_balance
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_account_balance_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_account_balance", bound_positional_method);
  json_connection->add_method("balance", bound_positional_method);
  json_connection->add_method("getbalance", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_account_balance_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_account_balance", bound_named_method);
  json_connection->add_named_param_method("balance", bound_named_method);
  json_connection->add_named_param_method("getbalance", bound_named_method);

  // register method wallet_account_balance_ids
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_account_balance_ids_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_account_balance_ids", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_account_balance_ids_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_account_balance_ids", bound_named_method);

  // register method wallet_account_balance_extended
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_account_balance_extended_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_account_balance_extended", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_account_balance_extended_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_account_balance_extended", bound_named_method);

  // register method wallet_account_vesting_balances
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_account_vesting_balances_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_account_vesting_balances", bound_positional_method);
  json_connection->add_method("vesting", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_account_vesting_balances_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_account_vesting_balances", bound_named_method);
  json_connection->add_named_param_method("vesting", bound_named_method);

  // register method wallet_account_yield
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_account_yield_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_account_yield", bound_positional_method);
  json_connection->add_method("yield", bound_positional_method);
  json_connection->add_method("getyield", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_account_yield_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_account_yield", bound_named_method);
  json_connection->add_named_param_method("yield", bound_named_method);
  json_connection->add_named_param_method("getyield", bound_named_method);

  // register method wallet_account_list_public_keys
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_account_list_public_keys_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_account_list_public_keys", bound_positional_method);
  json_connection->add_method("public_keys", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_account_list_public_keys_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_account_list_public_keys", bound_named_method);
  json_connection->add_named_param_method("public_keys", bound_named_method);

  // register method wallet_delegate_withdraw_pay
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_delegate_withdraw_pay_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_delegate_withdraw_pay", bound_positional_method);
  json_connection->add_method("pay_delegate", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_delegate_withdraw_pay_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_delegate_withdraw_pay", bound_named_method);
  json_connection->add_named_param_method("pay_delegate", bound_named_method);

  // register method wallet_set_transaction_fee
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_set_transaction_fee_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_set_transaction_fee", bound_positional_method);
  json_connection->add_method("wallet_set_priority_fee", bound_positional_method);
  json_connection->add_method("set_priority_fee", bound_positional_method);
  json_connection->add_method("settrxfee", bound_positional_method);
  json_connection->add_method("setfee", bound_positional_method);
  json_connection->add_method("set_fee", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_set_transaction_fee_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_set_transaction_fee", bound_named_method);
  json_connection->add_named_param_method("wallet_set_priority_fee", bound_named_method);
  json_connection->add_named_param_method("set_priority_fee", bound_named_method);
  json_connection->add_named_param_method("settrxfee", bound_named_method);
  json_connection->add_named_param_method("setfee", bound_named_method);
  json_connection->add_named_param_method("set_fee", bound_named_method);

  // register method wallet_get_transaction_fee
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_get_transaction_fee_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_get_transaction_fee", bound_positional_method);
  json_connection->add_method("wallet_get_priority_fee", bound_positional_method);
  json_connection->add_method("get_priority_fee", bound_positional_method);
  json_connection->add_method("gettrxfee", bound_positional_method);
  json_connection->add_method("getfee", bound_positional_method);
  json_connection->add_method("get_fee", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_get_transaction_fee_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_get_transaction_fee", bound_named_method);
  json_connection->add_named_param_method("wallet_get_priority_fee", bound_named_method);
  json_connection->add_named_param_method("get_priority_fee", bound_named_method);
  json_connection->add_named_param_method("gettrxfee", bound_named_method);
  json_connection->add_named_param_method("getfee", bound_named_method);
  json_connection->add_named_param_method("get_fee", bound_named_method);

  // register method wallet_market_submit_bid
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_market_submit_bid_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_market_submit_bid", bound_positional_method);
  json_connection->add_method("bid", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_market_submit_bid_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_market_submit_bid", bound_named_method);
  json_connection->add_named_param_method("bid", bound_named_method);

  // register method wallet_market_submit_ask
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_market_submit_ask_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_market_submit_ask", bound_positional_method);
  json_connection->add_method("ask", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_market_submit_ask_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_market_submit_ask", bound_named_method);
  json_connection->add_named_param_method("ask", bound_named_method);

  // register method wallet_market_submit_short
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_market_submit_short_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_market_submit_short", bound_positional_method);
  json_connection->add_method("short", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_market_submit_short_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_market_submit_short", bound_named_method);
  json_connection->add_named_param_method("short", bound_named_method);

  // register method wallet_market_cover
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_market_cover_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_market_cover", bound_positional_method);
  json_connection->add_method("cover", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_market_cover_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_market_cover", bound_named_method);
  json_connection->add_named_param_method("cover", bound_named_method);

  // register method wallet_market_batch_update
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_market_batch_update_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_market_batch_update", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_market_batch_update_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_market_batch_update", bound_named_method);

  // register method wallet_market_add_collateral
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_market_add_collateral_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_market_add_collateral", bound_positional_method);
  json_connection->add_method("add_collateral", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_market_add_collateral_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_market_add_collateral", bound_named_method);
  json_connection->add_named_param_method("add_collateral", bound_named_method);

  // register method wallet_market_order_list
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_market_order_list_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_market_order_list", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_market_order_list_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_market_order_list", bound_named_method);

  // register method wallet_account_order_list
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_account_order_list_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_account_order_list", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_account_order_list_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_account_order_list", bound_named_method);

  // register method wallet_market_cancel_order
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_market_cancel_order_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_market_cancel_order", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_market_cancel_order_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_market_cancel_order", bound_named_method);

  // register method wallet_market_cancel_orders
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_market_cancel_orders_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_market_cancel_orders", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_market_cancel_orders_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_market_cancel_orders", bound_named_method);

  // register method wallet_dump_private_key
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_dump_private_key_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_dump_private_key", bound_positional_method);
  json_connection->add_method("dump_private_key", bound_positional_method);
  json_connection->add_method("dumpprivkey", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_dump_private_key_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_dump_private_key", bound_named_method);
  json_connection->add_named_param_method("dump_private_key", bound_named_method);
  json_connection->add_named_param_method("dumpprivkey", bound_named_method);

  // register method wallet_dump_account_private_key
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_dump_account_private_key_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_dump_account_private_key", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_dump_account_private_key_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_dump_account_private_key", bound_named_method);

  // register method wallet_account_vote_summary
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_account_vote_summary_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_account_vote_summary", bound_positional_method);
  json_connection->add_method("votes", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_account_vote_summary_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_account_vote_summary", bound_named_method);
  json_connection->add_named_param_method("votes", bound_named_method);

  // register method wallet_set_setting
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_set_setting_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_set_setting", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_set_setting_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_set_setting", bound_named_method);

  // register method wallet_get_setting
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_get_setting_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_get_setting", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_get_setting_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_get_setting", bound_named_method);

  // register method wallet_delegate_set_block_production
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_delegate_set_block_production_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_delegate_set_block_production", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_delegate_set_block_production_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_delegate_set_block_production", bound_named_method);

  // register method wallet_set_transaction_scanning
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_set_transaction_scanning_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_set_transaction_scanning", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_set_transaction_scanning_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_set_transaction_scanning", bound_named_method);

  // register method wallet_sign_hash
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_sign_hash_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_sign_hash", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_sign_hash_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_sign_hash", bound_named_method);

  // register method wallet_login_start
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_login_start_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_login_start", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_login_start_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_login_start", bound_named_method);

  // register method wallet_login_finish
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_login_finish_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_login_finish", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_login_finish_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_login_finish", bound_named_method);

  // register method wallet_balance_set_vote_info
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_balance_set_vote_info_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_balance_set_vote_info", bound_positional_method);
  json_connection->add_method("set_vote_info", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_balance_set_vote_info_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_balance_set_vote_info", bound_named_method);
  json_connection->add_named_param_method("set_vote_info", bound_named_method);

  // register method wallet_publish_slate
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_publish_slate_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_publish_slate", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_publish_slate_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_publish_slate", bound_named_method);

  // register method wallet_publish_version
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_publish_version_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_publish_version", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_publish_version_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_publish_version", bound_named_method);

  // register method wallet_collect_genesis_balances
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_collect_genesis_balances_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_collect_genesis_balances", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_collect_genesis_balances_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_collect_genesis_balances", bound_named_method);

  // register method wallet_collect_vested_balances
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_collect_vested_balances_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_collect_vested_balances", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_collect_vested_balances_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_collect_vested_balances", bound_named_method);

  // register method wallet_delegate_update_signing_key
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_delegate_update_signing_key_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_delegate_update_signing_key", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_delegate_update_signing_key_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_delegate_update_signing_key", bound_named_method);

  // register method wallet_recover_accounts
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_recover_accounts_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_recover_accounts", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_recover_accounts_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_recover_accounts", bound_named_method);

  // register method wallet_recover_titan_deposit_info
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_recover_titan_deposit_info_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_recover_titan_deposit_info", bound_positional_method);
  json_connection->add_method("recover_transaction", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_recover_titan_deposit_info_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_recover_titan_deposit_info", bound_named_method);
  json_connection->add_named_param_method("recover_transaction", bound_named_method);

  // register method wallet_verify_titan_deposit
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_verify_titan_deposit_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_verify_titan_deposit", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_verify_titan_deposit_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_verify_titan_deposit", bound_named_method);

  // register method wallet_publish_price_feed
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_publish_price_feed_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_publish_price_feed", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_publish_price_feed_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_publish_price_feed", bound_named_method);

  // register method wallet_publish_feeds
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_publish_feeds_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_publish_feeds", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_publish_feeds_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_publish_feeds", bound_named_method);

  // register method wallet_publish_feeds_multi_experimental
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_publish_feeds_multi_experimental_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_publish_feeds_multi_experimental", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_publish_feeds_multi_experimental_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_publish_feeds_multi_experimental", bound_named_method);

  // register method wallet_repair_records
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_repair_records_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_repair_records", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_repair_records_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_repair_records", bound_named_method);

  // register method wallet_regenerate_keys
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_regenerate_keys_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_regenerate_keys", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_regenerate_keys_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_regenerate_keys", bound_named_method);

  // register method wallet_account_retract
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_account_retract_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_account_retract", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_account_retract_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_account_retract", bound_named_method);

  // register method wallet_generate_brain_seed
  bound_positional_method = boost::bind(&common_api_rpc_server::wallet_generate_brain_seed_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("wallet_generate_brain_seed", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::wallet_generate_brain_seed_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("wallet_generate_brain_seed", bound_named_method);

  // register method fetch_welcome_package
  bound_positional_method = boost::bind(&common_api_rpc_server::fetch_welcome_package_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("fetch_welcome_package", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::fetch_welcome_package_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("fetch_welcome_package", bound_named_method);

  // register method request_register_account
  bound_positional_method = boost::bind(&common_api_rpc_server::request_register_account_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("request_register_account", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::request_register_account_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("request_register_account", bound_named_method);

  // register method approve_register_account
  bound_positional_method = boost::bind(&common_api_rpc_server::approve_register_account_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("approve_register_account", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::approve_register_account_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("approve_register_account", bound_named_method);

  // register method debug_start_simulated_time
  bound_positional_method = boost::bind(&common_api_rpc_server::debug_start_simulated_time_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("debug_start_simulated_time", bound_positional_method);
  json_connection->add_method("start_simulated_time", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::debug_start_simulated_time_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("debug_start_simulated_time", bound_named_method);
  json_connection->add_named_param_method("start_simulated_time", bound_named_method);

  // register method debug_advance_time
  bound_positional_method = boost::bind(&common_api_rpc_server::debug_advance_time_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("debug_advance_time", bound_positional_method);
  json_connection->add_method("advance_time", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::debug_advance_time_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("debug_advance_time", bound_named_method);
  json_connection->add_named_param_method("advance_time", bound_named_method);

  // register method debug_trap
  bound_positional_method = boost::bind(&common_api_rpc_server::debug_trap_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("debug_trap", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::debug_trap_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("debug_trap", bound_named_method);

  // register method debug_wait
  bound_positional_method = boost::bind(&common_api_rpc_server::debug_wait_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("debug_wait", bound_positional_method);
  json_connection->add_method("wait", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::debug_wait_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("debug_wait", bound_named_method);
  json_connection->add_named_param_method("wait", bound_named_method);

  // register method debug_wait_for_block_by_number
  bound_positional_method = boost::bind(&common_api_rpc_server::debug_wait_for_block_by_number_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("debug_wait_for_block_by_number", bound_positional_method);
  json_connection->add_method("wait_for_block_by_number", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::debug_wait_for_block_by_number_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("debug_wait_for_block_by_number", bound_named_method);
  json_connection->add_named_param_method("wait_for_block_by_number", bound_named_method);

  // register method debug_wait_block_interval
  bound_positional_method = boost::bind(&common_api_rpc_server::debug_wait_block_interval_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("debug_wait_block_interval", bound_positional_method);
  json_connection->add_method("wait_block_interval", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::debug_wait_block_interval_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("debug_wait_block_interval", bound_named_method);
  json_connection->add_named_param_method("wait_block_interval", bound_named_method);

  // register method debug_enable_output
  bound_positional_method = boost::bind(&common_api_rpc_server::debug_enable_output_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("debug_enable_output", bound_positional_method);
  json_connection->add_method("enable_output", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::debug_enable_output_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("debug_enable_output", bound_named_method);
  json_connection->add_named_param_method("enable_output", bound_named_method);

  // register method debug_filter_output_for_tests
  bound_positional_method = boost::bind(&common_api_rpc_server::debug_filter_output_for_tests_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("debug_filter_output_for_tests", bound_positional_method);
  json_connection->add_method("filter_output_for_tests", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::debug_filter_output_for_tests_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("debug_filter_output_for_tests", bound_named_method);
  json_connection->add_named_param_method("filter_output_for_tests", bound_named_method);

  // register method debug_update_logging_config
  bound_positional_method = boost::bind(&common_api_rpc_server::debug_update_logging_config_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("debug_update_logging_config", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::debug_update_logging_config_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("debug_update_logging_config", bound_named_method);

  // register method debug_get_call_statistics
  bound_positional_method = boost::bind(&common_api_rpc_server::debug_get_call_statistics_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("debug_get_call_statistics", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::debug_get_call_statistics_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("debug_get_call_statistics", bound_named_method);

  // register method debug_get_client_name
  bound_positional_method = boost::bind(&common_api_rpc_server::debug_get_client_name_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("debug_get_client_name", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::debug_get_client_name_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("debug_get_client_name", bound_named_method);

  // register method debug_deterministic_private_keys
  bound_positional_method = boost::bind(&common_api_rpc_server::debug_deterministic_private_keys_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("debug_deterministic_private_keys", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::debug_deterministic_private_keys_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("debug_deterministic_private_keys", bound_named_method);

  // register method debug_stop_before_block
  bound_positional_method = boost::bind(&common_api_rpc_server::debug_stop_before_block_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("debug_stop_before_block", bound_positional_method);
  json_connection->add_method("stop_before_block", bound_positional_method);
  json_connection->add_method("stop_b4_block", bound_positional_method);
  json_connection->add_method("debug_stop_b4_block", bound_positional_method);
  json_connection->add_method("stop_before", bound_positional_method);
  json_connection->add_method("stop_b4", bound_positional_method);
  json_connection->add_method("stopb4", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::debug_stop_before_block_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("debug_stop_before_block", bound_named_method);
  json_connection->add_named_param_method("stop_before_block", bound_named_method);
  json_connection->add_named_param_method("stop_b4_block", bound_named_method);
  json_connection->add_named_param_method("debug_stop_b4_block", bound_named_method);
  json_connection->add_named_param_method("stop_before", bound_named_method);
  json_connection->add_named_param_method("stop_b4", bound_named_method);
  json_connection->add_named_param_method("stopb4", bound_named_method);

  // register method debug_verify_market_matching
  bound_positional_method = boost::bind(&common_api_rpc_server::debug_verify_market_matching_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("debug_verify_market_matching", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::debug_verify_market_matching_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("debug_verify_market_matching", bound_named_method);

  // register method debug_list_matching_errors
  bound_positional_method = boost::bind(&common_api_rpc_server::debug_list_matching_errors_positional, 
                                        this, capture_con, _1);
  json_connection->add_method("debug_list_matching_errors", bound_positional_method);
  bound_named_method = boost::bind(&common_api_rpc_server::debug_list_matching_errors_named, 
                                        this, capture_con, _1);
  json_connection->add_named_param_method("debug_list_matching_errors", bound_named_method);

}

void common_api_rpc_server::register_common_api_method_metadata()
{
  {
    // register method about
    fbtc::api::method_data about_method_metadata{"about", nullptr,
      /* description */ "Returns version number and associated information for this client",
      /* returns */ "json_object",
      /* params: */ {},
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Returns version number and associated information for this client\n\nParameters:\n  (none)\n\nReturns:\n  json_object\n",
      /* aliases */ {}, false};
    store_method_metadata(about_method_metadata);
  }

  {
    // register method get_info
    fbtc::api::method_data get_info_method_metadata{"get_info", nullptr,
      /* description */ "Returns version number and associated information for this client",
      /* returns */ "json_object",
      /* params: */ {},
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Returns version number and associated information for this client\n\nParameters:\n  (none)\n\nReturns:\n  json_object\n",
      /* aliases */ {"getinfo", "info"}, false};
    store_method_metadata(get_info_method_metadata);
  }

  {
    // register method stop
    fbtc::api::method_data stop_method_metadata{"stop", nullptr,
      /* description */ "shut down the RPC server and exit this client",
      /* returns */ "void",
      /* params: */ {},
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "shut down the RPC server and exit this client\n\nParameters:\n  (none)\n\nReturns:\n  void\n",
      /* aliases */ {"quit", "exit"}, false};
    store_method_metadata(stop_method_metadata);
  }

  {
    // register method help
    fbtc::api::method_data help_method_metadata{"help", nullptr,
      /* description */ "display a list of commands, or detailed help on an individual command",
      /* returns */ "string",
      /* params: */ {
        {"command_name", "method_name", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "display a list of commands, or detailed help on an individual command\n\nParameters:\n  command_name (method_name, optional, defaults to \"\"): the name of the method to get detailed help, or omit this for a list of commands\n\nReturns:\n  string\n",
      /* aliases */ {"h"}, false};
    store_method_metadata(help_method_metadata);
  }

  {
    // register method validate_address
    fbtc::api::method_data validate_address_method_metadata{"validate_address", nullptr,
      /* description */ "Return information about given FastBitcoin address",
      /* returns */ "json_object",
      /* params: */ {
        {"address", "string", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Return information about given FastBitcoin address\n\nParameters:\n  address (string, required): the address or public key to validate\n\nReturns:\n  json_object\n",
      /* aliases */ {"validateaddress"}, false};
    store_method_metadata(validate_address_method_metadata);
  }

  {
    // register method convert_to_native_address
    fbtc::api::method_data convert_to_native_address_method_metadata{"convert_to_native_address", nullptr,
      /* description */ "Convert a BTC or PTS address into a FBTC address.",
      /* returns */ "address",
      /* params: */ {
        {"raw_address", "string", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Convert a BTC or PTS address into a FBTC address.\n\nParameters:\n  raw_address (string, required): the BTC or PTS address to convert\n\nReturns:\n  address\n",
      /* aliases */ {"convertaddress"}, false};
    store_method_metadata(convert_to_native_address_method_metadata);
  }

  {
    // register method execute_command_line
    fbtc::api::method_data execute_command_line_method_metadata{"execute_command_line", nullptr,
      /* description */ "Execute the given command as if it were typed on the CLI",
      /* returns */ "string",
      /* params: */ {
        {"input", "passphrase", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "Execute the given command as if it were typed on the CLI\n\nParameters:\n  input (passphrase, required): The entire command input as if it were a CLI input\n\nReturns:\n  string\n",
      /* aliases */ {}, false};
    store_method_metadata(execute_command_line_method_metadata);
  }

  {
    // register method execute_script
    fbtc::api::method_data execute_script_method_metadata{"execute_script", nullptr,
      /* description */ "Execute the given file as if it were typed on the CLI",
      /* returns */ "void",
      /* params: */ {
        {"script", "filename", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "Execute the given file as if it were typed on the CLI\n\nParameters:\n  script (filename, required): Name of a file containing CLI commands to execute\n\nReturns:\n  void\n",
      /* aliases */ {}, false};
    store_method_metadata(execute_script_method_metadata);
  }

  {
    // register method batch
    fbtc::api::method_data batch_method_metadata{"batch", nullptr,
      /* description */ "Takes any no_prerequisites command and an array of its arguments and returns an array of results. Example: batch blockchain_get_blockhash [[1], [2]]",
      /* returns */ "variants",
      /* params: */ {
        {"method_name", "string", fbtc::api::required_positional, fc::ovariant()},
        {"parameters_list", "parameters_list", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Takes any no_prerequisites command and an array of its arguments and returns an array of results. Example: batch blockchain_get_blockhash [[1], [2]]\n\nParameters:\n  method_name (string, required): The command name for calling\n  parameters_list (parameters_list, required): The list of list of parameters for this command, the return will be the list of execute result of corresponding parameters\n\nReturns:\n  variants\n",
      /* aliases */ {}, false};
    store_method_metadata(batch_method_metadata);
  }

  {
    // register method batch_authenticated
    fbtc::api::method_data batch_authenticated_method_metadata{"batch_authenticated", nullptr,
      /* description */ "Takes any no_prerequisites command and an array of its arguments and returns an array of results. Example: batch_authenticated blockchain_get_blockhash [[1], [2]]",
      /* returns */ "variants",
      /* params: */ {
        {"method_name", "string", fbtc::api::required_positional, fc::ovariant()},
        {"parameters_list", "parameters_list", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "Takes any no_prerequisites command and an array of its arguments and returns an array of results. Example: batch_authenticated blockchain_get_blockhash [[1], [2]]\n\nParameters:\n  method_name (string, required): The command name for calling\n  parameters_list (parameters_list, required): The list of list of parameters for this command, the return will be the list of execute result of corresponding parameters\n\nReturns:\n  variants\n",
      /* aliases */ {}, false};
    store_method_metadata(batch_authenticated_method_metadata);
  }

  {
    // register method builder_finalize_and_sign
    fbtc::api::method_data builder_finalize_and_sign_method_metadata{"builder_finalize_and_sign", nullptr,
      /* description */ "Takes a transaction builder and returns a signed transaction for broadcasting",
      /* returns */ "transaction_record",
      /* params: */ {
        {"builder", "transaction_builder", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 5,
      /* detailed description */ "Takes a transaction builder and returns a signed transaction for broadcasting\n\nParameters:\n  builder (transaction_builder, required): \n\nReturns:\n  transaction_record\n",
      /* aliases */ {}, false};
    store_method_metadata(builder_finalize_and_sign_method_metadata);
  }

  {
    // register method meta_help
    fbtc::api::method_data meta_help_method_metadata{"meta_help", nullptr,
      /* description */ "Returns help information as JSON data",
      /* returns */ "method_map_type",
      /* params: */ {},
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Returns help information as JSON data\n\nParameters:\n  (none)\n\nReturns:\n  method_map_type\n",
      /* aliases */ {}, false};
    store_method_metadata(meta_help_method_metadata);
  }

  {
    // register method rpc_set_username
    fbtc::api::method_data rpc_set_username_method_metadata{"rpc_set_username", nullptr,
      /* description */ "Set the username for basic auth for the http server.",
      /* returns */ "void",
      /* params: */ {
        {"username", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "Set the username for basic auth for the http server.\n\nParameters:\n  username (string, optional, defaults to \"\"): Username for basic auth\n\nReturns:\n  void\n",
      /* aliases */ {}, false};
    store_method_metadata(rpc_set_username_method_metadata);
  }

  {
    // register method rpc_set_password
    fbtc::api::method_data rpc_set_password_method_metadata{"rpc_set_password", nullptr,
      /* description */ "Set the password for basic auth for the http server.",
      /* returns */ "void",
      /* params: */ {
        {"password", "passphrase", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "Set the password for basic auth for the http server.\n\nParameters:\n  password (passphrase, optional, defaults to \"\"): Password for basic auth\n\nReturns:\n  void\n",
      /* aliases */ {}, false};
    store_method_metadata(rpc_set_password_method_metadata);
  }

  {
    // register method rpc_start_server
    fbtc::api::method_data rpc_start_server_method_metadata{"rpc_start_server", nullptr,
      /* description */ "Set the port and start rpc server.",
      /* returns */ "void",
      /* params: */ {
        {"port", "uint32_t", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"65065\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "Set the port and start rpc server.\n\nParameters:\n  port (uint32_t, optional, defaults to \"65065\"): Port for rpc server\n\nReturns:\n  void\n",
      /* aliases */ {}, false};
    store_method_metadata(rpc_start_server_method_metadata);
  }

  {
    // register method http_start_server
    fbtc::api::method_data http_start_server_method_metadata{"http_start_server", nullptr,
      /* description */ "Set the port and start http server.",
      /* returns */ "void",
      /* params: */ {
        {"port", "uint32_t", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"65066\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "Set the port and start http server.\n\nParameters:\n  port (uint32_t, optional, defaults to \"65066\"): Port for http server\n\nReturns:\n  void\n",
      /* aliases */ {}, false};
    store_method_metadata(http_start_server_method_metadata);
  }

  {
    // register method ntp_update_time
    fbtc::api::method_data ntp_update_time_method_metadata{"ntp_update_time", nullptr,
      /* description */ "Update the NTP time right now.",
      /* returns */ "void",
      /* params: */ {},
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "Update the NTP time right now.\n\nParameters:\n  (none)\n\nReturns:\n  void\n",
      /* aliases */ {}, false};
    store_method_metadata(ntp_update_time_method_metadata);
  }

  {
    // register method disk_usage
    fbtc::api::method_data disk_usage_method_metadata{"disk_usage", nullptr,
      /* description */ "Report disk space taken up by different groups of client files",
      /* returns */ "variant",
      /* params: */ {},
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "Report disk space taken up by different groups of client files\n\nParameters:\n  (none)\n\nReturns:\n  variant\n",
      /* aliases */ {"size", "sizes", "usage", "diskusage"}, false};
    store_method_metadata(disk_usage_method_metadata);
  }

  {
    // register method network_add_node
    fbtc::api::method_data network_add_node_method_metadata{"network_add_node", nullptr,
      /* description */ "Attempts add or remove <node> from the peer list or try a connection to <node> once",
      /* returns */ "void",
      /* params: */ {
        {"node", "string", fbtc::api::required_positional, fc::ovariant()},
        {"command", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"add\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "Attempts add or remove <node> from the peer list or try a connection to <node> once\n\nParameters:\n  node (string, required): The node (see network_get_peer_info for nodes)\n  command (string, optional, defaults to \"add\"): 'add' to add a node to the list, 'remove' to remove a node from the list, 'onetry' to try a connection to the node once\n\nReturns:\n  void\n",
      /* aliases */ {"addnode"}, false};
    store_method_metadata(network_add_node_method_metadata);
  }

  {
    // register method network_get_connection_count
    fbtc::api::method_data network_get_connection_count_method_metadata{"network_get_connection_count", nullptr,
      /* description */ "Returns the number of fully-established connections to other nodes",
      /* returns */ "uint32_t",
      /* params: */ {},
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "Returns the number of fully-established connections to other nodes\n\nParameters:\n  (none)\n\nReturns:\n  uint32_t\n",
      /* aliases */ {"getconnectioncount"}, false};
    store_method_metadata(network_get_connection_count_method_metadata);
  }

  {
    // register method network_get_peer_info
    fbtc::api::method_data network_get_peer_info_method_metadata{"network_get_peer_info", nullptr,
      /* description */ "Returns data about each connected node",
      /* returns */ "json_object_array",
      /* params: */ {
        {"not_firewalled", "bool", fbtc::api::optional_positional, fc::variant(fc::json::from_string("false"))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "Returns data about each connected node\n\nParameters:\n  not_firewalled (bool, optional, defaults to false): true to output only peers not behind a firewall and false otherwise\n\nReturns:\n  json_object_array\n",
      /* aliases */ {}, false};
    store_method_metadata(network_get_peer_info_method_metadata);
  }

  {
    // register method network_broadcast_transaction
    fbtc::api::method_data network_broadcast_transaction_method_metadata{"network_broadcast_transaction", nullptr,
      /* description */ "Broadcast a previously-created signed transaction to the network",
      /* returns */ "transaction_id",
      /* params: */ {
        {"transaction_to_broadcast", "signed_transaction", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 9,
      /* detailed description */ "Broadcast a previously-created signed transaction to the network\n\nParameters:\n  transaction_to_broadcast (signed_transaction, required): The transaction to broadcast to the network\n\nReturns:\n  transaction_id\n",
      /* aliases */ {}, false};
    store_method_metadata(network_broadcast_transaction_method_metadata);
  }

  {
    // register method network_set_advanced_node_parameters
    fbtc::api::method_data network_set_advanced_node_parameters_method_metadata{"network_set_advanced_node_parameters", nullptr,
      /* description */ "Sets advanced node parameters, used for setting up automated tests",
      /* returns */ "void",
      /* params: */ {
        {"params", "json_object", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "Sets advanced node parameters, used for setting up automated tests\n\nParameters:\n  params (json_object, required): A JSON object containing the name/value pairs for the parameters to set\n\nReturns:\n  void\n",
      /* aliases */ {}, false};
    store_method_metadata(network_set_advanced_node_parameters_method_metadata);
  }

  {
    // register method network_get_advanced_node_parameters
    fbtc::api::method_data network_get_advanced_node_parameters_method_metadata{"network_get_advanced_node_parameters", nullptr,
      /* description */ "Sets advanced node parameters, used for setting up automated tests",
      /* returns */ "json_object",
      /* params: */ {},
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "Sets advanced node parameters, used for setting up automated tests\n\nParameters:\n  (none)\n\nReturns:\n  json_object\n",
      /* aliases */ {}, false};
    store_method_metadata(network_get_advanced_node_parameters_method_metadata);
  }

  {
    // register method network_get_transaction_propagation_data
    fbtc::api::method_data network_get_transaction_propagation_data_method_metadata{"network_get_transaction_propagation_data", nullptr,
      /* description */ "Returns the time the transaction was first seen by this client",
      /* returns */ "message_propagation_data",
      /* params: */ {
        {"transaction_id", "transaction_id", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "Returns the time the transaction was first seen by this client\n\nThis interrogates the p2p node's message cache to find out when it first saw this transaction. The data in the message cache is only kept for a few blocks, so you can only use this to ask about recent transactions. This is intended to be used to track message propagation delays in our test network.\n\nParameters:\n  transaction_id (transaction_id, required): the id of the transaction\n\nReturns:\n  message_propagation_data\n",
      /* aliases */ {}, false};
    store_method_metadata(network_get_transaction_propagation_data_method_metadata);
  }

  {
    // register method network_get_block_propagation_data
    fbtc::api::method_data network_get_block_propagation_data_method_metadata{"network_get_block_propagation_data", nullptr,
      /* description */ "Returns the time the block was first seen by this client",
      /* returns */ "message_propagation_data",
      /* params: */ {
        {"block_hash", "block_id_type", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "Returns the time the block was first seen by this client\n\nThis interrogates the p2p node's message cache to find out when it first saw this block. The data in the message cache is only kept for a few blocks, so you can only use this to ask about recent transactions. This is intended to be used to track message propagation delays in our test network.\n\nParameters:\n  block_hash (block_id_type, required): the id of the block\n\nReturns:\n  message_propagation_data\n",
      /* aliases */ {}, false};
    store_method_metadata(network_get_block_propagation_data_method_metadata);
  }

  {
    // register method network_set_allowed_peers
    fbtc::api::method_data network_set_allowed_peers_method_metadata{"network_set_allowed_peers", nullptr,
      /* description */ "Sets the list of peers this node is allowed to connect to",
      /* returns */ "void",
      /* params: */ {
        {"allowed_peers", "node_id_list", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "Sets the list of peers this node is allowed to connect to\n\nThis function sets the list of peers we're allowed to connect to. It is used during testing to force network splits or other weird topologies.\n\nParameters:\n  allowed_peers (node_id_list, required): the list of allowable peers\n\nReturns:\n  void\n",
      /* aliases */ {}, false};
    store_method_metadata(network_set_allowed_peers_method_metadata);
  }

  {
    // register method network_get_info
    fbtc::api::method_data network_get_info_method_metadata{"network_get_info", nullptr,
      /* description */ "Returns assorted information about the network settings and connections",
      /* returns */ "json_object",
      /* params: */ {},
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "Returns assorted information about the network settings and connections\n\nParameters:\n  (none)\n\nReturns:\n  json_object\n",
      /* aliases */ {}, false};
    store_method_metadata(network_get_info_method_metadata);
  }

  {
    // register method network_list_potential_peers
    fbtc::api::method_data network_list_potential_peers_method_metadata{"network_list_potential_peers", nullptr,
      /* description */ "Returns list of potential peers",
      /* returns */ "potential_peer_record_array",
      /* params: */ {},
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "Returns list of potential peers\n\nParameters:\n  (none)\n\nReturns:\n  potential_peer_record_array\n",
      /* aliases */ {}, false};
    store_method_metadata(network_list_potential_peers_method_metadata);
  }

  {
    // register method network_get_upnp_info
    fbtc::api::method_data network_get_upnp_info_method_metadata{"network_get_upnp_info", nullptr,
      /* description */ "Get information on UPNP status including whether it's enabled and what the client believes its IP to be",
      /* returns */ "json_object",
      /* params: */ {},
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "Get information on UPNP status including whether it's enabled and what the client believes its IP to be\n\nParameters:\n  (none)\n\nReturns:\n  json_object\n",
      /* aliases */ {}, false};
    store_method_metadata(network_get_upnp_info_method_metadata);
  }

  {
    // register method network_get_usage_stats
    fbtc::api::method_data network_get_usage_stats_method_metadata{"network_get_usage_stats", nullptr,
      /* description */ "Get bandwidth usage stats",
      /* returns */ "json_object",
      /* params: */ {},
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "Get bandwidth usage stats\n\nParameters:\n  (none)\n\nReturns:\n  json_object\n",
      /* aliases */ {}, false};
    store_method_metadata(network_get_usage_stats_method_metadata);
  }

  {
    // register method delegate_get_config
    fbtc::api::method_data delegate_get_config_method_metadata{"delegate_get_config", nullptr,
      /* description */ "Returns current settings used during local block production",
      /* returns */ "variant",
      /* params: */ {},
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Returns current settings used during local block production\n\nParameters:\n  (none)\n\nReturns:\n  variant\n",
      /* aliases */ {}, false};
    store_method_metadata(delegate_get_config_method_metadata);
  }

  {
    // register method delegate_set_network_min_connection_count
    fbtc::api::method_data delegate_set_network_min_connection_count_method_metadata{"delegate_set_network_min_connection_count", nullptr,
      /* description */ "Set minimum network connection count required for block production",
      /* returns */ "void",
      /* params: */ {
        {"count", "uint32_t", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Set minimum network connection count required for block production\n\nParameters:\n  count (uint32_t, required): minimum network connection count\n\nReturns:\n  void\n",
      /* aliases */ {}, false};
    store_method_metadata(delegate_set_network_min_connection_count_method_metadata);
  }

  {
    // register method delegate_set_block_max_transaction_count
    fbtc::api::method_data delegate_set_block_max_transaction_count_method_metadata{"delegate_set_block_max_transaction_count", nullptr,
      /* description */ "Set maximum number of transactions allowed in a block",
      /* returns */ "void",
      /* params: */ {
        {"count", "uint32_t", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Set maximum number of transactions allowed in a block\n\nParameters:\n  count (uint32_t, required): maximum transaction count\n\nReturns:\n  void\n",
      /* aliases */ {}, false};
    store_method_metadata(delegate_set_block_max_transaction_count_method_metadata);
  }

  {
    // register method delegate_set_block_max_size
    fbtc::api::method_data delegate_set_block_max_size_method_metadata{"delegate_set_block_max_size", nullptr,
      /* description */ "Set maximum block size allowed",
      /* returns */ "void",
      /* params: */ {
        {"size", "uint32_t", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Set maximum block size allowed\n\nParameters:\n  size (uint32_t, required): maximum block size in bytes\n\nReturns:\n  void\n",
      /* aliases */ {}, false};
    store_method_metadata(delegate_set_block_max_size_method_metadata);
  }

  {
    // register method delegate_set_block_max_production_time
    fbtc::api::method_data delegate_set_block_max_production_time_method_metadata{"delegate_set_block_max_production_time", nullptr,
      /* description */ "Set maximum time spent producing a block",
      /* returns */ "void",
      /* params: */ {
        {"time", "uint64_t", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Set maximum time spent producing a block\n\nParameters:\n  time (uint64_t, required): maximum production time in microseconds\n\nReturns:\n  void\n",
      /* aliases */ {}, false};
    store_method_metadata(delegate_set_block_max_production_time_method_metadata);
  }

  {
    // register method delegate_set_transaction_max_size
    fbtc::api::method_data delegate_set_transaction_max_size_method_metadata{"delegate_set_transaction_max_size", nullptr,
      /* description */ "Set maximum transaction size allowed",
      /* returns */ "void",
      /* params: */ {
        {"size", "uint32_t", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Set maximum transaction size allowed\n\nParameters:\n  size (uint32_t, required): maximum transaction size in bytes\n\nReturns:\n  void\n",
      /* aliases */ {}, false};
    store_method_metadata(delegate_set_transaction_max_size_method_metadata);
  }

  {
    // register method delegate_set_transaction_canonical_signatures_required
    fbtc::api::method_data delegate_set_transaction_canonical_signatures_required_method_metadata{"delegate_set_transaction_canonical_signatures_required", nullptr,
      /* description */ "Set whether canonical signatures are required",
      /* returns */ "void",
      /* params: */ {
        {"required", "bool", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Set whether canonical signatures are required\n\nParameters:\n  required (bool, required): whether canonical signatures are required\n\nReturns:\n  void\n",
      /* aliases */ {}, false};
    store_method_metadata(delegate_set_transaction_canonical_signatures_required_method_metadata);
  }

  {
    // register method delegate_set_transaction_min_fee
    fbtc::api::method_data delegate_set_transaction_min_fee_method_metadata{"delegate_set_transaction_min_fee", nullptr,
      /* description */ "Set minimum transaction fee allowed",
      /* returns */ "void",
      /* params: */ {
        {"fee", "uint64_t", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Set minimum transaction fee allowed\n\nParameters:\n  fee (uint64_t, required): minimum transaction fee in shares\n\nReturns:\n  void\n",
      /* aliases */ {}, false};
    store_method_metadata(delegate_set_transaction_min_fee_method_metadata);
  }

  {
    // register method delegate_blacklist_add_transaction
    fbtc::api::method_data delegate_blacklist_add_transaction_method_metadata{"delegate_blacklist_add_transaction", nullptr,
      /* description */ "Add specified transaction to blacklist",
      /* returns */ "void",
      /* params: */ {
        {"id", "transaction_id", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Add specified transaction to blacklist\n\nParameters:\n  id (transaction_id, required): transaction to add to blacklist\n\nReturns:\n  void\n",
      /* aliases */ {}, false};
    store_method_metadata(delegate_blacklist_add_transaction_method_metadata);
  }

  {
    // register method delegate_blacklist_remove_transaction
    fbtc::api::method_data delegate_blacklist_remove_transaction_method_metadata{"delegate_blacklist_remove_transaction", nullptr,
      /* description */ "Remove specified transaction from blacklist",
      /* returns */ "void",
      /* params: */ {
        {"id", "transaction_id", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Remove specified transaction from blacklist\n\nParameters:\n  id (transaction_id, required): transaction to remove from blacklist\n\nReturns:\n  void\n",
      /* aliases */ {}, false};
    store_method_metadata(delegate_blacklist_remove_transaction_method_metadata);
  }

  {
    // register method delegate_blacklist_add_operation
    fbtc::api::method_data delegate_blacklist_add_operation_method_metadata{"delegate_blacklist_add_operation", nullptr,
      /* description */ "Add specified operation to blacklist",
      /* returns */ "void",
      /* params: */ {
        {"id", "operation_type", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Add specified operation to blacklist\n\nParameters:\n  id (operation_type, required): operation to add to blacklist\n\nReturns:\n  void\n",
      /* aliases */ {}, false};
    store_method_metadata(delegate_blacklist_add_operation_method_metadata);
  }

  {
    // register method delegate_blacklist_remove_operation
    fbtc::api::method_data delegate_blacklist_remove_operation_method_metadata{"delegate_blacklist_remove_operation", nullptr,
      /* description */ "Remove specified operation from blacklist",
      /* returns */ "void",
      /* params: */ {
        {"id", "operation_type", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Remove specified operation from blacklist\n\nParameters:\n  id (operation_type, required): operation to remove from blacklist\n\nReturns:\n  void\n",
      /* aliases */ {}, false};
    store_method_metadata(delegate_blacklist_remove_operation_method_metadata);
  }

  {
    // register method blockchain_get_info
    fbtc::api::method_data blockchain_get_info_method_metadata{"blockchain_get_info", nullptr,
      /* description */ "Returns current blockchain information and parameters",
      /* returns */ "json_object",
      /* params: */ {},
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Returns current blockchain information and parameters\n\nParameters:\n  (none)\n\nReturns:\n  json_object\n",
      /* aliases */ {"getconfig", "get_config", "config", "blockchain_get_config"}, true};
    store_method_metadata(blockchain_get_info_method_metadata);
  }

  {
    // register method blockchain_generate_snapshot
    fbtc::api::method_data blockchain_generate_snapshot_method_metadata{"blockchain_generate_snapshot", nullptr,
      /* description */ "Save snapshot of current base asset balances to specified file",
      /* returns */ "void",
      /* params: */ {
        {"filename", "string", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Save snapshot of current base asset balances to specified file\n\nParameters:\n  filename (string, required): filename to save snapshot to\n\nReturns:\n  void\n",
      /* aliases */ {}, false};
    store_method_metadata(blockchain_generate_snapshot_method_metadata);
  }

  {
    // register method blockchain_graphene_snapshot
    fbtc::api::method_data blockchain_graphene_snapshot_method_metadata{"blockchain_graphene_snapshot", nullptr,
      /* description */ "Save snapshot of current state to specified file in Graphene genesis format",
      /* returns */ "void",
      /* params: */ {
        {"filename", "string", fbtc::api::required_positional, fc::ovariant()},
        {"whitelist_filename", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Save snapshot of current state to specified file in Graphene genesis format\n\nParameters:\n  filename (string, required): filename to save snapshot to\n  whitelist_filename (string, optional, defaults to \"\"): filename containing set of account names to whitelist from name-prefixing\n\nReturns:\n  void\n",
      /* aliases */ {}, false};
    store_method_metadata(blockchain_graphene_snapshot_method_metadata);
  }

  {
    // register method blockchain_generate_issuance_map
    fbtc::api::method_data blockchain_generate_issuance_map_method_metadata{"blockchain_generate_issuance_map", nullptr,
      /* description */ "A utility to help verify UIA distribution. Returns a snapshot map of all issuances for a particular UIA.",
      /* returns */ "void",
      /* params: */ {
        {"symbol", "string", fbtc::api::required_positional, fc::ovariant()},
        {"filename", "string", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "A utility to help verify UIA distribution. Returns a snapshot map of all issuances for a particular UIA.\n\nParameters:\n  symbol (string, required): the UIA for which to compute issuance map\n  filename (string, required): filename to save snapshot to\n\nReturns:\n  void\n",
      /* aliases */ {}, false};
    store_method_metadata(blockchain_generate_issuance_map_method_metadata);
  }

  {
    // register method blockchain_calculate_supply
    fbtc::api::method_data blockchain_calculate_supply_method_metadata{"blockchain_calculate_supply", nullptr,
      /* description */ "Calculate the total supply of an asset from the current blockchain database state",
      /* returns */ "asset",
      /* params: */ {
        {"asset", "string", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Calculate the total supply of an asset from the current blockchain database state\n\nParameters:\n  asset (string, required): asset ticker symbol or ID to calculate supply for\n\nReturns:\n  asset\n",
      /* aliases */ {"supply", "calculate_supply"}, true};
    store_method_metadata(blockchain_calculate_supply_method_metadata);
  }

  {
    // register method blockchain_calculate_debt
    fbtc::api::method_data blockchain_calculate_debt_method_metadata{"blockchain_calculate_debt", nullptr,
      /* description */ "Calculate the total amount of a market-issued asset that is owed to the network by open short positions",
      /* returns */ "asset",
      /* params: */ {
        {"asset", "string", fbtc::api::required_positional, fc::ovariant()},
        {"include_interest", "bool", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"false\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Calculate the total amount of a market-issued asset that is owed to the network by open short positions\n\nParameters:\n  asset (string, required): asset ticker symbol or ID to calculate debt for\n  include_interest (bool, optional, defaults to \"false\"): true to include current outstanding interest and false otherwise\n\nReturns:\n  asset\n",
      /* aliases */ {"debt", "calculate_debt"}, true};
    store_method_metadata(blockchain_calculate_debt_method_metadata);
  }

  {
    // register method blockchain_calculate_max_supply
    fbtc::api::method_data blockchain_calculate_max_supply_method_metadata{"blockchain_calculate_max_supply", nullptr,
      /* description */ "Calculate the maximum possible supply of the core asset from the current time assuming a maximum dilution schedule",
      /* returns */ "asset",
      /* params: */ {
        {"average_delegate_pay_rate", "uint8_t", fbtc::api::optional_positional, fc::variant(fc::json::from_string("100"))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Calculate the maximum possible supply of the core asset from the current time assuming a maximum dilution schedule\n\nParameters:\n  average_delegate_pay_rate (uint8_t, optional, defaults to 100): average delegate pay rate percentage\n\nReturns:\n  asset\n",
      /* aliases */ {"max_supply", "calculate_max_supply"}, true};
    store_method_metadata(blockchain_calculate_max_supply_method_metadata);
  }

  {
    // register method blockchain_get_block_count
    fbtc::api::method_data blockchain_get_block_count_method_metadata{"blockchain_get_block_count", nullptr,
      /* description */ "Returns the current head block number",
      /* returns */ "uint32_t",
      /* params: */ {},
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Returns the current head block number\n\nParameters:\n  (none)\n\nReturns:\n  uint32_t\n",
      /* aliases */ {"blockchain_get_blockcount", "getblockcount"}, true};
    store_method_metadata(blockchain_get_block_count_method_metadata);
  }

  {
    // register method blockchain_list_accounts
    fbtc::api::method_data blockchain_list_accounts_method_metadata{"blockchain_list_accounts", nullptr,
      /* description */ "Returns registered accounts starting with a given name upto a the limit provided",
      /* returns */ "account_record_array",
      /* params: */ {
        {"first_account_name", "account_name", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))},
        {"limit", "uint32_t", fbtc::api::optional_positional, fc::variant(fc::json::from_string("20"))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Returns registered accounts starting with a given name upto a the limit provided\n\nParameters:\n  first_account_name (account_name, optional, defaults to \"\"): the first account name to include\n  limit (uint32_t, optional, defaults to 20): the maximum number of items to list\n\nReturns:\n  account_record_array\n",
      /* aliases */ {}, true};
    store_method_metadata(blockchain_list_accounts_method_metadata);
  }

  {
    // register method blockchain_list_recently_updated_accounts
    fbtc::api::method_data blockchain_list_recently_updated_accounts_method_metadata{"blockchain_list_recently_updated_accounts", nullptr,
      /* description */ "Returns a list of recently updated accounts",
      /* returns */ "account_record_array",
      /* params: */ {},
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Returns a list of recently updated accounts\n\nParameters:\n  (none)\n\nReturns:\n  account_record_array\n",
      /* aliases */ {}, true};
    store_method_metadata(blockchain_list_recently_updated_accounts_method_metadata);
  }

  {
    // register method blockchain_list_recently_registered_accounts
    fbtc::api::method_data blockchain_list_recently_registered_accounts_method_metadata{"blockchain_list_recently_registered_accounts", nullptr,
      /* description */ "Returns a list of recently registered accounts",
      /* returns */ "account_record_array",
      /* params: */ {},
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Returns a list of recently registered accounts\n\nParameters:\n  (none)\n\nReturns:\n  account_record_array\n",
      /* aliases */ {}, true};
    store_method_metadata(blockchain_list_recently_registered_accounts_method_metadata);
  }

  {
    // register method blockchain_list_assets
    fbtc::api::method_data blockchain_list_assets_method_metadata{"blockchain_list_assets", nullptr,
      /* description */ "Returns registered assets starting with a given name upto a the limit provided",
      /* returns */ "asset_record_array",
      /* params: */ {
        {"first_symbol", "asset_symbol", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))},
        {"limit", "uint32_t", fbtc::api::optional_positional, fc::variant(fc::json::from_string("20"))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Returns registered assets starting with a given name upto a the limit provided\n\nParameters:\n  first_symbol (asset_symbol, optional, defaults to \"\"): the prefix of the first asset symbol name to include\n  limit (uint32_t, optional, defaults to 20): the maximum number of items to list\n\nReturns:\n  asset_record_array\n",
      /* aliases */ {}, true};
    store_method_metadata(blockchain_list_assets_method_metadata);
  }

  {
    // register method blockchain_list_feed_prices
    fbtc::api::method_data blockchain_list_feed_prices_method_metadata{"blockchain_list_feed_prices", nullptr,
      /* description */ "Returns a list of all currently valid feed prices",
      /* returns */ "string_map",
      /* params: */ {},
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Returns a list of all currently valid feed prices\n\nParameters:\n  (none)\n\nReturns:\n  string_map\n",
      /* aliases */ {}, true};
    store_method_metadata(blockchain_list_feed_prices_method_metadata);
  }

  {
    // register method blockchain_get_account_wall
    fbtc::api::method_data blockchain_get_account_wall_method_metadata{"blockchain_get_account_wall", nullptr,
      /* description */ "returns all burn records associated with an account",
      /* returns */ "burn_records",
      /* params: */ {
        {"account_name", "account_name", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "returns all burn records associated with an account\n\nParameters:\n  account_name (account_name, optional, defaults to \"\"): the name of the account to fetch the burn records for\n\nReturns:\n  burn_records\n",
      /* aliases */ {"wall"}, true};
    store_method_metadata(blockchain_get_account_wall_method_metadata);
  }

  {
    // register method blockchain_list_pending_transactions
    fbtc::api::method_data blockchain_list_pending_transactions_method_metadata{"blockchain_list_pending_transactions", nullptr,
      /* description */ "Return a list of transactions that are not yet in a block.",
      /* returns */ "signed_transaction_array",
      /* params: */ {},
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Return a list of transactions that are not yet in a block.\n\nParameters:\n  (none)\n\nReturns:\n  signed_transaction_array\n",
      /* aliases */ {"blockchain_get_pending_transactions", "list_pending"}, false};
    store_method_metadata(blockchain_list_pending_transactions_method_metadata);
  }

  {
    // register method blockchain_get_pending_transactions_count
    fbtc::api::method_data blockchain_get_pending_transactions_count_method_metadata{"blockchain_get_pending_transactions_count", nullptr,
      /* description */ "Return pending transactions count.",
      /* returns */ "int32_t",
      /* params: */ {},
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Return pending transactions count.\n\nParameters:\n  (none)\n\nReturns:\n  int32_t\n",
      /* aliases */ {}, false};
    store_method_metadata(blockchain_get_pending_transactions_count_method_metadata);
  }

  {
    // register method blockchain_get_transaction
    fbtc::api::method_data blockchain_get_transaction_method_metadata{"blockchain_get_transaction", nullptr,
      /* description */ "Get detailed information about the specified transaction in the blockchain",
      /* returns */ "transaction_record_pair",
      /* params: */ {
        {"transaction_id_prefix", "string", fbtc::api::required_positional, fc::ovariant()},
        {"exact", "bool", fbtc::api::optional_positional, fc::variant(fc::json::from_string("false"))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Get detailed information about the specified transaction in the blockchain\n\nParameters:\n  transaction_id_prefix (string, required): the base58 transaction ID to return\n  exact (bool, optional, defaults to false): whether or not a partial match is ok\n\nReturns:\n  transaction_record_pair\n",
      /* aliases */ {}, true};
    store_method_metadata(blockchain_get_transaction_method_metadata);
  }

  {
    // register method blockchain_get_block
    fbtc::api::method_data blockchain_get_block_method_metadata{"blockchain_get_block", nullptr,
      /* description */ "Retrieves the block record for the given block number, ID or timestamp",
      /* returns */ "oblock_record",
      /* params: */ {
        {"block", "string", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Retrieves the block record for the given block number, ID or timestamp\n\nParameters:\n  block (string, required): timestamp, number or ID of the block to retrieve\n\nReturns:\n  oblock_record\n",
      /* aliases */ {"get_block", "getblock", "blockchain_get_block_hash", "blockchain_get_blockhash", "getblockhash"}, true};
    store_method_metadata(blockchain_get_block_method_metadata);
  }

  {
    // register method blockchain_get_block_transactions
    fbtc::api::method_data blockchain_get_block_transactions_method_metadata{"blockchain_get_block_transactions", nullptr,
      /* description */ "Retrieves the detailed transaction information for a block",
      /* returns */ "transaction_record_map",
      /* params: */ {
        {"block", "string", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Retrieves the detailed transaction information for a block\n\nParameters:\n  block (string, required): the number or id of the block to get transactions from\n\nReturns:\n  transaction_record_map\n",
      /* aliases */ {}, true};
    store_method_metadata(blockchain_get_block_transactions_method_metadata);
  }

  {
    // register method blockchain_get_account
    fbtc::api::method_data blockchain_get_account_method_metadata{"blockchain_get_account", nullptr,
      /* description */ "Retrieves the record for the given account name or ID",
      /* returns */ "optional_account_record",
      /* params: */ {
        {"account", "string", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Retrieves the record for the given account name or ID\n\nParameters:\n  account (string, required): account name, ID, or public key to retrieve the record for\n\nReturns:\n  optional_account_record\n",
      /* aliases */ {"get_account"}, true};
    store_method_metadata(blockchain_get_account_method_metadata);
  }

  {
    // register method blockchain_get_slate
    fbtc::api::method_data blockchain_get_slate_method_metadata{"blockchain_get_slate", nullptr,
      /* description */ "Retrieves a map of delegate IDs and names defined by the given slate ID or recommending account",
      /* returns */ "map<account_id_type, string>",
      /* params: */ {
        {"slate", "string", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Retrieves a map of delegate IDs and names defined by the given slate ID or recommending account\n\nParameters:\n  slate (string, required): slate ID or recommending account name for which to retrieve the slate of delegates\n\nReturns:\n  map<account_id_type, string>\n",
      /* aliases */ {"get_slate"}, true};
    store_method_metadata(blockchain_get_slate_method_metadata);
  }

  {
    // register method blockchain_get_balance
    fbtc::api::method_data blockchain_get_balance_method_metadata{"blockchain_get_balance", nullptr,
      /* description */ "Retrieves the specified balance record",
      /* returns */ "balance_record",
      /* params: */ {
        {"balance_id", "address", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Retrieves the specified balance record\n\nParameters:\n  balance_id (address, required): the ID of the balance record\n\nReturns:\n  balance_record\n",
      /* aliases */ {"get_balance"}, true};
    store_method_metadata(blockchain_get_balance_method_metadata);
  }

  {
    // register method blockchain_list_balances
    fbtc::api::method_data blockchain_list_balances_method_metadata{"blockchain_list_balances", nullptr,
      /* description */ "Lists balance records for the specified asset",
      /* returns */ "balance_record_map",
      /* params: */ {
        {"asset", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"0\""))},
        {"limit", "uint32_t", fbtc::api::optional_positional, fc::variant(fc::json::from_string("20"))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Lists balance records for the specified asset\n\nParameters:\n  asset (string, optional, defaults to \"0\"): the symbol or ID of the asset to list balances for, or empty to include all assets\n  limit (uint32_t, optional, defaults to 20): the maximum number of items to list\n\nReturns:\n  balance_record_map\n",
      /* aliases */ {"list_balances"}, true};
    store_method_metadata(blockchain_list_balances_method_metadata);
  }

  {
    // register method blockchain_list_address_balances
    fbtc::api::method_data blockchain_list_address_balances_method_metadata{"blockchain_list_address_balances", nullptr,
      /* description */ "Lists balance records which are the balance IDs or which can be claimed by signature for this address",
      /* returns */ "balance_record_map",
      /* params: */ {
        {"addr", "string", fbtc::api::required_positional, fc::ovariant()},
        {"chanced_since", "timestamp", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"1970-1-1T00:00:01\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Lists balance records which are the balance IDs or which can be claimed by signature for this address\n\nParameters:\n  addr (string, required): address to scan for\n  chanced_since (timestamp, optional, defaults to \"1970-1-1T00:00:01\"): Filter all balances that haven't chanced since the provided timestamp\n\nReturns:\n  balance_record_map\n",
      /* aliases */ {"list_address_balances"}, true};
    store_method_metadata(blockchain_list_address_balances_method_metadata);
  }

  {
    // register method blockchain_list_address_transactions
    fbtc::api::method_data blockchain_list_address_transactions_method_metadata{"blockchain_list_address_transactions", nullptr,
      /* description */ "Lists all transactions that involve the provided address after the specified time",
      /* returns */ "variant_object",
      /* params: */ {
        {"addr", "string", fbtc::api::required_positional, fc::ovariant()},
        {"filter_before", "uint32_t", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"0\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Lists all transactions that involve the provided address after the specified time\n\nParameters:\n  addr (string, required): address to scan for\n  filter_before (uint32_t, optional, defaults to \"0\"): Filter all transactions that occured prior to the specified block number\n\nReturns:\n  variant_object\n",
      /* aliases */ {"list_address_transactions"}, true};
    store_method_metadata(blockchain_list_address_transactions_method_metadata);
  }

  {
    // register method blockchain_get_account_public_balance
    fbtc::api::method_data blockchain_get_account_public_balance_method_metadata{"blockchain_get_account_public_balance", nullptr,
      /* description */ "Get the public balances associated with the specified account name; this command can take a long time",
      /* returns */ "asset_balance_map",
      /* params: */ {
        {"account_name", "account_name", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Get the public balances associated with the specified account name; this command can take a long time\n\nParameters:\n  account_name (account_name, required): the account name to query public balances for\n\nReturns:\n  asset_balance_map\n",
      /* aliases */ {}, true};
    store_method_metadata(blockchain_get_account_public_balance_method_metadata);
  }

  {
    // register method blockchain_median_feed_price
    fbtc::api::method_data blockchain_median_feed_price_method_metadata{"blockchain_median_feed_price", nullptr,
      /* description */ "Get the account record for a given name",
      /* returns */ "string",
      /* params: */ {
        {"symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Get the account record for a given name\n\nParameters:\n  symbol (asset_symbol, required): the asset symbol to fetch the median price of in FBTC\n\nReturns:\n  string\n",
      /* aliases */ {}, true};
    store_method_metadata(blockchain_median_feed_price_method_metadata);
  }

  {
    // register method blockchain_list_key_balances
    fbtc::api::method_data blockchain_list_key_balances_method_metadata{"blockchain_list_key_balances", nullptr,
      /* description */ "Lists balance records which can be claimed by signature for this key",
      /* returns */ "balance_record_map",
      /* params: */ {
        {"key", "public_key", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Lists balance records which can be claimed by signature for this key\n\nParameters:\n  key (public_key, required): Key to scan for\n\nReturns:\n  balance_record_map\n",
      /* aliases */ {"list_key_balances"}, true};
    store_method_metadata(blockchain_list_key_balances_method_metadata);
  }

  {
    // register method blockchain_get_asset
    fbtc::api::method_data blockchain_get_asset_method_metadata{"blockchain_get_asset", nullptr,
      /* description */ "Retrieves the record for the given asset ticker symbol or ID",
      /* returns */ "optional_asset_record",
      /* params: */ {
        {"asset", "string", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Retrieves the record for the given asset ticker symbol or ID\n\nParameters:\n  asset (string, required): asset ticker symbol or ID to retrieve\n\nReturns:\n  optional_asset_record\n",
      /* aliases */ {"get_asset"}, true};
    store_method_metadata(blockchain_get_asset_method_metadata);
  }

  {
    // register method blockchain_get_feeds_for_asset
    fbtc::api::method_data blockchain_get_feeds_for_asset_method_metadata{"blockchain_get_feeds_for_asset", nullptr,
      /* description */ "Retrieves all current feeds for the given asset",
      /* returns */ "feed_entry_list",
      /* params: */ {
        {"asset", "string", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Retrieves all current feeds for the given asset\n\nParameters:\n  asset (string, required): asset ticker symbol or ID to retrieve\n\nReturns:\n  feed_entry_list\n",
      /* aliases */ {}, true};
    store_method_metadata(blockchain_get_feeds_for_asset_method_metadata);
  }

  {
    // register method blockchain_get_feeds_from_delegate
    fbtc::api::method_data blockchain_get_feeds_from_delegate_method_metadata{"blockchain_get_feeds_from_delegate", nullptr,
      /* description */ "Retrieves all current feeds published by the given delegate",
      /* returns */ "feed_entry_list",
      /* params: */ {
        {"delegate_name", "string", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Retrieves all current feeds published by the given delegate\n\nParameters:\n  delegate_name (string, required): the name of the delegate to list feeds from\n\nReturns:\n  feed_entry_list\n",
      /* aliases */ {}, true};
    store_method_metadata(blockchain_get_feeds_from_delegate_method_metadata);
  }

  {
    // register method blockchain_market_list_bids
    fbtc::api::method_data blockchain_market_list_bids_method_metadata{"blockchain_market_list_bids", nullptr,
      /* description */ "Returns the bid side of the order book for a given market",
      /* returns */ "market_order_array",
      /* params: */ {
        {"quote_symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()},
        {"base_symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()},
        {"limit", "uint32_t", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"-1\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Returns the bid side of the order book for a given market\n\nParameters:\n  quote_symbol (asset_symbol, required): the symbol name the market is quoted in\n  base_symbol (asset_symbol, required): the item being bought in this market\n  limit (uint32_t, optional, defaults to \"-1\"): the maximum number of items to return, -1 for all\n\nReturns:\n  market_order_array\n",
      /* aliases */ {"market_bids"}, true};
    store_method_metadata(blockchain_market_list_bids_method_metadata);
  }

  {
    // register method blockchain_market_list_asks
    fbtc::api::method_data blockchain_market_list_asks_method_metadata{"blockchain_market_list_asks", nullptr,
      /* description */ "Returns the ask side of the order book for a given market",
      /* returns */ "market_order_array",
      /* params: */ {
        {"quote_symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()},
        {"base_symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()},
        {"limit", "uint32_t", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"-1\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Returns the ask side of the order book for a given market\n\nParameters:\n  quote_symbol (asset_symbol, required): the symbol name the market is quoted in\n  base_symbol (asset_symbol, required): the item being bought in this market\n  limit (uint32_t, optional, defaults to \"-1\"): the maximum number of items to return, -1 for all\n\nReturns:\n  market_order_array\n",
      /* aliases */ {"market_asks"}, true};
    store_method_metadata(blockchain_market_list_asks_method_metadata);
  }

  {
    // register method blockchain_market_list_shorts
    fbtc::api::method_data blockchain_market_list_shorts_method_metadata{"blockchain_market_list_shorts", nullptr,
      /* description */ "Returns the short side of the order book for a given market",
      /* returns */ "market_order_array",
      /* params: */ {
        {"quote_symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()},
        {"limit", "uint32_t", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"-1\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Returns the short side of the order book for a given market\n\nParameters:\n  quote_symbol (asset_symbol, required): the symbol name the market is quoted in\n  limit (uint32_t, optional, defaults to \"-1\"): the maximum number of items to return, -1 for all\n\nReturns:\n  market_order_array\n",
      /* aliases */ {"market_shorts"}, true};
    store_method_metadata(blockchain_market_list_shorts_method_metadata);
  }

  {
    // register method blockchain_market_list_covers
    fbtc::api::method_data blockchain_market_list_covers_method_metadata{"blockchain_market_list_covers", nullptr,
      /* description */ "Returns the covers side of the order book for a given market",
      /* returns */ "market_order_array",
      /* params: */ {
        {"quote_symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()},
        {"base_symbol", "asset_symbol", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"XTS\""))},
        {"limit", "uint32_t", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"-1\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Returns the covers side of the order book for a given market\n\nParameters:\n  quote_symbol (asset_symbol, required): the symbol name the market is quoted in\n  base_symbol (asset_symbol, optional, defaults to \"XTS\"): the symbol name the market is collateralized in\n  limit (uint32_t, optional, defaults to \"-1\"): the maximum number of items to return, -1 for all\n\nReturns:\n  market_order_array\n",
      /* aliases */ {"market_covers"}, true};
    store_method_metadata(blockchain_market_list_covers_method_metadata);
  }

  {
    // register method blockchain_market_get_asset_collateral
    fbtc::api::method_data blockchain_market_get_asset_collateral_method_metadata{"blockchain_market_get_asset_collateral", nullptr,
      /* description */ "Returns the total collateral for an asset of a given type",
      /* returns */ "share_type",
      /* params: */ {
        {"symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Returns the total collateral for an asset of a given type\n\nParameters:\n  symbol (asset_symbol, required): the symbol for the asset to count collateral for\n\nReturns:\n  share_type\n",
      /* aliases */ {"collateral"}, true};
    store_method_metadata(blockchain_market_get_asset_collateral_method_metadata);
  }

  {
    // register method blockchain_market_order_book
    fbtc::api::method_data blockchain_market_order_book_method_metadata{"blockchain_market_order_book", nullptr,
      /* description */ "Returns the long and short sides of the order book for a given market",
      /* returns */ "pair<market_order_array,market_order_array>",
      /* params: */ {
        {"quote_symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()},
        {"base_symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()},
        {"limit", "uint32_t", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"10\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Returns the long and short sides of the order book for a given market\n\nParameters:\n  quote_symbol (asset_symbol, required): the symbol name the market is quoted in\n  base_symbol (asset_symbol, required): the item being bought in this market\n  limit (uint32_t, optional, defaults to \"10\"): the maximum number of items to return, -1 for all\n\nReturns:\n  pair<market_order_array,market_order_array>\n",
      /* aliases */ {"market_book"}, true};
    store_method_metadata(blockchain_market_order_book_method_metadata);
  }

  {
    // register method blockchain_get_market_order
    fbtc::api::method_data blockchain_get_market_order_method_metadata{"blockchain_get_market_order", nullptr,
      /* description */ "Fetch an order",
      /* returns */ "market_order",
      /* params: */ {
        {"order_id", "string", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Fetch an order\n\nParameters:\n  order_id (string, required): market order id\n\nReturns:\n  market_order\n",
      /* aliases */ {}, true};
    store_method_metadata(blockchain_get_market_order_method_metadata);
  }

  {
    // register method blockchain_list_address_orders
    fbtc::api::method_data blockchain_list_address_orders_method_metadata{"blockchain_list_address_orders", nullptr,
      /* description */ "List an order list of a specific market",
      /* returns */ "market_order_map",
      /* params: */ {
        {"base_symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()},
        {"quote_symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()},
        {"account_address", "string", fbtc::api::required_positional, fc::ovariant()},
        {"limit", "uint32_t", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"10\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "List an order list of a specific market\n\nParameters:\n  base_symbol (asset_symbol, required): the base symbol of the market\n  quote_symbol (asset_symbol, required): the quote symbol of the market\n  account_address (string, required): the account for which to get the orders\n  limit (uint32_t, optional, defaults to \"10\"): the maximum number of items to return, -1 for all\n\nReturns:\n  market_order_map\n",
      /* aliases */ {}, true};
    store_method_metadata(blockchain_list_address_orders_method_metadata);
  }

  {
    // register method blockchain_market_order_history
    fbtc::api::method_data blockchain_market_order_history_method_metadata{"blockchain_market_order_history", nullptr,
      /* description */ "Returns a list of recently filled orders in a given market, in reverse order of execution.",
      /* returns */ "order_history_record_array",
      /* params: */ {
        {"quote_symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()},
        {"base_symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()},
        {"skip_count", "uint32_t", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"0\""))},
        {"limit", "uint32_t", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"20\""))},
        {"owner", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Returns a list of recently filled orders in a given market, in reverse order of execution.\n\nParameters:\n  quote_symbol (asset_symbol, required): the symbol name the market is quoted in\n  base_symbol (asset_symbol, required): the item being bought in this market\n  skip_count (uint32_t, optional, defaults to \"0\"): Number of transactions before head block to skip in listing\n  limit (uint32_t, optional, defaults to \"20\"): The maximum number of transactions to list\n  owner (string, optional, defaults to \"\"): If present, only transactions belonging to this owner key will be returned\n\nReturns:\n  order_history_record_array\n",
      /* aliases */ {}, true};
    store_method_metadata(blockchain_market_order_history_method_metadata);
  }

  {
    // register method blockchain_market_price_history
    fbtc::api::method_data blockchain_market_price_history_method_metadata{"blockchain_market_price_history", nullptr,
      /* description */ "Returns historical data on orders matched within the given timeframe for the specified market",
      /* returns */ "market_history_points",
      /* params: */ {
        {"quote_symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()},
        {"base_symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()},
        {"start_time", "timestamp", fbtc::api::required_positional, fc::ovariant()},
        {"duration", "time_interval_in_seconds", fbtc::api::required_positional, fc::ovariant()},
        {"granularity", "market_history_key::time_granularity", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"each_block\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Returns historical data on orders matched within the given timeframe for the specified market\n\nParameters:\n  quote_symbol (asset_symbol, required): the symbol name the market is quoted in\n  base_symbol (asset_symbol, required): the item being bought in this market\n  start_time (timestamp, required): The time to begin getting price history for\n  duration (time_interval_in_seconds, required): The maximum time period to get price history for\n  granularity (market_history_key::time_granularity, optional, defaults to \"each_block\"): The frequency of price updates (each_block, each_hour, or each_day)\n\nReturns:\n  market_history_points\n",
      /* aliases */ {}, true};
    store_method_metadata(blockchain_market_price_history_method_metadata);
  }

  {
    // register method blockchain_list_active_delegates
    fbtc::api::method_data blockchain_list_active_delegates_method_metadata{"blockchain_list_active_delegates", nullptr,
      /* description */ "Returns a list of the current round's active delegates in signing order",
      /* returns */ "account_record_array",
      /* params: */ {
        {"first", "uint32_t", fbtc::api::optional_positional, fc::variant(fc::json::from_string("0"))},
        {"count", "uint32_t", fbtc::api::optional_positional, fc::variant(fc::json::from_string("20"))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Returns a list of the current round's active delegates in signing order\n\nParameters:\n  first (uint32_t, optional, defaults to 0): \n  count (uint32_t, optional, defaults to 20): \n\nReturns:\n  account_record_array\n",
      /* aliases */ {"blockchain_get_active_delegates"}, true};
    store_method_metadata(blockchain_list_active_delegates_method_metadata);
  }

  {
    // register method blockchain_list_delegates
    fbtc::api::method_data blockchain_list_delegates_method_metadata{"blockchain_list_delegates", nullptr,
      /* description */ "Returns a list of all the delegates sorted by vote",
      /* returns */ "account_record_array",
      /* params: */ {
        {"first", "uint32_t", fbtc::api::optional_positional, fc::variant(fc::json::from_string("0"))},
        {"count", "uint32_t", fbtc::api::optional_positional, fc::variant(fc::json::from_string("20"))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Returns a list of all the delegates sorted by vote\n\nParameters:\n  first (uint32_t, optional, defaults to 0): \n  count (uint32_t, optional, defaults to 20): \n\nReturns:\n  account_record_array\n",
      /* aliases */ {"blockchain_get_delegates"}, true};
    store_method_metadata(blockchain_list_delegates_method_metadata);
  }

  {
    // register method blockchain_list_blocks
    fbtc::api::method_data blockchain_list_blocks_method_metadata{"blockchain_list_blocks", nullptr,
      /* description */ "Returns a descending list of block records starting from the specified block number",
      /* returns */ "block_record_array",
      /* params: */ {
        {"max_block_num", "uint32_t", fbtc::api::optional_positional, fc::variant(fc::json::from_string("-1"))},
        {"limit", "uint32_t", fbtc::api::optional_positional, fc::variant(fc::json::from_string("20"))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Returns a descending list of block records starting from the specified block number\n\nParameters:\n  max_block_num (uint32_t, optional, defaults to -1): the block num to start from; negative to count backwards from the current head block\n  limit (uint32_t, optional, defaults to 20): max number of blocks to return\n\nReturns:\n  block_record_array\n",
      /* aliases */ {"list_blocks"}, true};
    store_method_metadata(blockchain_list_blocks_method_metadata);
  }

  {
    // register method blockchain_list_missing_block_delegates
    fbtc::api::method_data blockchain_list_missing_block_delegates_method_metadata{"blockchain_list_missing_block_delegates", nullptr,
      /* description */ "Returns any delegates who were supposed to produce a given block number but didn't",
      /* returns */ "account_name_array",
      /* params: */ {
        {"block_number", "uint32_t", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Returns any delegates who were supposed to produce a given block number but didn't\n\nParameters:\n  block_number (uint32_t, required): The block to examine\n\nReturns:\n  account_name_array\n",
      /* aliases */ {}, true};
    store_method_metadata(blockchain_list_missing_block_delegates_method_metadata);
  }

  {
    // register method blockchain_export_fork_graph
    fbtc::api::method_data blockchain_export_fork_graph_method_metadata{"blockchain_export_fork_graph", nullptr,
      /* description */ "dumps the fork data to graphviz format",
      /* returns */ "string",
      /* params: */ {
        {"start_block", "uint32_t", fbtc::api::optional_positional, fc::variant(fc::json::from_string("1"))},
        {"end_block", "uint32_t", fbtc::api::optional_positional, fc::variant(fc::json::from_string("-1"))},
        {"filename", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "dumps the fork data to graphviz format\n\nParameters:\n  start_block (uint32_t, optional, defaults to 1): the first block number to consider\n  end_block (uint32_t, optional, defaults to -1): the last block number to consider\n  filename (string, optional, defaults to \"\"): the filename to save to\n\nReturns:\n  string\n",
      /* aliases */ {"export_forks"}, false};
    store_method_metadata(blockchain_export_fork_graph_method_metadata);
  }

  {
    // register method blockchain_list_forks
    fbtc::api::method_data blockchain_list_forks_method_metadata{"blockchain_list_forks", nullptr,
      /* description */ "returns a list of all blocks for which there is a fork off of the main chain",
      /* returns */ "map<uint32_t, vector<fork_record>>",
      /* params: */ {},
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "returns a list of all blocks for which there is a fork off of the main chain\n\nParameters:\n  (none)\n\nReturns:\n  map<uint32_t, vector<fork_record>>\n",
      /* aliases */ {"list_forks"}, true};
    store_method_metadata(blockchain_list_forks_method_metadata);
  }

  {
    // register method blockchain_get_delegate_slot_records
    fbtc::api::method_data blockchain_get_delegate_slot_records_method_metadata{"blockchain_get_delegate_slot_records", nullptr,
      /* description */ "Query the most recent block production slot records for the specified delegate",
      /* returns */ "slot_records_list",
      /* params: */ {
        {"delegate_name", "string", fbtc::api::required_positional, fc::ovariant()},
        {"limit", "uint32_t", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"10\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Query the most recent block production slot records for the specified delegate\n\nParameters:\n  delegate_name (string, required): Delegate whose block production slot records to query\n  limit (uint32_t, optional, defaults to \"10\"): The maximum number of slot records to return\n\nReturns:\n  slot_records_list\n",
      /* aliases */ {"get_slot"}, true};
    store_method_metadata(blockchain_get_delegate_slot_records_method_metadata);
  }

  {
    // register method blockchain_get_block_signee
    fbtc::api::method_data blockchain_get_block_signee_method_metadata{"blockchain_get_block_signee", nullptr,
      /* description */ "Get the delegate that signed a given block",
      /* returns */ "string",
      /* params: */ {
        {"block", "string", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Get the delegate that signed a given block\n\nParameters:\n  block (string, required): block number or ID to retrieve the signee for\n\nReturns:\n  string\n",
      /* aliases */ {}, true};
    store_method_metadata(blockchain_get_block_signee_method_metadata);
  }

  {
    // register method blockchain_list_markets
    fbtc::api::method_data blockchain_list_markets_method_metadata{"blockchain_list_markets", nullptr,
      /* description */ "Returns a list of active markets",
      /* returns */ "market_status_array",
      /* params: */ {},
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Returns a list of active markets\n\nParameters:\n  (none)\n\nReturns:\n  market_status_array\n",
      /* aliases */ {}, true};
    store_method_metadata(blockchain_list_markets_method_metadata);
  }

  {
    // register method blockchain_list_market_transactions
    fbtc::api::method_data blockchain_list_market_transactions_method_metadata{"blockchain_list_market_transactions", nullptr,
      /* description */ "Returns a list of market transactions executed on a given block.",
      /* returns */ "market_transaction_array",
      /* params: */ {
        {"block_number", "uint32_t", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Returns a list of market transactions executed on a given block.\n\nParameters:\n  block_number (uint32_t, required): Block to get market operations for.\n\nReturns:\n  market_transaction_array\n",
      /* aliases */ {}, true};
    store_method_metadata(blockchain_list_market_transactions_method_metadata);
  }

  {
    // register method blockchain_market_status
    fbtc::api::method_data blockchain_market_status_method_metadata{"blockchain_market_status", nullptr,
      /* description */ "Returns the status of a particular market, including any trading errors.",
      /* returns */ "market_status",
      /* params: */ {
        {"quote_symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()},
        {"base_symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Returns the status of a particular market, including any trading errors.\n\nParameters:\n  quote_symbol (asset_symbol, required): quote symbol\n  base_symbol (asset_symbol, required): base symbol\n\nReturns:\n  market_status\n",
      /* aliases */ {}, true};
    store_method_metadata(blockchain_market_status_method_metadata);
  }

  {
    // register method blockchain_unclaimed_genesis
    fbtc::api::method_data blockchain_unclaimed_genesis_method_metadata{"blockchain_unclaimed_genesis", nullptr,
      /* description */ "Returns the total shares in the genesis block which have never been fully or partially claimed.",
      /* returns */ "asset",
      /* params: */ {},
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Returns the total shares in the genesis block which have never been fully or partially claimed.\n\nParameters:\n  (none)\n\nReturns:\n  asset\n",
      /* aliases */ {}, true};
    store_method_metadata(blockchain_unclaimed_genesis_method_metadata);
  }

  {
    // register method blockchain_verify_signature
    fbtc::api::method_data blockchain_verify_signature_method_metadata{"blockchain_verify_signature", nullptr,
      /* description */ "Verify that the given signature proves the given hash was signed by the given account.",
      /* returns */ "bool",
      /* params: */ {
        {"signer", "string", fbtc::api::required_positional, fc::ovariant()},
        {"hash", "sha256", fbtc::api::required_positional, fc::ovariant()},
        {"signature", "compact_signature", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Verify that the given signature proves the given hash was signed by the given account.\n\nParameters:\n  signer (string, required): A public key, address, or account name whose signature to check\n  hash (sha256, required): The hash the signature claims to be for\n  signature (compact_signature, required): A signature produced by wallet_sign_hash\n\nReturns:\n  bool\n",
      /* aliases */ {"verify_signature", "verify_sig", "blockchain_verify_sig"}, true};
    store_method_metadata(blockchain_verify_signature_method_metadata);
  }

  {
    // register method blockchain_broadcast_transaction
    fbtc::api::method_data blockchain_broadcast_transaction_method_metadata{"blockchain_broadcast_transaction", nullptr,
      /* description */ "Takes a signed transaction and broadcasts it to the network.",
      /* returns */ "void",
      /* params: */ {
        {"trx", "signed_transaction", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Takes a signed transaction and broadcasts it to the network.\n\nParameters:\n  trx (signed_transaction, required): The transaction to broadcast\n\nReturns:\n  void\n",
      /* aliases */ {}, true};
    store_method_metadata(blockchain_broadcast_transaction_method_metadata);
  }

  {
    // register method wallet_get_info
    fbtc::api::method_data wallet_get_info_method_metadata{"wallet_get_info", nullptr,
      /* description */ "Extra information about the wallet.",
      /* returns */ "json_object",
      /* params: */ {},
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "Extra information about the wallet.\n\nParameters:\n  (none)\n\nReturns:\n  json_object\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_get_info_method_metadata);
  }

  {
    // register method wallet_open
    fbtc::api::method_data wallet_open_method_metadata{"wallet_open", nullptr,
      /* description */ "Opens the wallet of the given name",
      /* returns */ "void",
      /* params: */ {
        {"wallet_name", "wallet_name", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "Opens the wallet of the given name\n\nParameters:\n  wallet_name (wallet_name, required): the name of the wallet to open\n\nReturns:\n  void\n",
      /* aliases */ {"open"}, false};
    store_method_metadata(wallet_open_method_metadata);
  }

  {
    // register method wallet_get_account_public_address
    fbtc::api::method_data wallet_get_account_public_address_method_metadata{"wallet_get_account_public_address", nullptr,
      /* description */ "Get the account entry for a given name",
      /* returns */ "string",
      /* params: */ {
        {"account_name", "account_name", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "Get the account entry for a given name\n\nParameters:\n  account_name (account_name, required): the name of the account whose public address you want\n\nReturns:\n  string\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_get_account_public_address_method_metadata);
  }

  {
    // register method wallet_list_my_addresses
    fbtc::api::method_data wallet_list_my_addresses_method_metadata{"wallet_list_my_addresses", nullptr,
      /* description */ "Lists all accounts and account addresses for which we have a private key in this wallet",
      /* returns */ "account_address_data_array",
      /* params: */ {},
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "Lists all accounts and account addresses for which we have a private key in this wallet\n\nParameters:\n  (none)\n\nReturns:\n  account_address_data_array\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_list_my_addresses_method_metadata);
  }

  {
    // register method wallet_create
    fbtc::api::method_data wallet_create_method_metadata{"wallet_create", nullptr,
      /* description */ "Creates a wallet with the given name",
      /* returns */ "void",
      /* params: */ {
        {"wallet_name", "wallet_name", fbtc::api::required_positional, fc::ovariant()},
        {"new_passphrase", "new_passphrase", fbtc::api::required_positional, fc::ovariant()},
        {"brain_key", "brainkey", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))},
        {"new_passphrase_verify", "passphrase", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "Creates a wallet with the given name\n\nParameters:\n  wallet_name (wallet_name, required): name of the wallet to create\n  new_passphrase (new_passphrase, required): a passphrase for encrypting the wallet; must be surrounded with quotes if contains spaces\n  brain_key (brainkey, optional, defaults to \"\"): a strong passphrase that will be used to generate all private keys, defaults to a large random number\n  new_passphrase_verify (passphrase, optional, defaults to \"\"): optionally provide passphrase again to double-check\n\nReturns:\n  void\n",
      /* aliases */ {"create"}, false};
    store_method_metadata(wallet_create_method_metadata);
  }

  {
    // register method wallet_import_private_key
    fbtc::api::method_data wallet_import_private_key_method_metadata{"wallet_import_private_key", nullptr,
      /* description */ "Loads the private key into the specified account. Returns which account it was actually imported to.",
      /* returns */ "account_name",
      /* params: */ {
        {"wif_key", "wif_private_key", fbtc::api::required_positional, fc::ovariant()},
        {"account_name", "account_name", fbtc::api::optional_positional, fc::variant(fc::json::from_string("null"))},
        {"create_new_account", "bool", fbtc::api::optional_positional, fc::variant(fc::json::from_string("false"))},
        {"rescan", "bool", fbtc::api::optional_positional, fc::variant(fc::json::from_string("false"))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Loads the private key into the specified account. Returns which account it was actually imported to.\n\nParameters:\n  wif_key (wif_private_key, required): A private key in bitcoin Wallet Import Format (WIF)\n  account_name (account_name, optional, defaults to null): the name of the account the key should be imported into, if null then the key must belong to an active account\n  create_new_account (bool, optional, defaults to false): If true, the wallet will attempt to create a new account for the name provided rather than import the key into an existing account\n  rescan (bool, optional, defaults to false): If true, the wallet will rescan the blockchain looking for transactions that involve this private key\n\nReturns:\n  account_name\n",
      /* aliases */ {"import_key", "importprivkey"}, false};
    store_method_metadata(wallet_import_private_key_method_metadata);
  }

  {
    // register method wallet_import_bitcoin
    fbtc::api::method_data wallet_import_bitcoin_method_metadata{"wallet_import_bitcoin", nullptr,
      /* description */ "Imports a Bitcoin Core or FastBitcoin PTS wallet",
      /* returns */ "uint32_t",
      /* params: */ {
        {"wallet_filename", "filename", fbtc::api::required_positional, fc::ovariant()},
        {"passphrase", "passphrase", fbtc::api::required_positional, fc::ovariant()},
        {"account_name", "account_name", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Imports a Bitcoin Core or FastBitcoin PTS wallet\n\nParameters:\n  wallet_filename (filename, required): the Bitcoin/PTS wallet file path\n  passphrase (passphrase, required): the imported wallet's password\n  account_name (account_name, required): the account to receive the contents of the wallet\n\nReturns:\n  uint32_t\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_import_bitcoin_method_metadata);
  }

  {
    // register method wallet_import_electrum
    fbtc::api::method_data wallet_import_electrum_method_metadata{"wallet_import_electrum", nullptr,
      /* description */ "Imports an Electrum wallet",
      /* returns */ "uint32_t",
      /* params: */ {
        {"wallet_filename", "filename", fbtc::api::required_positional, fc::ovariant()},
        {"passphrase", "passphrase", fbtc::api::required_positional, fc::ovariant()},
        {"account_name", "account_name", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Imports an Electrum wallet\n\nParameters:\n  wallet_filename (filename, required): the Electrum wallet file path\n  passphrase (passphrase, required): the imported wallet's password\n  account_name (account_name, required): the account to receive the contents of the wallet\n\nReturns:\n  uint32_t\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_import_electrum_method_metadata);
  }

  {
    // register method wallet_import_keyhotee
    fbtc::api::method_data wallet_import_keyhotee_method_metadata{"wallet_import_keyhotee", nullptr,
      /* description */ "Create the key from keyhotee config and import it to the wallet, creating a new account using this key",
      /* returns */ "void",
      /* params: */ {
        {"firstname", "name", fbtc::api::required_positional, fc::ovariant()},
        {"middlename", "name", fbtc::api::required_positional, fc::ovariant()},
        {"lastname", "name", fbtc::api::required_positional, fc::ovariant()},
        {"brainkey", "brainkey", fbtc::api::required_positional, fc::ovariant()},
        {"keyhoteeid", "keyhoteeid", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Create the key from keyhotee config and import it to the wallet, creating a new account using this key\n\nParameters:\n  firstname (name, required): first name in keyhotee profile config, for salting the seed of private key\n  middlename (name, required): middle name in keyhotee profile config, for salting the seed of private key\n  lastname (name, required): last name in keyhotee profile config, for salting the seed of private key\n  brainkey (brainkey, required): brainkey in keyhotee profile config, for salting the seed of private key\n  keyhoteeid (keyhoteeid, required): using keyhotee id as account name\n\nReturns:\n  void\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_import_keyhotee_method_metadata);
  }

  {
    // register method wallet_import_keys_from_json
    fbtc::api::method_data wallet_import_keys_from_json_method_metadata{"wallet_import_keys_from_json", nullptr,
      /* description */ "Imports anything that looks like a private key from the given JSON file.",
      /* returns */ "uint32_t",
      /* params: */ {
        {"json_filename", "filename", fbtc::api::required_positional, fc::ovariant()},
        {"imported_wallet_passphrase", "passphrase", fbtc::api::required_positional, fc::ovariant()},
        {"account", "account_name", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "Imports anything that looks like a private key from the given JSON file.\n\nParameters:\n  json_filename (filename, required): the full path and filename of JSON wallet to import\n  imported_wallet_passphrase (passphrase, required): passphrase for encrypted keys\n  account (account_name, required): Account into which to import keys.\n\nReturns:\n  uint32_t\n",
      /* aliases */ {"import_keys_from_json"}, false};
    store_method_metadata(wallet_import_keys_from_json_method_metadata);
  }

  {
    // register method wallet_close
    fbtc::api::method_data wallet_close_method_metadata{"wallet_close", nullptr,
      /* description */ "Closes the curent wallet if one is open",
      /* returns */ "void",
      /* params: */ {},
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Closes the curent wallet if one is open\n\nParameters:\n  (none)\n\nReturns:\n  void\n",
      /* aliases */ {"close"}, false};
    store_method_metadata(wallet_close_method_metadata);
  }

  {
    // register method wallet_backup_create
    fbtc::api::method_data wallet_backup_create_method_metadata{"wallet_backup_create", nullptr,
      /* description */ "Exports the current wallet to a JSON file",
      /* returns */ "void",
      /* params: */ {
        {"json_filename", "filename", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "Exports the current wallet to a JSON file\n\nParameters:\n  json_filename (filename, required): the full path and filename of JSON file to generate\n\nReturns:\n  void\n",
      /* aliases */ {"backupwallet", "wallet_export_to_json"}, false};
    store_method_metadata(wallet_backup_create_method_metadata);
  }

  {
    // register method wallet_backup_restore
    fbtc::api::method_data wallet_backup_restore_method_metadata{"wallet_backup_restore", nullptr,
      /* description */ "Creates a new wallet from an exported JSON file",
      /* returns */ "void",
      /* params: */ {
        {"json_filename", "filename", fbtc::api::required_positional, fc::ovariant()},
        {"wallet_name", "wallet_name", fbtc::api::required_positional, fc::ovariant()},
        {"imported_wallet_passphrase", "passphrase", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "Creates a new wallet from an exported JSON file\n\nParameters:\n  json_filename (filename, required): the full path and filename of JSON wallet to import\n  wallet_name (wallet_name, required): name of the wallet to create\n  imported_wallet_passphrase (passphrase, required): passphrase of the imported wallet\n\nReturns:\n  void\n",
      /* aliases */ {"wallet_create_from_json"}, false};
    store_method_metadata(wallet_backup_restore_method_metadata);
  }

  {
    // register method wallet_export_keys
    fbtc::api::method_data wallet_export_keys_method_metadata{"wallet_export_keys", nullptr,
      /* description */ "Exports encrypted keys to a JSON file",
      /* returns */ "void",
      /* params: */ {
        {"json_filename", "filename", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "Exports encrypted keys to a JSON file\n\nParameters:\n  json_filename (filename, required): the full path and filename of JSON file to generate\n\nReturns:\n  void\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_export_keys_method_metadata);
  }

  {
    // register method wallet_set_automatic_backups
    fbtc::api::method_data wallet_set_automatic_backups_method_metadata{"wallet_set_automatic_backups", nullptr,
      /* description */ "Enables or disables automatic wallet backups",
      /* returns */ "bool",
      /* params: */ {
        {"enabled", "bool", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "Enables or disables automatic wallet backups\n\nParameters:\n  enabled (bool, required): true to enable and false to disable\n\nReturns:\n  bool\n",
      /* aliases */ {"auto_backup", "autobackup"}, false};
    store_method_metadata(wallet_set_automatic_backups_method_metadata);
  }

  {
    // register method wallet_set_transaction_expiration_time
    fbtc::api::method_data wallet_set_transaction_expiration_time_method_metadata{"wallet_set_transaction_expiration_time", nullptr,
      /* description */ "Set transaction expiration time",
      /* returns */ "uint32_t",
      /* params: */ {
        {"seconds", "uint32_t", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "Set transaction expiration time\n\nParameters:\n  seconds (uint32_t, required): seconds before new transactions expire\n\nReturns:\n  uint32_t\n",
      /* aliases */ {"set_expiration"}, false};
    store_method_metadata(wallet_set_transaction_expiration_time_method_metadata);
  }

  {
    // register method wallet_account_transaction_history
    fbtc::api::method_data wallet_account_transaction_history_method_metadata{"wallet_account_transaction_history", nullptr,
      /* description */ "Lists transaction history for the specified account",
      /* returns */ "pretty_transactions",
      /* params: */ {
        {"account_name", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))},
        {"asset_symbol", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))},
        {"limit", "int32_t", fbtc::api::optional_positional, fc::variant(fc::json::from_string("0"))},
        {"start_block_num", "uint32_t", fbtc::api::optional_positional, fc::variant(fc::json::from_string("0"))},
        {"end_block_num", "uint32_t", fbtc::api::optional_positional, fc::variant(fc::json::from_string("-1"))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "Lists transaction history for the specified account\n\nParameters:\n  account_name (string, optional, defaults to \"\"): the name of the account for which the transaction history will be returned, \"\" for all accounts\n  asset_symbol (string, optional, defaults to \"\"): only include transactions involving the specified asset, or \"\" to include all\n  limit (int32_t, optional, defaults to 0): limit the number of returned transactions; negative for most recent and positive for least recent. 0 does not limit\n  start_block_num (uint32_t, optional, defaults to 0): the earliest block number to list transactions from; 0 to include all transactions starting from genesis\n  end_block_num (uint32_t, optional, defaults to -1): the latest block to list transaction from; -1 to include all transactions ending at the head block\n\nReturns:\n  pretty_transactions\n",
      /* aliases */ {"history", "listtransactions"}, false};
    store_method_metadata(wallet_account_transaction_history_method_metadata);
  }

  {
    // register method wallet_account_historic_balance
    fbtc::api::method_data wallet_account_historic_balance_method_metadata{"wallet_account_historic_balance", nullptr,
      /* description */ "Lists wallet's balance at the given time",
      /* returns */ "account_balance_summary_type",
      /* params: */ {
        {"time", "timestamp", fbtc::api::required_positional, fc::ovariant()},
        {"account_name", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "Lists wallet's balance at the given time\n\nParameters:\n  time (timestamp, required): the date and time for which the balance will be computed\n  account_name (string, optional, defaults to \"\"): the name of the account for which the historic balance will be returned, \"\" for all accounts\n\nReturns:\n  account_balance_summary_type\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_account_historic_balance_method_metadata);
  }

  {
    // register method wallet_transaction_history_experimental
    fbtc::api::method_data wallet_transaction_history_experimental_method_metadata{"wallet_transaction_history_experimental", nullptr,
      /* description */ "",
      /* returns */ "experimental_transactions",
      /* params: */ {
        {"account_name", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "\n\nParameters:\n  account_name (string, optional, defaults to \"\"): the name of the account for which the transaction history will be returned, \"\" for all accounts\n\nReturns:\n  experimental_transactions\n",
      /* aliases */ {"hx"}, false};
    store_method_metadata(wallet_transaction_history_experimental_method_metadata);
  }

  {
    // register method wallet_remove_transaction
    fbtc::api::method_data wallet_remove_transaction_method_metadata{"wallet_remove_transaction", nullptr,
      /* description */ "Removes the specified transaction record from your transaction history. USE WITH CAUTION! Rescan cannot reconstruct all transaction details",
      /* returns */ "void",
      /* params: */ {
        {"transaction_id", "string", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Removes the specified transaction record from your transaction history. USE WITH CAUTION! Rescan cannot reconstruct all transaction details\n\nParameters:\n  transaction_id (string, required): the id (or id prefix) of the transaction record\n\nReturns:\n  void\n",
      /* aliases */ {"remove_transaction", "wallet_transaction_remove"}, false};
    store_method_metadata(wallet_remove_transaction_method_metadata);
  }

  {
    // register method wallet_get_pending_transaction_errors
    fbtc::api::method_data wallet_get_pending_transaction_errors_method_metadata{"wallet_get_pending_transaction_errors", nullptr,
      /* description */ "Return any errors for your currently pending transactions",
      /* returns */ "map<transaction_id_type, fc::exception>",
      /* params: */ {
        {"filename", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "Return any errors for your currently pending transactions\n\nParameters:\n  filename (string, optional, defaults to \"\"): filename to save pending transaction errors to\n\nReturns:\n  map<transaction_id_type, fc::exception>\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_get_pending_transaction_errors_method_metadata);
  }

  {
    // register method wallet_lock
    fbtc::api::method_data wallet_lock_method_metadata{"wallet_lock", nullptr,
      /* description */ "Lock the private keys in wallet, disables spending commands until unlocked",
      /* returns */ "void",
      /* params: */ {},
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "Lock the private keys in wallet, disables spending commands until unlocked\n\nParameters:\n  (none)\n\nReturns:\n  void\n",
      /* aliases */ {"lock"}, false};
    store_method_metadata(wallet_lock_method_metadata);
  }

  {
    // register method wallet_unlock
    fbtc::api::method_data wallet_unlock_method_metadata{"wallet_unlock", nullptr,
      /* description */ "Unlock the private keys in the wallet to enable spending operations",
      /* returns */ "void",
      /* params: */ {
        {"timeout", "uint32_t", fbtc::api::required_positional, fc::ovariant()},
        {"passphrase", "passphrase", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "Unlock the private keys in the wallet to enable spending operations\n\nParameters:\n  timeout (uint32_t, required): the number of seconds to keep the wallet unlocked\n  passphrase (passphrase, required): the passphrase for encrypting the wallet\n\nReturns:\n  void\n",
      /* aliases */ {"unlock", "walletpassphrase"}, false};
    store_method_metadata(wallet_unlock_method_metadata);
  }

  {
    // register method wallet_change_passphrase
    fbtc::api::method_data wallet_change_passphrase_method_metadata{"wallet_change_passphrase", nullptr,
      /* description */ "Change the password of the current wallet",
      /* returns */ "void",
      /* params: */ {
        {"new_passphrase", "new_passphrase", fbtc::api::required_positional, fc::ovariant()},
        {"new_passphrase_verify", "passphrase", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Change the password of the current wallet\n\nThis will change the wallet's spending passphrase, please make sure you remember it.\n\nParameters:\n  new_passphrase (new_passphrase, required): the new passphrase for encrypting the wallet; must be surrounded with quotes if contains spaces\n  new_passphrase_verify (passphrase, optional, defaults to \"\"): optionally provide passphrase again to double-check\n\nReturns:\n  void\n",
      /* aliases */ {"walletpassphrasechange"}, false};
    store_method_metadata(wallet_change_passphrase_method_metadata);
  }

  {
    // register method wallet_list
    fbtc::api::method_data wallet_list_method_metadata{"wallet_list", nullptr,
      /* description */ "Return a list of wallets in the current data directory",
      /* returns */ "wallet_name_array",
      /* params: */ {},
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "Return a list of wallets in the current data directory\n\nParameters:\n  (none)\n\nReturns:\n  wallet_name_array\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_list_method_metadata);
  }

  {
    // register method wallet_account_create
    fbtc::api::method_data wallet_account_create_method_metadata{"wallet_account_create", nullptr,
      /* description */ "Add new account for receiving payments",
      /* returns */ "public_key",
      /* params: */ {
        {"account_name", "account_name", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Add new account for receiving payments\n\nParameters:\n  account_name (account_name, required): the name you will use to refer to this receive account\n\nReturns:\n  public_key\n",
      /* aliases */ {"wallet_create_account", "create_account"}, false};
    store_method_metadata(wallet_account_create_method_metadata);
  }

  {
    // register method wallet_list_contacts
    fbtc::api::method_data wallet_list_contacts_method_metadata{"wallet_list_contacts", nullptr,
      /* description */ "List all contact entries",
      /* returns */ "wallet_contact_record_array",
      /* params: */ {},
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "List all contact entries\n\nParameters:\n  (none)\n\nReturns:\n  wallet_contact_record_array\n",
      /* aliases */ {"contacts", "get_contacts", "list_contacts"}, false};
    store_method_metadata(wallet_list_contacts_method_metadata);
  }

  {
    // register method wallet_get_contact
    fbtc::api::method_data wallet_get_contact_method_metadata{"wallet_get_contact", nullptr,
      /* description */ "Get the specified contact entry",
      /* returns */ "owallet_contact_record",
      /* params: */ {
        {"contact", "string", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "Get the specified contact entry\n\nParameters:\n  contact (string, required): the value or label (prefixed by \"label:\") of the contact to query\n\nReturns:\n  owallet_contact_record\n",
      /* aliases */ {"contact", "get_contact"}, false};
    store_method_metadata(wallet_get_contact_method_metadata);
  }

  {
    // register method wallet_add_contact
    fbtc::api::method_data wallet_add_contact_method_metadata{"wallet_add_contact", nullptr,
      /* description */ "Add a new contact entry or update the label for an existing entry",
      /* returns */ "wallet_contact_record",
      /* params: */ {
        {"contact", "string", fbtc::api::required_positional, fc::ovariant()},
        {"label", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "Add a new contact entry or update the label for an existing entry\n\nParameters:\n  contact (string, required): a registered account name, a public key, an address, or a btc address that represents this contact\n  label (string, optional, defaults to \"\"): an optional custom label to use when referring to this contact\n\nReturns:\n  wallet_contact_record\n",
      /* aliases */ {"add_contact", "update_contact"}, false};
    store_method_metadata(wallet_add_contact_method_metadata);
  }

  {
    // register method wallet_remove_contact
    fbtc::api::method_data wallet_remove_contact_method_metadata{"wallet_remove_contact", nullptr,
      /* description */ "Remove a contact entry",
      /* returns */ "owallet_contact_record",
      /* params: */ {
        {"contact", "string", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "Remove a contact entry\n\nParameters:\n  contact (string, required): the value or label (prefixed by \"label:\") of the contact to remove\n\nReturns:\n  owallet_contact_record\n",
      /* aliases */ {"remove_contact"}, false};
    store_method_metadata(wallet_remove_contact_method_metadata);
  }

  {
    // register method wallet_list_approvals
    fbtc::api::method_data wallet_list_approvals_method_metadata{"wallet_list_approvals", nullptr,
      /* description */ "List all approval entries",
      /* returns */ "wallet_approval_record_array",
      /* params: */ {},
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "List all approval entries\n\nParameters:\n  (none)\n\nReturns:\n  wallet_approval_record_array\n",
      /* aliases */ {"approvals", "get_approvals", "list_approvals"}, false};
    store_method_metadata(wallet_list_approvals_method_metadata);
  }

  {
    // register method wallet_get_approval
    fbtc::api::method_data wallet_get_approval_method_metadata{"wallet_get_approval", nullptr,
      /* description */ "Get the specified approval entry",
      /* returns */ "owallet_approval_record",
      /* params: */ {
        {"approval", "string", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "Get the specified approval entry\n\nParameters:\n  approval (string, required): the name of the approval to query\n\nReturns:\n  owallet_approval_record\n",
      /* aliases */ {"approval", "get_approval"}, false};
    store_method_metadata(wallet_get_approval_method_metadata);
  }

  {
    // register method wallet_approve
    fbtc::api::method_data wallet_approve_method_metadata{"wallet_approve", nullptr,
      /* description */ "Approve or disapprove the specified account or proposal",
      /* returns */ "wallet_approval_record",
      /* params: */ {
        {"name", "string", fbtc::api::required_positional, fc::ovariant()},
        {"approval", "int8_t", fbtc::api::optional_positional, fc::variant(fc::json::from_string("1"))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "Approve or disapprove the specified account or proposal\n\nParameters:\n  name (string, required): a registered account or proposal name to set approval for\n  approval (int8_t, optional, defaults to 1): 1, 0, or -1 respectively for approve, neutral, or disapprove\n\nReturns:\n  wallet_approval_record\n",
      /* aliases */ {"approve", "add_approval", "update_approval"}, false};
    store_method_metadata(wallet_approve_method_metadata);
  }

  {
    // register method wallet_burn
    fbtc::api::method_data wallet_burn_method_metadata{"wallet_burn", nullptr,
      /* description */ "Burns given amount to the given account.  This will allow you to post message and +/- sentiment on someones account as a form of reputation.",
      /* returns */ "transaction_record",
      /* params: */ {
        {"amount_to_burn", "string", fbtc::api::required_positional, fc::ovariant()},
        {"asset_symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()},
        {"from_account_name", "sending_account_name", fbtc::api::required_positional, fc::ovariant()},
        {"for_or_against", "string", fbtc::api::required_positional, fc::ovariant()},
        {"to_account_name", "receive_account_name", fbtc::api::required_positional, fc::ovariant()},
        {"public_message", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))},
        {"anonymous", "bool", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"false\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Burns given amount to the given account.  This will allow you to post message and +/- sentiment on someones account as a form of reputation.\n\nParameters:\n  amount_to_burn (string, required): the amount of shares to burn\n  asset_symbol (asset_symbol, required): the asset to burn\n  from_account_name (sending_account_name, required): the source account to draw the shares from\n  for_or_against (string, required): the value 'for' or 'against'\n  to_account_name (receive_account_name, required): the account to which the burn should be credited (for or against) and on which the public message will appear\n  public_message (string, optional, defaults to \"\"): a public message to post\n  anonymous (bool, optional, defaults to \"false\"): true if anonymous, else signed by from_account_name\n\nReturns:\n  transaction_record\n",
      /* aliases */ {"burn"}, false};
    store_method_metadata(wallet_burn_method_metadata);
  }

  {
    // register method wallet_address_create
    fbtc::api::method_data wallet_address_create_method_metadata{"wallet_address_create", nullptr,
      /* description */ "Creates an address which can be used for a simple (non-TITAN) transfer.",
      /* returns */ "string",
      /* params: */ {
        {"account_name", "string", fbtc::api::required_positional, fc::ovariant()},
        {"label", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))},
        {"legacy_network_byte", "int32_t", fbtc::api::optional_positional, fc::variant(fc::json::from_string("-1"))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "Creates an address which can be used for a simple (non-TITAN) transfer.\n\nParameters:\n  account_name (string, required): The account name that will own this address\n  label (string, optional, defaults to \"\"): \n  legacy_network_byte (int32_t, optional, defaults to -1): If not -1, use this as the network byte for a BTC-style address.\n\nReturns:\n  string\n",
      /* aliases */ {"new_address"}, false};
    store_method_metadata(wallet_address_create_method_metadata);
  }

  {
    // register method wallet_transfer_to_address
    fbtc::api::method_data wallet_transfer_to_address_method_metadata{"wallet_transfer_to_address", nullptr,
      /* description */ "Do a simple (non-TITAN) transfer to an address",
      /* returns */ "transaction_record",
      /* params: */ {
        {"amount_to_transfer", "string", fbtc::api::required_positional, fc::ovariant()},
        {"asset_symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()},
        {"from_account_name", "account_name", fbtc::api::required_positional, fc::ovariant()},
        {"to_address", "string", fbtc::api::required_positional, fc::ovariant()},
        {"memo_message", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))},
        {"strategy", "vote_strategy", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"vote_recommended\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "Do a simple (non-TITAN) transfer to an address\n\nParameters:\n  amount_to_transfer (string, required): the amount of shares to transfer\n  asset_symbol (asset_symbol, required): the asset to transfer\n  from_account_name (account_name, required): the source account to draw the shares from\n  to_address (string, required): the address or pubkey to transfer to\n  memo_message (string, optional, defaults to \"\"): a memo to store with the transaction\n  strategy (vote_strategy, optional, defaults to \"vote_recommended\"): enumeration [vote_none | vote_all | vote_random | vote_recommended] \n\nReturns:\n  transaction_record\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_transfer_to_address_method_metadata);
  }

  {
    // register method wallet_transfer_to_genesis_multisig_address
    fbtc::api::method_data wallet_transfer_to_genesis_multisig_address_method_metadata{"wallet_transfer_to_genesis_multisig_address", nullptr,
      /* description */ "Do a simple (non-TITAN) transfer to an address",
      /* returns */ "transaction_record",
      /* params: */ {
        {"amount_to_transfer", "string", fbtc::api::required_positional, fc::ovariant()},
        {"asset_symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()},
        {"from_account_name", "account_name", fbtc::api::required_positional, fc::ovariant()},
        {"to_address", "string", fbtc::api::required_positional, fc::ovariant()},
        {"memo_message", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))},
        {"strategy", "vote_strategy", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"vote_recommended\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "Do a simple (non-TITAN) transfer to an address\n\nParameters:\n  amount_to_transfer (string, required): the amount of shares to transfer\n  asset_symbol (asset_symbol, required): the asset to transfer\n  from_account_name (account_name, required): the source account to draw the shares from\n  to_address (string, required): the address to transfer to\n  memo_message (string, optional, defaults to \"\"): a memo to store with the transaction\n  strategy (vote_strategy, optional, defaults to \"vote_recommended\"): enumeration [vote_none | vote_all | vote_random | vote_recommended] \n\nReturns:\n  transaction_record\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_transfer_to_genesis_multisig_address_method_metadata);
  }

  {
    // register method wallet_transfer_to_address_from_file
    fbtc::api::method_data wallet_transfer_to_address_from_file_method_metadata{"wallet_transfer_to_address_from_file", nullptr,
      /* description */ "only use for genesis balance distribute",
      /* returns */ "transaction_record",
      /* params: */ {
        {"from_account_name", "account_name", fbtc::api::required_positional, fc::ovariant()},
        {"file_path", "string", fbtc::api::required_positional, fc::ovariant()},
        {"memo_message", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))},
        {"strategy", "vote_strategy", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"vote_recommended\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "only use for genesis balance distribute\n\nParameters:\n  from_account_name (account_name, required): the source account to draw the shares from\n  file_path (string, required): the address or pubkey to transfer to\n  memo_message (string, optional, defaults to \"\"): a memo to store with the transaction\n  strategy (vote_strategy, optional, defaults to \"vote_recommended\"): enumeration [vote_none | vote_all | vote_random | vote_recommended] \n\nReturns:\n  transaction_record\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_transfer_to_address_from_file_method_metadata);
  }

  {
    // register method wallet_transfer_to_genesis_multisig_address_from_file
    fbtc::api::method_data wallet_transfer_to_genesis_multisig_address_from_file_method_metadata{"wallet_transfer_to_genesis_multisig_address_from_file", nullptr,
      /* description */ "only use for genesis balance distribute",
      /* returns */ "transaction_record",
      /* params: */ {
        {"from_account_name", "account_name", fbtc::api::required_positional, fc::ovariant()},
        {"file_path", "string", fbtc::api::required_positional, fc::ovariant()},
        {"memo_message", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))},
        {"strategy", "vote_strategy", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"vote_recommended\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "only use for genesis balance distribute\n\nParameters:\n  from_account_name (account_name, required): the source account to draw the shares from\n  file_path (string, required): the address or pubkey to transfer to\n  memo_message (string, optional, defaults to \"\"): a memo to store with the transaction\n  strategy (vote_strategy, optional, defaults to \"vote_recommended\"): enumeration [vote_none | vote_all | vote_random | vote_recommended] \n\nReturns:\n  transaction_record\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_transfer_to_genesis_multisig_address_from_file_method_metadata);
  }

  {
    // register method wallet_check_passphrase
    fbtc::api::method_data wallet_check_passphrase_method_metadata{"wallet_check_passphrase", nullptr,
      /* description */ "check the password of the current wallet",
      /* returns */ "bool",
      /* params: */ {
        {"passphrase", "passphrase", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "check the password of the current wallet\n\nThis will check the wallet's spending passphrase.\n\nParameters:\n  passphrase (passphrase, required): the passphrase to be checking\n\nReturns:\n  bool\n",
      /* aliases */ {"check_passphrase", "check_password"}, false};
    store_method_metadata(wallet_check_passphrase_method_metadata);
  }

  {
    // register method wallet_transfer
    fbtc::api::method_data wallet_transfer_method_metadata{"wallet_transfer", nullptr,
      /* description */ "Sends given amount to the given account, with the from field set to the payer.  This transfer will occur in a single transaction and will be cheaper, but may reduce your privacy.",
      /* returns */ "transaction_record",
      /* params: */ {
        {"amount_to_transfer", "string", fbtc::api::required_positional, fc::ovariant()},
        {"asset_symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()},
        {"from_account_name", "sending_account_name", fbtc::api::required_positional, fc::ovariant()},
        {"recipient", "string", fbtc::api::required_positional, fc::ovariant()},
        {"memo_message", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))},
        {"strategy", "vote_strategy", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"vote_recommended\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Sends given amount to the given account, with the from field set to the payer.  This transfer will occur in a single transaction and will be cheaper, but may reduce your privacy.\n\nParameters:\n  amount_to_transfer (string, required): the amount of shares to transfer\n  asset_symbol (asset_symbol, required): the asset to transfer\n  from_account_name (sending_account_name, required): the source account to draw the shares from\n  recipient (string, required): the account name, public key, address, btc address, or contact label (prefixed by \"label:\") which will receive the funds\n  memo_message (string, optional, defaults to \"\"): a memo to send if the recipient is an account\n  strategy (vote_strategy, optional, defaults to \"vote_recommended\"): enumeration [vote_recommended | vote_all | vote_none]\n\nReturns:\n  transaction_record\n",
      /* aliases */ {"transfer"}, false};
    store_method_metadata(wallet_transfer_method_metadata);
  }

  {
    // register method wallet_multisig_get_balance_id
    fbtc::api::method_data wallet_multisig_get_balance_id_method_metadata{"wallet_multisig_get_balance_id", nullptr,
      /* description */ "",
      /* returns */ "address",
      /* params: */ {
        {"symbol", "string", fbtc::api::required_positional, fc::ovariant()},
        {"m", "uint32_t", fbtc::api::required_positional, fc::ovariant()},
        {"addresses", "address_list", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "\n\nParameters:\n  symbol (string, required): which asset\n  m (uint32_t, required): Required number of signatures\n  addresses (address_list, required): List of possible addresses for signatures\n\nReturns:\n  address\n",
      /* aliases */ {"get_multisig_id"}, false};
    store_method_metadata(wallet_multisig_get_balance_id_method_metadata);
  }

  {
    // register method wallet_multisig_deposit
    fbtc::api::method_data wallet_multisig_deposit_method_metadata{"wallet_multisig_deposit", nullptr,
      /* description */ "",
      /* returns */ "transaction_record",
      /* params: */ {
        {"amount", "string", fbtc::api::required_positional, fc::ovariant()},
        {"symbol", "string", fbtc::api::required_positional, fc::ovariant()},
        {"from_name", "string", fbtc::api::required_positional, fc::ovariant()},
        {"m", "uint32_t", fbtc::api::required_positional, fc::ovariant()},
        {"addresses", "address_list", fbtc::api::required_positional, fc::ovariant()},
        {"strategy", "vote_strategy", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"vote_none\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "\n\nParameters:\n  amount (string, required): how much to transfer\n  symbol (string, required): which asset\n  from_name (string, required): TITAN name to withdraw from\n  m (uint32_t, required): Required number of signatures\n  addresses (address_list, required): List of possible addresses for signatures\n  strategy (vote_strategy, optional, defaults to \"vote_none\"): enumeration [vote_recommended | vote_all | vote_none]\n\nReturns:\n  transaction_record\n",
      /* aliases */ {"transfer_to_multisig"}, false};
    store_method_metadata(wallet_multisig_deposit_method_metadata);
  }

  {
    // register method wallet_withdraw_from_address
    fbtc::api::method_data wallet_withdraw_from_address_method_metadata{"wallet_withdraw_from_address", nullptr,
      /* description */ "",
      /* returns */ "transaction_builder",
      /* params: */ {
        {"amount", "string", fbtc::api::required_positional, fc::ovariant()},
        {"symbol", "string", fbtc::api::required_positional, fc::ovariant()},
        {"from_address", "address", fbtc::api::required_positional, fc::ovariant()},
        {"to", "string", fbtc::api::required_positional, fc::ovariant()},
        {"strategy", "vote_strategy", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"vote_none\""))},
        {"sign_and_broadcast", "bool", fbtc::api::optional_positional, fc::variant(fc::json::from_string("true"))},
        {"builder_path", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "\n\nParameters:\n  amount (string, required): how much to transfer\n  symbol (string, required): which asset\n  from_address (address, required): the balance address to withdraw from\n  to (string, required): address or account to receive funds\n  strategy (vote_strategy, optional, defaults to \"vote_none\"): enumeration [vote_recommended | vote_all | vote_none]\n  sign_and_broadcast (bool, optional, defaults to true): \n  builder_path (string, optional, defaults to \"\"): If specified, will write builder here instead of to DATA_DIR/transactions/latest.trx\n\nReturns:\n  transaction_builder\n",
      /* aliases */ {"withdraw_from_address"}, false};
    store_method_metadata(wallet_withdraw_from_address_method_metadata);
  }

  {
    // register method wallet_receive_genesis_multisig_blanace
    fbtc::api::method_data wallet_receive_genesis_multisig_blanace_method_metadata{"wallet_receive_genesis_multisig_blanace", nullptr,
      /* description */ "",
      /* returns */ "transaction_builder",
      /* params: */ {
        {"from_address", "address", fbtc::api::required_positional, fc::ovariant()},
        {"from_address_redeemscript", "string", fbtc::api::required_positional, fc::ovariant()},
        {"to", "string", fbtc::api::required_positional, fc::ovariant()},
        {"strategy", "vote_strategy", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"vote_none\""))},
        {"sign_and_broadcast", "bool", fbtc::api::optional_positional, fc::variant(fc::json::from_string("true"))},
        {"builder_path", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "\n\nParameters:\n  from_address (address, required): old btc multisig address\n  from_address_redeemscript (string, required): old btc multisig address redeemscript\n  to (string, required): address or account to receive funds\n  strategy (vote_strategy, optional, defaults to \"vote_none\"): enumeration [vote_recommended | vote_all | vote_none]\n  sign_and_broadcast (bool, optional, defaults to true): \n  builder_path (string, optional, defaults to \"\"): If specified, will write builder here instead of to DATA_DIR/transactions/latest.trx\n\nReturns:\n  transaction_builder\n",
      /* aliases */ {"receive_from_genesis_address"}, false};
    store_method_metadata(wallet_receive_genesis_multisig_blanace_method_metadata);
  }

  {
    // register method wallet_withdraw_from_legacy_address
    fbtc::api::method_data wallet_withdraw_from_legacy_address_method_metadata{"wallet_withdraw_from_legacy_address", nullptr,
      /* description */ "",
      /* returns */ "transaction_builder",
      /* params: */ {
        {"amount", "string", fbtc::api::required_positional, fc::ovariant()},
        {"symbol", "string", fbtc::api::required_positional, fc::ovariant()},
        {"from_address", "legacy_address", fbtc::api::required_positional, fc::ovariant()},
        {"to", "string", fbtc::api::required_positional, fc::ovariant()},
        {"strategy", "vote_strategy", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"vote_none\""))},
        {"sign_and_broadcast", "bool", fbtc::api::optional_positional, fc::variant(fc::json::from_string("true"))},
        {"builder_path", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "\n\nParameters:\n  amount (string, required): how much to transfer\n  symbol (string, required): which asset\n  from_address (legacy_address, required): the balance address to withdraw from\n  to (string, required): address or account to receive funds\n  strategy (vote_strategy, optional, defaults to \"vote_none\"): enumeration [vote_recommended | vote_all | vote_none]\n  sign_and_broadcast (bool, optional, defaults to true): \n  builder_path (string, optional, defaults to \"\"): If specified, will write builder here instead of to DATA_DIR/transactions/latest.trx\n\nReturns:\n  transaction_builder\n",
      /* aliases */ {"withdraw_from_legacy_address"}, false};
    store_method_metadata(wallet_withdraw_from_legacy_address_method_metadata);
  }

  {
    // register method wallet_multisig_withdraw_start
    fbtc::api::method_data wallet_multisig_withdraw_start_method_metadata{"wallet_multisig_withdraw_start", nullptr,
      /* description */ "",
      /* returns */ "transaction_builder",
      /* params: */ {
        {"amount", "string", fbtc::api::required_positional, fc::ovariant()},
        {"symbol", "string", fbtc::api::required_positional, fc::ovariant()},
        {"from", "address", fbtc::api::required_positional, fc::ovariant()},
        {"to_address", "address", fbtc::api::required_positional, fc::ovariant()},
        {"strategy", "vote_strategy", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"vote_none\""))},
        {"builder_path", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "\n\nParameters:\n  amount (string, required): how much to transfer\n  symbol (string, required): which asset\n  from (address, required): multisig balance ID to withdraw from\n  to_address (address, required): address to receive funds\n  strategy (vote_strategy, optional, defaults to \"vote_none\"): enumeration [vote_recommended | vote_all | vote_none]\n  builder_path (string, optional, defaults to \"\"): If specified, will write builder here instead of to DATA_DIR/transactions/latest.trx\n\nReturns:\n  transaction_builder\n",
      /* aliases */ {"withdraw_from_multisig"}, false};
    store_method_metadata(wallet_multisig_withdraw_start_method_metadata);
  }

  {
    // register method wallet_builder_add_signature
    fbtc::api::method_data wallet_builder_add_signature_method_metadata{"wallet_builder_add_signature", nullptr,
      /* description */ "Review a transaction and add a signature.",
      /* returns */ "transaction_builder",
      /* params: */ {
        {"builder", "transaction_builder", fbtc::api::required_positional, fc::ovariant()},
        {"broadcast", "bool", fbtc::api::optional_positional, fc::variant(fc::json::from_string("false"))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "Review a transaction and add a signature.\n\nParameters:\n  builder (transaction_builder, required): A transaction builder object created by a wallet. If null, tries to use builder in file.\n  broadcast (bool, optional, defaults to false): Try to broadcast this transaction?\n\nReturns:\n  transaction_builder\n",
      /* aliases */ {"add_signature"}, false};
    store_method_metadata(wallet_builder_add_signature_method_metadata);
  }

  {
    // register method wallet_builder_file_add_signature
    fbtc::api::method_data wallet_builder_file_add_signature_method_metadata{"wallet_builder_file_add_signature", nullptr,
      /* description */ "Review a transaction in a builder file and add a signature.",
      /* returns */ "transaction_builder",
      /* params: */ {
        {"builder_path", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))},
        {"broadcast", "bool", fbtc::api::optional_positional, fc::variant(fc::json::from_string("false"))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "Review a transaction in a builder file and add a signature.\n\nParameters:\n  builder_path (string, optional, defaults to \"\"): If specified, will write builder here instead of to DATA_DIR/transactions/latest.trx\n  broadcast (bool, optional, defaults to false): Try to broadcast this transaction?\n\nReturns:\n  transaction_builder\n",
      /* aliases */ {"add_signature_to_file"}, false};
    store_method_metadata(wallet_builder_file_add_signature_method_metadata);
  }

  {
    // register method wallet_release_escrow
    fbtc::api::method_data wallet_release_escrow_method_metadata{"wallet_release_escrow", nullptr,
      /* description */ "Releases escrow balance to third parties",
      /* returns */ "transaction_record",
      /* params: */ {
        {"pay_fee_with_account_name", "account_name", fbtc::api::required_positional, fc::ovariant()},
        {"escrow_balance_id", "address", fbtc::api::required_positional, fc::ovariant()},
        {"released_by_account", "account_name", fbtc::api::required_positional, fc::ovariant()},
        {"amount_to_sender", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("0"))},
        {"amount_to_receiver", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("0"))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "Releases escrow balance to third parties\n\nParameters:\n  pay_fee_with_account_name (account_name, required): when releasing escrow a transaction fee must be paid by funds not in escrow, this account will pay the fee\n  escrow_balance_id (address, required): The balance id of the escrow to be released.\n  released_by_account (account_name, required): the account that is to perform the release.\n  amount_to_sender (string, optional, defaults to 0): Amount to release back to the sender.\n  amount_to_receiver (string, optional, defaults to 0): Amount to release to receiver.\n\nReturns:\n  transaction_record\n",
      /* aliases */ {"release"}, false};
    store_method_metadata(wallet_release_escrow_method_metadata);
  }

  {
    // register method wallet_transfer_from_with_escrow
    fbtc::api::method_data wallet_transfer_from_with_escrow_method_metadata{"wallet_transfer_from_with_escrow", nullptr,
      /* description */ "Sends given amount to the given name, with the from field set to a different account than the payer.  This transfer will occur in a single transaction and will be cheaper, but may reduce your privacy.",
      /* returns */ "transaction_record",
      /* params: */ {
        {"amount_to_transfer", "string", fbtc::api::required_positional, fc::ovariant()},
        {"asset_symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()},
        {"paying_account_name", "sending_account_name", fbtc::api::required_positional, fc::ovariant()},
        {"from_account_name", "sending_account_name", fbtc::api::required_positional, fc::ovariant()},
        {"to_account_name", "receive_account_name", fbtc::api::required_positional, fc::ovariant()},
        {"escrow_account_name", "account_name", fbtc::api::required_positional, fc::ovariant()},
        {"agreement", "digest", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))},
        {"memo_message", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))},
        {"strategy", "vote_strategy", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"vote_recommended\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Sends given amount to the given name, with the from field set to a different account than the payer.  This transfer will occur in a single transaction and will be cheaper, but may reduce your privacy.\n\nParameters:\n  amount_to_transfer (string, required): the amount of shares to transfer\n  asset_symbol (asset_symbol, required): the asset to transfer\n  paying_account_name (sending_account_name, required): the source account to draw the shares from\n  from_account_name (sending_account_name, required): the account to show the recipient as being the sender (requires account's private key to be in wallet).\n  to_account_name (receive_account_name, required): the account to transfer the shares to\n  escrow_account_name (account_name, required): the account of the escrow agent which has the power to decide how to divide the funds among from/to accounts.\n  agreement (digest, optional, defaults to \"\"): the hash of an agreement between the sender/receiver in the event a dispute arises can be given to escrow agent\n  memo_message (string, optional, defaults to \"\"): a memo to store with the transaction\n  strategy (vote_strategy, optional, defaults to \"vote_recommended\"): enumeration [vote_recommended | vote_all | vote_none]\n\nReturns:\n  transaction_record\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_transfer_from_with_escrow_method_metadata);
  }

  {
    // register method wallet_rescan_blockchain
    fbtc::api::method_data wallet_rescan_blockchain_method_metadata{"wallet_rescan_blockchain", nullptr,
      /* description */ "Scans the blockchain history for operations relevant to this wallet.",
      /* returns */ "void",
      /* params: */ {
        {"start_block_num", "uint32_t", fbtc::api::optional_positional, fc::variant(fc::json::from_string("0"))},
        {"limit", "uint32_t", fbtc::api::optional_positional, fc::variant(fc::json::from_string("-1"))},
        {"scan_in_background", "bool", fbtc::api::optional_positional, fc::variant(fc::json::from_string("true"))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Scans the blockchain history for operations relevant to this wallet.\n\nParameters:\n  start_block_num (uint32_t, optional, defaults to 0): the first block to scan\n  limit (uint32_t, optional, defaults to -1): the maximum number of blocks to scan\n  scan_in_background (bool, optional, defaults to true): if true then scan asynchronously in the background, otherwise block until scan is done\n\nReturns:\n  void\n",
      /* aliases */ {"scan", "rescan"}, false};
    store_method_metadata(wallet_rescan_blockchain_method_metadata);
  }

  {
    // register method wallet_cancel_scan
    fbtc::api::method_data wallet_cancel_scan_method_metadata{"wallet_cancel_scan", nullptr,
      /* description */ "Cancel any current scan task",
      /* returns */ "void",
      /* params: */ {},
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Cancel any current scan task\n\nParameters:\n  (none)\n\nReturns:\n  void\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_cancel_scan_method_metadata);
  }

  {
    // register method wallet_get_transaction
    fbtc::api::method_data wallet_get_transaction_method_metadata{"wallet_get_transaction", nullptr,
      /* description */ "Queries your wallet for the specified transaction",
      /* returns */ "transaction_record",
      /* params: */ {
        {"transaction_id", "string", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "Queries your wallet for the specified transaction\n\nParameters:\n  transaction_id (string, required): the id (or id prefix) of the transaction\n\nReturns:\n  transaction_record\n",
      /* aliases */ {"get_transaction"}, false};
    store_method_metadata(wallet_get_transaction_method_metadata);
  }

  {
    // register method wallet_scan_transaction
    fbtc::api::method_data wallet_scan_transaction_method_metadata{"wallet_scan_transaction", nullptr,
      /* description */ "Scans the specified transaction",
      /* returns */ "transaction_record",
      /* params: */ {
        {"transaction_id", "string", fbtc::api::required_positional, fc::ovariant()},
        {"overwrite_existing", "bool", fbtc::api::optional_positional, fc::variant(fc::json::from_string("false"))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Scans the specified transaction\n\nParameters:\n  transaction_id (string, required): the id (or id prefix) of the transaction\n  overwrite_existing (bool, optional, defaults to false): true to overwrite existing wallet transaction record and false otherwise\n\nReturns:\n  transaction_record\n",
      /* aliases */ {"scan_transaction", "wallet_transaction_scan"}, false};
    store_method_metadata(wallet_scan_transaction_method_metadata);
  }

  {
    // register method wallet_scan_transaction_experimental
    fbtc::api::method_data wallet_scan_transaction_experimental_method_metadata{"wallet_scan_transaction_experimental", nullptr,
      /* description */ "Scans the specified transaction",
      /* returns */ "void",
      /* params: */ {
        {"transaction_id", "string", fbtc::api::required_positional, fc::ovariant()},
        {"overwrite_existing", "bool", fbtc::api::optional_positional, fc::variant(fc::json::from_string("false"))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Scans the specified transaction\n\nParameters:\n  transaction_id (string, required): the id (or id prefix) of the transaction\n  overwrite_existing (bool, optional, defaults to false): true to overwrite existing wallet transaction record and false otherwise\n\nReturns:\n  void\n",
      /* aliases */ {"sx"}, false};
    store_method_metadata(wallet_scan_transaction_experimental_method_metadata);
  }

  {
    // register method wallet_add_transaction_note_experimental
    fbtc::api::method_data wallet_add_transaction_note_experimental_method_metadata{"wallet_add_transaction_note_experimental", nullptr,
      /* description */ "Adds a custom note to the specified transaction",
      /* returns */ "void",
      /* params: */ {
        {"transaction_id", "string", fbtc::api::required_positional, fc::ovariant()},
        {"note", "string", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Adds a custom note to the specified transaction\n\nParameters:\n  transaction_id (string, required): the id (or id prefix) of the transaction\n  note (string, required): note to add\n\nReturns:\n  void\n",
      /* aliases */ {"nx"}, false};
    store_method_metadata(wallet_add_transaction_note_experimental_method_metadata);
  }

  {
    // register method wallet_rebroadcast_transaction
    fbtc::api::method_data wallet_rebroadcast_transaction_method_metadata{"wallet_rebroadcast_transaction", nullptr,
      /* description */ "Rebroadcasts the specified transaction",
      /* returns */ "void",
      /* params: */ {
        {"transaction_id", "string", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "Rebroadcasts the specified transaction\n\nParameters:\n  transaction_id (string, required): the id (or id prefix) of the transaction\n\nReturns:\n  void\n",
      /* aliases */ {"rebroadcast", "wallet_transaction_rebroadcast"}, false};
    store_method_metadata(wallet_rebroadcast_transaction_method_metadata);
  }

  {
    // register method wallet_account_register
    fbtc::api::method_data wallet_account_register_method_metadata{"wallet_account_register", nullptr,
      /* description */ "Updates the data published about a given account",
      /* returns */ "transaction_record",
      /* params: */ {
        {"account_name", "account_name", fbtc::api::required_positional, fc::ovariant()},
        {"pay_from_account", "account_name", fbtc::api::required_positional, fc::ovariant()},
        {"public_data", "json_variant", fbtc::api::optional_positional, fc::variant(fc::json::from_string("null"))},
        {"delegate_pay_rate", "uint8_t", fbtc::api::optional_positional, fc::variant(fc::json::from_string("-1"))},
        {"account_type", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"titan_account\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Updates the data published about a given account\n\nParameters:\n  account_name (account_name, required): the account that will be updated\n  pay_from_account (account_name, required): the account from which fees will be paid\n  public_data (json_variant, optional, defaults to null): public data about the account\n  delegate_pay_rate (uint8_t, optional, defaults to -1): -1 for non-delegates; otherwise the percent of delegate pay to accept per produced block\n  account_type (string, optional, defaults to \"titan_account\"): titan_account | public_account - public accounts do not receive memos and all payments are made to the active key\n\nReturns:\n  transaction_record\n",
      /* aliases */ {"register"}, false};
    store_method_metadata(wallet_account_register_method_metadata);
  }

  {
    // register method wallet_set_custom_data
    fbtc::api::method_data wallet_set_custom_data_method_metadata{"wallet_set_custom_data", nullptr,
      /* description */ "Overwrite the local custom data for an account, contact, or approval",
      /* returns */ "void",
      /* params: */ {
        {"type", "wallet_record_type", fbtc::api::required_positional, fc::ovariant()},
        {"item", "string", fbtc::api::required_positional, fc::ovariant()},
        {"custom_data", "variant_object", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Overwrite the local custom data for an account, contact, or approval\n\nParameters:\n  type (wallet_record_type, required): specify one of {account_record_type, contact_record_type, approval_record_type}\n  item (string, required): name of the account, contact, or approval\n  custom_data (variant_object, required): the custom data object to store\n\nReturns:\n  void\n",
      /* aliases */ {"update_private_data"}, false};
    store_method_metadata(wallet_set_custom_data_method_metadata);
  }

  {
    // register method wallet_account_update_registration
    fbtc::api::method_data wallet_account_update_registration_method_metadata{"wallet_account_update_registration", nullptr,
      /* description */ "Updates the data published about a given account",
      /* returns */ "transaction_record",
      /* params: */ {
        {"account_name", "account_name", fbtc::api::required_positional, fc::ovariant()},
        {"pay_from_account", "account_name", fbtc::api::required_positional, fc::ovariant()},
        {"public_data", "json_variant", fbtc::api::optional_positional, fc::variant(fc::json::from_string("null"))},
        {"delegate_pay_rate", "uint8_t", fbtc::api::optional_positional, fc::variant(fc::json::from_string("-1"))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Updates the data published about a given account\n\nParameters:\n  account_name (account_name, required): the account that will be updated\n  pay_from_account (account_name, required): the account from which fees will be paid\n  public_data (json_variant, optional, defaults to null): public data about the account\n  delegate_pay_rate (uint8_t, optional, defaults to -1): -1 for non-delegates; otherwise the percent of delegate pay to accept per produced block\n\nReturns:\n  transaction_record\n",
      /* aliases */ {"update_registration"}, false};
    store_method_metadata(wallet_account_update_registration_method_metadata);
  }

  {
    // register method wallet_account_update_active_key
    fbtc::api::method_data wallet_account_update_active_key_method_metadata{"wallet_account_update_active_key", nullptr,
      /* description */ "Updates the specified account's active key and broadcasts the transaction.",
      /* returns */ "transaction_record",
      /* params: */ {
        {"account_to_update", "account_name", fbtc::api::required_positional, fc::ovariant()},
        {"pay_from_account", "account_name", fbtc::api::required_positional, fc::ovariant()},
        {"new_active_key", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Updates the specified account's active key and broadcasts the transaction.\n\nParameters:\n  account_to_update (account_name, required): The name of the account to update the active key of.\n  pay_from_account (account_name, required): The account from which fees will be paid.\n  new_active_key (string, optional, defaults to \"\"): WIF private key to update active key to. If empty, a new key will be generated.\n\nReturns:\n  transaction_record\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_account_update_active_key_method_metadata);
  }

  {
    // register method wallet_list_accounts
    fbtc::api::method_data wallet_list_accounts_method_metadata{"wallet_list_accounts", nullptr,
      /* description */ "Lists all account entries",
      /* returns */ "wallet_account_record_array",
      /* params: */ {},
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "Lists all account entries\n\nParameters:\n  (none)\n\nReturns:\n  wallet_account_record_array\n",
      /* aliases */ {"accounts", "get_accounts", "list_accounts", "listaccounts"}, false};
    store_method_metadata(wallet_list_accounts_method_metadata);
  }

  {
    // register method wallet_get_account
    fbtc::api::method_data wallet_get_account_method_metadata{"wallet_get_account", nullptr,
      /* description */ "Get the specified account entry",
      /* returns */ "owallet_account_record",
      /* params: */ {
        {"account", "string", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "Get the specified account entry\n\nParameters:\n  account (string, required): the name, key, address, or id of the account to query\n\nReturns:\n  owallet_account_record\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_get_account_method_metadata);
  }

  {
    // register method wallet_account_rename
    fbtc::api::method_data wallet_account_rename_method_metadata{"wallet_account_rename", nullptr,
      /* description */ "Rename an account in wallet",
      /* returns */ "void",
      /* params: */ {
        {"current_account_name", "account_name", fbtc::api::required_positional, fc::ovariant()},
        {"new_account_name", "new_account_name", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "Rename an account in wallet\n\nParameters:\n  current_account_name (account_name, required): the current name of the account\n  new_account_name (new_account_name, required): the new name for the account\n\nReturns:\n  void\n",
      /* aliases */ {"wallet_rename_account"}, false};
    store_method_metadata(wallet_account_rename_method_metadata);
  }

  {
    // register method wallet_mia_create
    fbtc::api::method_data wallet_mia_create_method_metadata{"wallet_mia_create", nullptr,
      /* description */ "Create a new market-issued asset (BitAsset) on the blockchain. Warning: creation fees can be very high!",
      /* returns */ "transaction_record",
      /* params: */ {
        {"payer_account", "string", fbtc::api::required_positional, fc::ovariant()},
        {"symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()},
        {"name", "string", fbtc::api::required_positional, fc::ovariant()},
        {"description", "string", fbtc::api::required_positional, fc::ovariant()},
        {"max_divisibility", "string", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Create a new market-issued asset (BitAsset) on the blockchain. Warning: creation fees can be very high!\n\nParameters:\n  payer_account (string, required): The local account name that will pay the creation fee\n  symbol (asset_symbol, required): A unique symbol that will represent the new asset. Short symbols are very expensive!\n  name (string, required): A human-readable name for the new asset\n  description (string, required): A human-readable description of the new asset\n  max_divisibility (string, required): Choose the max share divisibility for the new asset. Must be an inverse power of ten. For example: 0.00001 or 1\n\nReturns:\n  transaction_record\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_mia_create_method_metadata);
  }

  {
    // register method wallet_uia_create
    fbtc::api::method_data wallet_uia_create_method_metadata{"wallet_uia_create", nullptr,
      /* description */ "Create a new user-issued asset on the blockchain. Warning: creation fees can be very high!",
      /* returns */ "transaction_record",
      /* params: */ {
        {"issuer_account", "string", fbtc::api::required_positional, fc::ovariant()},
        {"symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()},
        {"name", "string", fbtc::api::required_positional, fc::ovariant()},
        {"description", "string", fbtc::api::required_positional, fc::ovariant()},
        {"max_supply_with_trailing_decimals", "string", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Create a new user-issued asset on the blockchain. Warning: creation fees can be very high!\n\nParameters:\n  issuer_account (string, required): The registered account name that will pay the creation fee and control the new asset\n  symbol (asset_symbol, required): A unique symbol that will represent the new asset. Short symbols are very expensive!\n  name (string, required): A human-readable name for the new asset\n  description (string, required): A human-readable description of the new asset\n  max_supply_with_trailing_decimals (string, required): Choose the max share supply and max share divisibility for the new asset. For example: 10000000000.00000 or 12345.6789\n\nReturns:\n  transaction_record\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_uia_create_method_metadata);
  }

  {
    // register method wallet_uia_issue
    fbtc::api::method_data wallet_uia_issue_method_metadata{"wallet_uia_issue", nullptr,
      /* description */ "Issue shares of a user-issued asset to the specified recipient",
      /* returns */ "transaction_record",
      /* params: */ {
        {"asset_amount", "string", fbtc::api::required_positional, fc::ovariant()},
        {"asset_symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()},
        {"recipient", "string", fbtc::api::required_positional, fc::ovariant()},
        {"memo_message", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Issue shares of a user-issued asset to the specified recipient\n\nParameters:\n  asset_amount (string, required): the amount of shares of the asset to issue\n  asset_symbol (asset_symbol, required): specify the unique symbol of the asset\n  recipient (string, required): the account name, public key, address, btc address, or contact label (prefixed by \"label:\") which will receive the funds\n  memo_message (string, optional, defaults to \"\"): a memo to send if the recipient is an account\n\nReturns:\n  transaction_record\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_uia_issue_method_metadata);
  }

  {
    // register method wallet_uia_issue_to_addresses
    fbtc::api::method_data wallet_uia_issue_to_addresses_method_metadata{"wallet_uia_issue_to_addresses", nullptr,
      /* description */ "Issues new UIA shares to specific addresses.",
      /* returns */ "transaction_record",
      /* params: */ {
        {"symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()},
        {"addresses", "snapshot_map", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Issues new UIA shares to specific addresses.\n\nThis is intended to be used with a helper script to break up snapshots. It will not do any magic for you.\n\nParameters:\n  symbol (asset_symbol, required): the ticker symbol for asset\n  addresses (snapshot_map, required): A map of addresses-to-amounts to transfer the new shares to\n\nReturns:\n  transaction_record\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_uia_issue_to_addresses_method_metadata);
  }

  {
    // register method wallet_uia_collect_fees
    fbtc::api::method_data wallet_uia_collect_fees_method_metadata{"wallet_uia_collect_fees", nullptr,
      /* description */ "Withdraw fees collected in the specified user-issued asset and deposit to the specified recipient",
      /* returns */ "transaction_record",
      /* params: */ {
        {"asset_symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()},
        {"recipient", "string", fbtc::api::required_positional, fc::ovariant()},
        {"memo_message", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Withdraw fees collected in the specified user-issued asset and deposit to the specified recipient\n\nParameters:\n  asset_symbol (asset_symbol, required): specify the unique symbol of the asset\n  recipient (string, required): the account name, public key, address, btc address, or contact label (prefixed by \"label:\") which will receive the funds\n  memo_message (string, optional, defaults to \"\"): a memo to send if the recipient is an account\n\nReturns:\n  transaction_record\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_uia_collect_fees_method_metadata);
  }

  {
    // register method wallet_uia_update_description
    fbtc::api::method_data wallet_uia_update_description_method_metadata{"wallet_uia_update_description", nullptr,
      /* description */ "Update the name, description, public data of the specified user-issue asset",
      /* returns */ "transaction_record",
      /* params: */ {
        {"paying_account", "account_name", fbtc::api::required_positional, fc::ovariant()},
        {"asset_symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()},
        {"name", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))},
        {"description", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))},
        {"public_data", "variant", fbtc::api::optional_positional, fc::variant(fc::json::from_string("null"))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Update the name, description, public data of the specified user-issue asset\n\nParameters:\n  paying_account (account_name, required): the account that will pay the transaction fee\n  asset_symbol (asset_symbol, required): the user-issued asset to update\n  name (string, optional, defaults to \"\"): A human-readable name for the new asset\n  description (string, optional, defaults to \"\"): A human-readable description of the new asset\n  public_data (variant, optional, defaults to null): Extra data to attach to the asset\n\nReturns:\n  transaction_record\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_uia_update_description_method_metadata);
  }

  {
    // register method wallet_uia_update_supply
    fbtc::api::method_data wallet_uia_update_supply_method_metadata{"wallet_uia_update_supply", nullptr,
      /* description */ "Update the max supply and max divisibility of the specified user-issued asset if permitted",
      /* returns */ "transaction_record",
      /* params: */ {
        {"paying_account", "account_name", fbtc::api::required_positional, fc::ovariant()},
        {"asset_symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()},
        {"max_supply_with_trailing_decimals", "string", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Update the max supply and max divisibility of the specified user-issued asset if permitted\n\nParameters:\n  paying_account (account_name, required): the account that will pay the transaction fee\n  asset_symbol (asset_symbol, required): the user-issued asset to update\n  max_supply_with_trailing_decimals (string, required): Choose the max share supply and max share divisibility for the asset. For example: 10000000000.00000 or 12345.6789\n\nReturns:\n  transaction_record\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_uia_update_supply_method_metadata);
  }

  {
    // register method wallet_uia_update_fees
    fbtc::api::method_data wallet_uia_update_fees_method_metadata{"wallet_uia_update_fees", nullptr,
      /* description */ "Update the transaction fee, market fee rate for the specified user-issued asset if permitted",
      /* returns */ "transaction_record",
      /* params: */ {
        {"paying_account", "account_name", fbtc::api::required_positional, fc::ovariant()},
        {"asset_symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()},
        {"withdrawal_fee", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))},
        {"market_fee_rate", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Update the transaction fee, market fee rate for the specified user-issued asset if permitted\n\nParameters:\n  paying_account (account_name, required): the account that will pay the transaction fee\n  asset_symbol (asset_symbol, required): the user-issued asset to update\n  withdrawal_fee (string, optional, defaults to \"\"): the transaction fee for the asset in shares of the asset\n  market_fee_rate (string, optional, defaults to \"\"): the market fee rate for the asset as a percentage between 0.01 and 100, or 0\n\nReturns:\n  transaction_record\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_uia_update_fees_method_metadata);
  }

  {
    // register method wallet_uia_update_active_flags
    fbtc::api::method_data wallet_uia_update_active_flags_method_metadata{"wallet_uia_update_active_flags", nullptr,
      /* description */ "Activate or deactivate one of the special flags for the specified user-issued asset as permitted",
      /* returns */ "transaction_record",
      /* params: */ {
        {"paying_account", "account_name", fbtc::api::required_positional, fc::ovariant()},
        {"asset_symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()},
        {"flag", "asset_flag_enum", fbtc::api::required_positional, fc::ovariant()},
        {"enable_instead_of_disable", "bool", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Activate or deactivate one of the special flags for the specified user-issued asset as permitted\n\nParameters:\n  paying_account (account_name, required): the account that will pay the transaction fee\n  asset_symbol (asset_symbol, required): the user-issued asset to update\n  flag (asset_flag_enum, required): the special flag to enable or disable; one of {dynamic_max_supply, dynamic_fees, halted_markets, halted_withdrawals, retractable_balances, restricted_accounts}\n  enable_instead_of_disable (bool, required): true to enable, or false to disable\n\nReturns:\n  transaction_record\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_uia_update_active_flags_method_metadata);
  }

  {
    // register method wallet_uia_update_authority_permissions
    fbtc::api::method_data wallet_uia_update_authority_permissions_method_metadata{"wallet_uia_update_authority_permissions", nullptr,
      /* description */ "Update the authority's special flag permissions for the specified user-issued asset. Warning: If any shares have been issued, then revoked permissions cannot be restored!",
      /* returns */ "transaction_record",
      /* params: */ {
        {"paying_account", "account_name", fbtc::api::required_positional, fc::ovariant()},
        {"asset_symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()},
        {"permission", "asset_flag_enum", fbtc::api::required_positional, fc::ovariant()},
        {"add_instead_of_remove", "bool", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Update the authority's special flag permissions for the specified user-issued asset. Warning: If any shares have been issued, then revoked permissions cannot be restored!\n\nParameters:\n  paying_account (account_name, required): the account that will pay the transaction fee\n  asset_symbol (asset_symbol, required): the user-issued asset to update\n  permission (asset_flag_enum, required): the special permission to enable or disable; one of {dynamic_max_supply, dynamic_fees, halted_markets, halted_withdrawals, retractable_balances, restricted_accounts}\n  add_instead_of_remove (bool, required): True to add, or false to remove. Use with extreme caution!\n\nReturns:\n  transaction_record\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_uia_update_authority_permissions_method_metadata);
  }

  {
    // register method wallet_uia_update_whitelist
    fbtc::api::method_data wallet_uia_update_whitelist_method_metadata{"wallet_uia_update_whitelist", nullptr,
      /* description */ "Add or remove the specified registered account from the specified user-issued asset's whitelist",
      /* returns */ "transaction_record",
      /* params: */ {
        {"paying_account", "account_name", fbtc::api::required_positional, fc::ovariant()},
        {"asset_symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()},
        {"account_name", "string", fbtc::api::required_positional, fc::ovariant()},
        {"add_to_whitelist", "bool", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Add or remove the specified registered account from the specified user-issued asset's whitelist\n\nParameters:\n  paying_account (account_name, required): the account that will pay the transaction fee\n  asset_symbol (asset_symbol, required): the user-issued asset that will have its whitelist updated\n  account_name (string, required): the name of the account to add or remove from the whitelist\n  add_to_whitelist (bool, required): true to add to whitelist, or false to remove\n\nReturns:\n  transaction_record\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_uia_update_whitelist_method_metadata);
  }

  {
    // register method wallet_uia_retract_balance
    fbtc::api::method_data wallet_uia_retract_balance_method_metadata{"wallet_uia_retract_balance", nullptr,
      /* description */ "Retract all funds from the specified user-issued asset balance record",
      /* returns */ "transaction_record",
      /* params: */ {
        {"balance_id", "address", fbtc::api::required_positional, fc::ovariant()},
        {"account_name", "string", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Retract all funds from the specified user-issued asset balance record\n\nParameters:\n  balance_id (address, required): the ID of the balance record\n  account_name (string, required): the local account name that will receive the funds and pay the fee\n\nReturns:\n  transaction_record\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_uia_retract_balance_method_metadata);
  }

  {
    // register method wallet_escrow_summary
    fbtc::api::method_data wallet_escrow_summary_method_metadata{"wallet_escrow_summary", nullptr,
      /* description */ "Lists the total asset balances for all open escrows",
      /* returns */ "escrow_summary_array",
      /* params: */ {
        {"account_name", "account_name", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "Lists the total asset balances for all open escrows\n\nParameters:\n  account_name (account_name, optional, defaults to \"\"): the account to get a escrow summary for, or leave empty for all accounts\n\nReturns:\n  escrow_summary_array\n",
      /* aliases */ {"escrow"}, true};
    store_method_metadata(wallet_escrow_summary_method_metadata);
  }

  {
    // register method wallet_account_balance
    fbtc::api::method_data wallet_account_balance_method_metadata{"wallet_account_balance", nullptr,
      /* description */ "Lists the total asset balances for the specified account",
      /* returns */ "account_balance_summary_type",
      /* params: */ {
        {"account_name", "account_name", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "Lists the total asset balances for the specified account\n\nParameters:\n  account_name (account_name, optional, defaults to \"\"): the account to get a balance for, or leave empty for all accounts\n\nReturns:\n  account_balance_summary_type\n",
      /* aliases */ {"balance", "getbalance"}, true};
    store_method_metadata(wallet_account_balance_method_metadata);
  }

  {
    // register method wallet_account_balance_ids
    fbtc::api::method_data wallet_account_balance_ids_method_metadata{"wallet_account_balance_ids", nullptr,
      /* description */ "Lists the balance IDs for the specified account",
      /* returns */ "account_balance_id_summary_type",
      /* params: */ {
        {"account_name", "account_name", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "Lists the balance IDs for the specified account\n\nParameters:\n  account_name (account_name, optional, defaults to \"\"): the account to get a balance IDs for, or leave empty for all accounts\n\nReturns:\n  account_balance_id_summary_type\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_account_balance_ids_method_metadata);
  }

  {
    // register method wallet_account_balance_extended
    fbtc::api::method_data wallet_account_balance_extended_method_metadata{"wallet_account_balance_extended", nullptr,
      /* description */ "Lists the total asset balances across all withdraw condition types for the specified account",
      /* returns */ "account_extended_balance_type",
      /* params: */ {
        {"account_name", "account_name", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "Lists the total asset balances across all withdraw condition types for the specified account\n\nParameters:\n  account_name (account_name, optional, defaults to \"\"): the account to get a balance for, or leave empty for all accounts\n\nReturns:\n  account_extended_balance_type\n",
      /* aliases */ {}, true};
    store_method_metadata(wallet_account_balance_extended_method_metadata);
  }

  {
    // register method wallet_account_vesting_balances
    fbtc::api::method_data wallet_account_vesting_balances_method_metadata{"wallet_account_vesting_balances", nullptr,
      /* description */ "List the vesting balances available to the specified account",
      /* returns */ "account_vesting_balance_summary_type",
      /* params: */ {
        {"account_name", "account_name", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "List the vesting balances available to the specified account\n\nParameters:\n  account_name (account_name, optional, defaults to \"\"): the account name to list vesting balances for, or leave empty for all accounts\n\nReturns:\n  account_vesting_balance_summary_type\n",
      /* aliases */ {"vesting"}, true};
    store_method_metadata(wallet_account_vesting_balances_method_metadata);
  }

  {
    // register method wallet_account_yield
    fbtc::api::method_data wallet_account_yield_method_metadata{"wallet_account_yield", nullptr,
      /* description */ "Lists the total accumulated yield for asset balances",
      /* returns */ "account_balance_summary_type",
      /* params: */ {
        {"account_name", "account_name", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "Lists the total accumulated yield for asset balances\n\nParameters:\n  account_name (account_name, optional, defaults to \"\"): the account to get yield for, or leave empty for all accounts\n\nReturns:\n  account_balance_summary_type\n",
      /* aliases */ {"yield", "getyield"}, true};
    store_method_metadata(wallet_account_yield_method_metadata);
  }

  {
    // register method wallet_account_list_public_keys
    fbtc::api::method_data wallet_account_list_public_keys_method_metadata{"wallet_account_list_public_keys", nullptr,
      /* description */ "Lists all public keys in this account",
      /* returns */ "public_key_summary_array",
      /* params: */ {
        {"account_name", "account_name", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "Lists all public keys in this account\n\nParameters:\n  account_name (account_name, required): the account for which public keys should be listed\n\nReturns:\n  public_key_summary_array\n",
      /* aliases */ {"public_keys"}, true};
    store_method_metadata(wallet_account_list_public_keys_method_metadata);
  }

  {
    // register method wallet_delegate_withdraw_pay
    fbtc::api::method_data wallet_delegate_withdraw_pay_method_metadata{"wallet_delegate_withdraw_pay", nullptr,
      /* description */ "Used to transfer some of the delegate's pay from their balance",
      /* returns */ "transaction_record",
      /* params: */ {
        {"delegate_name", "account_name", fbtc::api::required_positional, fc::ovariant()},
        {"to_account_name", "account_name", fbtc::api::required_positional, fc::ovariant()},
        {"amount_to_withdraw", "string", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Used to transfer some of the delegate's pay from their balance\n\nParameters:\n  delegate_name (account_name, required): the delegate whose pay is being cashed out\n  to_account_name (account_name, required): the account that should receive the funds\n  amount_to_withdraw (string, required): the amount to withdraw\n\nReturns:\n  transaction_record\n",
      /* aliases */ {"pay_delegate"}, false};
    store_method_metadata(wallet_delegate_withdraw_pay_method_metadata);
  }

  {
    // register method wallet_set_transaction_fee
    fbtc::api::method_data wallet_set_transaction_fee_method_metadata{"wallet_set_transaction_fee", nullptr,
      /* description */ "Set the fee to add to new transactions",
      /* returns */ "asset",
      /* params: */ {
        {"fee", "string", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "Set the fee to add to new transactions\n\nParameters:\n  fee (string, required): the wallet transaction fee to set\n\nReturns:\n  asset\n",
      /* aliases */ {"wallet_set_priority_fee", "set_priority_fee", "settrxfee", "setfee", "set_fee"}, false};
    store_method_metadata(wallet_set_transaction_fee_method_metadata);
  }

  {
    // register method wallet_get_transaction_fee
    fbtc::api::method_data wallet_get_transaction_fee_method_metadata{"wallet_get_transaction_fee", nullptr,
      /* description */ "Returns ",
      /* returns */ "asset",
      /* params: */ {
        {"symbol", "asset_symbol", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "Returns \n\nParameters:\n  symbol (asset_symbol, optional, defaults to \"\"): the wallet transaction if paid in the given asset type\n\nReturns:\n  asset\n",
      /* aliases */ {"wallet_get_priority_fee", "get_priority_fee", "gettrxfee", "getfee", "get_fee"}, true};
    store_method_metadata(wallet_get_transaction_fee_method_metadata);
  }

  {
    // register method wallet_market_submit_bid
    fbtc::api::method_data wallet_market_submit_bid_method_metadata{"wallet_market_submit_bid", nullptr,
      /* description */ "Used to place a request to buy a quantity of assets at a price specified in another asset",
      /* returns */ "transaction_record",
      /* params: */ {
        {"from_account_name", "account_name", fbtc::api::required_positional, fc::ovariant()},
        {"quantity", "string", fbtc::api::required_positional, fc::ovariant()},
        {"quantity_symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()},
        {"base_price", "string", fbtc::api::required_positional, fc::ovariant()},
        {"base_symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()},
        {"allow_stupid_bid", "bool", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"false\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Used to place a request to buy a quantity of assets at a price specified in another asset\n\nParameters:\n  from_account_name (account_name, required): the account that will provide funds for the bid\n  quantity (string, required): the quantity of items you would like to buy\n  quantity_symbol (asset_symbol, required): the type of items you would like to buy\n  base_price (string, required): the price you would like to pay\n  base_symbol (asset_symbol, required): the type of asset you would like to pay with\n  allow_stupid_bid (bool, optional, defaults to \"false\"): Allow user to place bid at more than 5% above the current sell price.\n\nReturns:\n  transaction_record\n",
      /* aliases */ {"bid"}, false};
    store_method_metadata(wallet_market_submit_bid_method_metadata);
  }

  {
    // register method wallet_market_submit_ask
    fbtc::api::method_data wallet_market_submit_ask_method_metadata{"wallet_market_submit_ask", nullptr,
      /* description */ "Used to place a request to sell a quantity of assets at a price specified in another asset",
      /* returns */ "transaction_record",
      /* params: */ {
        {"from_account_name", "account_name", fbtc::api::required_positional, fc::ovariant()},
        {"sell_quantity", "string", fbtc::api::required_positional, fc::ovariant()},
        {"sell_quantity_symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()},
        {"ask_price", "string", fbtc::api::required_positional, fc::ovariant()},
        {"ask_price_symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()},
        {"allow_stupid_ask", "bool", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"false\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Used to place a request to sell a quantity of assets at a price specified in another asset\n\nParameters:\n  from_account_name (account_name, required): the account that will provide funds for the ask\n  sell_quantity (string, required): the quantity of items you would like to sell\n  sell_quantity_symbol (asset_symbol, required): the type of items you would like to sell\n  ask_price (string, required): the price per unit sold.\n  ask_price_symbol (asset_symbol, required): the type of asset you would like to be paid\n  allow_stupid_ask (bool, optional, defaults to \"false\"): Allow user to place ask at more than 5% below the current buy price.\n\nReturns:\n  transaction_record\n",
      /* aliases */ {"ask"}, false};
    store_method_metadata(wallet_market_submit_ask_method_metadata);
  }

  {
    // register method wallet_market_submit_short
    fbtc::api::method_data wallet_market_submit_short_method_metadata{"wallet_market_submit_short", nullptr,
      /* description */ "Used to place a request to short sell a quantity of assets at a price specified",
      /* returns */ "transaction_record",
      /* params: */ {
        {"from_account_name", "account_name", fbtc::api::required_positional, fc::ovariant()},
        {"short_collateral", "string", fbtc::api::required_positional, fc::ovariant()},
        {"collateral_symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()},
        {"interest_rate", "string", fbtc::api::required_positional, fc::ovariant()},
        {"quote_symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()},
        {"short_price_limit", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("0"))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Used to place a request to short sell a quantity of assets at a price specified\n\nParameters:\n  from_account_name (account_name, required): the account that will provide funds for the ask\n  short_collateral (string, required): the amount of collateral you wish to fund this short with\n  collateral_symbol (asset_symbol, required): the type of asset collateralizing this short (i.e. XTS)\n  interest_rate (string, required): the APR you wish to pay interest at (0.0% to 50.0%)\n  quote_symbol (asset_symbol, required): the asset to short sell (i.e. USD)\n  short_price_limit (string, optional, defaults to 0): maximim price (USD per XTS) that the short will execute at, if 0 then no limit will be applied\n\nReturns:\n  transaction_record\n",
      /* aliases */ {"short"}, false};
    store_method_metadata(wallet_market_submit_short_method_metadata);
  }

  {
    // register method wallet_market_cover
    fbtc::api::method_data wallet_market_cover_method_metadata{"wallet_market_cover", nullptr,
      /* description */ "Used to place a request to cover an existing short position",
      /* returns */ "transaction_record",
      /* params: */ {
        {"from_account_name", "account_name", fbtc::api::required_positional, fc::ovariant()},
        {"quantity", "string", fbtc::api::required_positional, fc::ovariant()},
        {"quantity_symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()},
        {"cover_id", "order_id", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Used to place a request to cover an existing short position\n\nParameters:\n  from_account_name (account_name, required): the account that will provide funds for the ask\n  quantity (string, required): the quantity of asset you would like to cover\n  quantity_symbol (asset_symbol, required): the type of asset you are covering (ie: USD)\n  cover_id (order_id, required): the order ID you would like to cover\n\nReturns:\n  transaction_record\n",
      /* aliases */ {"cover"}, false};
    store_method_metadata(wallet_market_cover_method_metadata);
  }

  {
    // register method wallet_market_batch_update
    fbtc::api::method_data wallet_market_batch_update_method_metadata{"wallet_market_batch_update", nullptr,
      /* description */ "Cancel and/or create many market orders in a single transaction.",
      /* returns */ "transaction_record",
      /* params: */ {
        {"cancel_order_ids", "order_ids", fbtc::api::required_positional, fc::ovariant()},
        {"new_orders", "order_descriptions", fbtc::api::required_positional, fc::ovariant()},
        {"sign", "bool", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Cancel and/or create many market orders in a single transaction.\n\nParameters:\n  cancel_order_ids (order_ids, required): Order IDs of all market orders to cancel in this transaction.\n  new_orders (order_descriptions, required): Descriptions of all new orders to create in this transaction.\n  sign (bool, required): True if transaction should be signed and broadcast (if possible), false otherwse.\n\nReturns:\n  transaction_record\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_market_batch_update_method_metadata);
  }

  {
    // register method wallet_market_add_collateral
    fbtc::api::method_data wallet_market_add_collateral_method_metadata{"wallet_market_add_collateral", nullptr,
      /* description */ "Add collateral to a short position",
      /* returns */ "transaction_record",
      /* params: */ {
        {"from_account_name", "account_name", fbtc::api::required_positional, fc::ovariant()},
        {"cover_id", "order_id", fbtc::api::required_positional, fc::ovariant()},
        {"real_quantity_collateral_to_add", "string", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Add collateral to a short position\n\nParameters:\n  from_account_name (account_name, required): the account that will provide funds for the ask\n  cover_id (order_id, required): the ID of the order to recollateralize\n  real_quantity_collateral_to_add (string, required): the quantity of collateral of the base asset to add to the specified position\n\nReturns:\n  transaction_record\n",
      /* aliases */ {"add_collateral"}, false};
    store_method_metadata(wallet_market_add_collateral_method_metadata);
  }

  {
    // register method wallet_market_order_list
    fbtc::api::method_data wallet_market_order_list_method_metadata{"wallet_market_order_list", nullptr,
      /* description */ "List an order list of a specific market",
      /* returns */ "market_order_map",
      /* params: */ {
        {"base_symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()},
        {"quote_symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()},
        {"limit", "uint32_t", fbtc::api::optional_positional, fc::variant(fc::json::from_string("-1"))},
        {"account_name", "account_name", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "List an order list of a specific market\n\nParameters:\n  base_symbol (asset_symbol, required): the base symbol of the market\n  quote_symbol (asset_symbol, required): the quote symbol of the market\n  limit (uint32_t, optional, defaults to -1): the maximum number of items to return\n  account_name (account_name, optional, defaults to \"\"): the account for which to get the orders, or empty for all accounts\n\nReturns:\n  market_order_map\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_market_order_list_method_metadata);
  }

  {
    // register method wallet_account_order_list
    fbtc::api::method_data wallet_account_order_list_method_metadata{"wallet_account_order_list", nullptr,
      /* description */ "List an order list of a specific account",
      /* returns */ "market_order_map",
      /* params: */ {
        {"account_name", "account_name", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))},
        {"limit", "uint32_t", fbtc::api::optional_positional, fc::variant(fc::json::from_string("-1"))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "List an order list of a specific account\n\nParameters:\n  account_name (account_name, optional, defaults to \"\"): the account for which to get the orders, or empty for all accounts\n  limit (uint32_t, optional, defaults to -1): the maximum number of items to return\n\nReturns:\n  market_order_map\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_account_order_list_method_metadata);
  }

  {
    // register method wallet_market_cancel_order
    fbtc::api::method_data wallet_market_cancel_order_method_metadata{"wallet_market_cancel_order", nullptr,
      /* description */ "Cancel an order: deprecated - use wallet_market_cancel_orders",
      /* returns */ "transaction_record",
      /* params: */ {
        {"order_id", "order_id", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Cancel an order: deprecated - use wallet_market_cancel_orders\n\nParameters:\n  order_id (order_id, required): the ID of the order to cancel\n\nReturns:\n  transaction_record\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_market_cancel_order_method_metadata);
  }

  {
    // register method wallet_market_cancel_orders
    fbtc::api::method_data wallet_market_cancel_orders_method_metadata{"wallet_market_cancel_orders", nullptr,
      /* description */ "Cancel more than one order at a time",
      /* returns */ "transaction_record",
      /* params: */ {
        {"order_ids", "order_ids", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Cancel more than one order at a time\n\nParameters:\n  order_ids (order_ids, required): the IDs of the orders to cancel\n\nReturns:\n  transaction_record\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_market_cancel_orders_method_metadata);
  }

  {
    // register method wallet_dump_private_key
    fbtc::api::method_data wallet_dump_private_key_method_metadata{"wallet_dump_private_key", nullptr,
      /* description */ "Reveals the private key corresponding to the specified public key or address; use with caution",
      /* returns */ "optional_string",
      /* params: */ {
        {"input", "string", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Reveals the private key corresponding to the specified public key or address; use with caution\n\nParameters:\n  input (string, required): public key or address to dump private key for\n\nReturns:\n  optional_string\n",
      /* aliases */ {"dump_private_key", "dumpprivkey"}, false};
    store_method_metadata(wallet_dump_private_key_method_metadata);
  }

  {
    // register method wallet_dump_account_private_key
    fbtc::api::method_data wallet_dump_account_private_key_method_metadata{"wallet_dump_account_private_key", nullptr,
      /* description */ "Reveals the specified account private key; use with caution",
      /* returns */ "optional_string",
      /* params: */ {
        {"account_name", "string", fbtc::api::required_positional, fc::ovariant()},
        {"key_type", "account_key_type", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Reveals the specified account private key; use with caution\n\nParameters:\n  account_name (string, required): account name to dump private key for\n  key_type (account_key_type, required): which account private key to dump; one of {owner_key, active_key, signing_key}\n\nReturns:\n  optional_string\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_dump_account_private_key_method_metadata);
  }

  {
    // register method wallet_account_vote_summary
    fbtc::api::method_data wallet_account_vote_summary_method_metadata{"wallet_account_vote_summary", nullptr,
      /* description */ "Returns the allocation of votes by this account",
      /* returns */ "account_vote_summary",
      /* params: */ {
        {"account_name", "account_name", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "Returns the allocation of votes by this account\n\nParameters:\n  account_name (account_name, optional, defaults to \"\"): the account to report votes on, or empty for all accounts\n\nReturns:\n  account_vote_summary\n",
      /* aliases */ {"votes"}, false};
    store_method_metadata(wallet_account_vote_summary_method_metadata);
  }

  {
    // register method wallet_set_setting
    fbtc::api::method_data wallet_set_setting_method_metadata{"wallet_set_setting", nullptr,
      /* description */ "Set a property in the GUI settings DB",
      /* returns */ "void",
      /* params: */ {
        {"name", "string", fbtc::api::required_positional, fc::ovariant()},
        {"value", "variant", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "Set a property in the GUI settings DB\n\nParameters:\n  name (string, required): the name of the setting to set\n  value (variant, required): the value to set the setting to\n\nReturns:\n  void\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_set_setting_method_metadata);
  }

  {
    // register method wallet_get_setting
    fbtc::api::method_data wallet_get_setting_method_metadata{"wallet_get_setting", nullptr,
      /* description */ "Get the value of the given setting",
      /* returns */ "optional_variant",
      /* params: */ {
        {"name", "string", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "Get the value of the given setting\n\nParameters:\n  name (string, required): The name of the setting to fetch\n\nReturns:\n  optional_variant\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_get_setting_method_metadata);
  }

  {
    // register method wallet_delegate_set_block_production
    fbtc::api::method_data wallet_delegate_set_block_production_method_metadata{"wallet_delegate_set_block_production", nullptr,
      /* description */ "Enable or disable block production for a particular delegate account",
      /* returns */ "void",
      /* params: */ {
        {"delegate_name", "string", fbtc::api::required_positional, fc::ovariant()},
        {"enabled", "bool", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "Enable or disable block production for a particular delegate account\n\nParameters:\n  delegate_name (string, required): The delegate to enable/disable block production for; ALL for all delegate accounts\n  enabled (bool, required): true to enable block production, false otherwise\n\nReturns:\n  void\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_delegate_set_block_production_method_metadata);
  }

  {
    // register method wallet_set_transaction_scanning
    fbtc::api::method_data wallet_set_transaction_scanning_method_metadata{"wallet_set_transaction_scanning", nullptr,
      /* description */ "Enable or disable wallet transaction scanning",
      /* returns */ "bool",
      /* params: */ {
        {"enabled", "bool", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "Enable or disable wallet transaction scanning\n\nParameters:\n  enabled (bool, required): true to enable transaction scanning, false otherwise\n\nReturns:\n  bool\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_set_transaction_scanning_method_metadata);
  }

  {
    // register method wallet_sign_hash
    fbtc::api::method_data wallet_sign_hash_method_metadata{"wallet_sign_hash", nullptr,
      /* description */ "Signs the provided message digest with the account key",
      /* returns */ "compact_signature",
      /* params: */ {
        {"signer", "string", fbtc::api::required_positional, fc::ovariant()},
        {"hash", "sha256", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Signs the provided message digest with the account key\n\nParameters:\n  signer (string, required): A public key, address, or account name whose key to sign with\n  hash (sha256, required): SHA256 digest of the message to sign\n\nReturns:\n  compact_signature\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_sign_hash_method_metadata);
  }

  {
    // register method wallet_login_start
    fbtc::api::method_data wallet_login_start_method_metadata{"wallet_login_start", nullptr,
      /* description */ "Initiates the login procedure by providing a FastBitcoin Login URL",
      /* returns */ "string",
      /* params: */ {
        {"server_account", "string", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Initiates the login procedure by providing a FastBitcoin Login URL\n\nParameters:\n  server_account (string, required): Name of the account of the server. The user will be shown this name as the site he is logging into.\n\nReturns:\n  string\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_login_start_method_metadata);
  }

  {
    // register method wallet_login_finish
    fbtc::api::method_data wallet_login_finish_method_metadata{"wallet_login_finish", nullptr,
      /* description */ "Completes the login procedure by finding the user's public account key and shared secret",
      /* returns */ "variant",
      /* params: */ {
        {"server_key", "public_key", fbtc::api::required_positional, fc::ovariant()},
        {"client_key", "public_key", fbtc::api::required_positional, fc::ovariant()},
        {"client_signature", "compact_signature", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Completes the login procedure by finding the user's public account key and shared secret\n\nParameters:\n  server_key (public_key, required): The one-time public key from wallet_login_start.\n  client_key (public_key, required): The client's one-time public key.\n  client_signature (compact_signature, required): The client's signature of the shared secret.\n\nReturns:\n  variant\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_login_finish_method_metadata);
  }

  {
    // register method wallet_balance_set_vote_info
    fbtc::api::method_data wallet_balance_set_vote_info_method_metadata{"wallet_balance_set_vote_info", nullptr,
      /* description */ "Set this balance's voting address and slate",
      /* returns */ "transaction_builder",
      /* params: */ {
        {"balance_id", "address", fbtc::api::required_positional, fc::ovariant()},
        {"voter_address", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))},
        {"strategy", "vote_strategy", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"vote_all\""))},
        {"sign_and_broadcast", "bool", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"true\""))},
        {"builder_path", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 2,
      /* detailed description */ "Set this balance's voting address and slate\n\nParameters:\n  balance_id (address, required): the current name of the account\n  voter_address (string, optional, defaults to \"\"): The new voting address. If none is specified, tries to re-use existing address.\n  strategy (vote_strategy, optional, defaults to \"vote_all\"): enumeration [vote_recommended | vote_all | vote_none]\n  sign_and_broadcast (bool, optional, defaults to \"true\"): \n  builder_path (string, optional, defaults to \"\"): If specified, will write builder here instead of to DATA_DIR/transactions/latest.trx\n\nReturns:\n  transaction_builder\n",
      /* aliases */ {"set_vote_info"}, false};
    store_method_metadata(wallet_balance_set_vote_info_method_metadata);
  }

  {
    // register method wallet_publish_slate
    fbtc::api::method_data wallet_publish_slate_method_metadata{"wallet_publish_slate", nullptr,
      /* description */ "Publishes the current wallet delegate slate to the public data associated with the account",
      /* returns */ "transaction_record",
      /* params: */ {
        {"publishing_account_name", "account_name", fbtc::api::required_positional, fc::ovariant()},
        {"paying_account_name", "account_name", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Publishes the current wallet delegate slate to the public data associated with the account\n\nParameters:\n  publishing_account_name (account_name, required): The account to publish the slate ID under\n  paying_account_name (account_name, optional, defaults to \"\"): The account to pay transaction fees or leave empty to pay with publishing account\n\nReturns:\n  transaction_record\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_publish_slate_method_metadata);
  }

  {
    // register method wallet_publish_version
    fbtc::api::method_data wallet_publish_version_method_metadata{"wallet_publish_version", nullptr,
      /* description */ "Publish your current client version to the specified account's public data record",
      /* returns */ "transaction_record",
      /* params: */ {
        {"publishing_account_name", "account_name", fbtc::api::required_positional, fc::ovariant()},
        {"paying_account_name", "account_name", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Publish your current client version to the specified account's public data record\n\nParameters:\n  publishing_account_name (account_name, required): The account to publish the client version under\n  paying_account_name (account_name, optional, defaults to \"\"): The account to pay transaction fees with or leave empty to pay with publishing account\n\nReturns:\n  transaction_record\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_publish_version_method_metadata);
  }

  {
    // register method wallet_collect_genesis_balances
    fbtc::api::method_data wallet_collect_genesis_balances_method_metadata{"wallet_collect_genesis_balances", nullptr,
      /* description */ "Collect specified account's genesis balances",
      /* returns */ "transaction_record",
      /* params: */ {
        {"account_name", "account_name", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Collect specified account's genesis balances\n\nParameters:\n  account_name (account_name, required): account to collect genesis balances for\n\nReturns:\n  transaction_record\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_collect_genesis_balances_method_metadata);
  }

  {
    // register method wallet_collect_vested_balances
    fbtc::api::method_data wallet_collect_vested_balances_method_metadata{"wallet_collect_vested_balances", nullptr,
      /* description */ "Collect specified account's vested balances",
      /* returns */ "transaction_record",
      /* params: */ {
        {"account_name", "account_name", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Collect specified account's vested balances\n\nParameters:\n  account_name (account_name, required): account to collect vested balances for\n\nReturns:\n  transaction_record\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_collect_vested_balances_method_metadata);
  }

  {
    // register method wallet_delegate_update_signing_key
    fbtc::api::method_data wallet_delegate_update_signing_key_method_metadata{"wallet_delegate_update_signing_key", nullptr,
      /* description */ "Update a delegate's block signing and feed publishing key",
      /* returns */ "transaction_record",
      /* params: */ {
        {"authorizing_account_name", "account_name", fbtc::api::required_positional, fc::ovariant()},
        {"delegate_name", "account_name", fbtc::api::required_positional, fc::ovariant()},
        {"signing_key", "public_key", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Update a delegate's block signing and feed publishing key\n\nParameters:\n  authorizing_account_name (account_name, required): The account that will authorize changing the block signing key\n  delegate_name (account_name, required): The delegate account which will have its block signing key changed\n  signing_key (public_key, required): The new key that will be used for block signing\n\nReturns:\n  transaction_record\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_delegate_update_signing_key_method_metadata);
  }

  {
    // register method wallet_recover_accounts
    fbtc::api::method_data wallet_recover_accounts_method_metadata{"wallet_recover_accounts", nullptr,
      /* description */ "Attempts to recover accounts created after last backup was taken and returns number of successful recoveries. Use if you have restored from backup and are missing accounts.",
      /* returns */ "int32_t",
      /* params: */ {
        {"accounts_to_recover", "int32_t", fbtc::api::required_positional, fc::ovariant()},
        {"maximum_number_of_attempts", "int32_t", fbtc::api::optional_positional, fc::variant(fc::json::from_string("1000"))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Attempts to recover accounts created after last backup was taken and returns number of successful recoveries. Use if you have restored from backup and are missing accounts.\n\nParameters:\n  accounts_to_recover (int32_t, required): The number of accounts to attept to recover\n  maximum_number_of_attempts (int32_t, optional, defaults to 1000): The maximum number of keys to generate trying to recover accounts\n\nReturns:\n  int32_t\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_recover_accounts_method_metadata);
  }

  {
    // register method wallet_recover_titan_deposit_info
    fbtc::api::method_data wallet_recover_titan_deposit_info_method_metadata{"wallet_recover_titan_deposit_info", nullptr,
      /* description */ "Attempts to recover any missing recipient and memo information for the specified transaction",
      /* returns */ "transaction_record",
      /* params: */ {
        {"transaction_id_prefix", "string", fbtc::api::required_positional, fc::ovariant()},
        {"recipient_account", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Attempts to recover any missing recipient and memo information for the specified transaction\n\nParameters:\n  transaction_id_prefix (string, required): the id (or id prefix) of the transaction record\n  recipient_account (string, optional, defaults to \"\"): the account name of the recipient (if known)\n\nReturns:\n  transaction_record\n",
      /* aliases */ {"recover_transaction"}, false};
    store_method_metadata(wallet_recover_titan_deposit_info_method_metadata);
  }

  {
    // register method wallet_verify_titan_deposit
    fbtc::api::method_data wallet_verify_titan_deposit_method_metadata{"wallet_verify_titan_deposit", nullptr,
      /* description */ "Verify whether the specified transaction made a TITAN deposit to the current wallet; returns null if not",
      /* returns */ "optional_variant_object",
      /* params: */ {
        {"transaction_id_prefix", "string", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Verify whether the specified transaction made a TITAN deposit to the current wallet; returns null if not\n\nParameters:\n  transaction_id_prefix (string, required): the id (or id prefix) of the transaction record\n\nReturns:\n  optional_variant_object\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_verify_titan_deposit_method_metadata);
  }

  {
    // register method wallet_publish_price_feed
    fbtc::api::method_data wallet_publish_price_feed_method_metadata{"wallet_publish_price_feed", nullptr,
      /* description */ "publishes a price feed for BitAssets, only active delegates may do this",
      /* returns */ "transaction_record",
      /* params: */ {
        {"delegate_account", "account_name", fbtc::api::required_positional, fc::ovariant()},
        {"price", "string", fbtc::api::required_positional, fc::ovariant()},
        {"asset_symbol", "asset_symbol", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "publishes a price feed for BitAssets, only active delegates may do this\n\nParameters:\n  delegate_account (account_name, required): the delegate to publish the price under\n  price (string, required): the number of this asset per XTS\n  asset_symbol (asset_symbol, required): the type of asset being priced\n\nReturns:\n  transaction_record\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_publish_price_feed_method_metadata);
  }

  {
    // register method wallet_publish_feeds
    fbtc::api::method_data wallet_publish_feeds_method_metadata{"wallet_publish_feeds", nullptr,
      /* description */ "publish price feeds for market-pegged assets; pays fee from delegate pay balance otherwise wallet account balance",
      /* returns */ "transaction_record",
      /* params: */ {
        {"delegate_account", "account_name", fbtc::api::required_positional, fc::ovariant()},
        {"symbol_to_price_map", "string_map", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "publish price feeds for market-pegged assets; pays fee from delegate pay balance otherwise wallet account balance\n\nParameters:\n  delegate_account (account_name, required): the delegate to publish the price under\n  symbol_to_price_map (string_map, required): maps the BitAsset symbol to its price per share\n\nReturns:\n  transaction_record\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_publish_feeds_method_metadata);
  }

  {
    // register method wallet_publish_feeds_multi_experimental
    fbtc::api::method_data wallet_publish_feeds_multi_experimental_method_metadata{"wallet_publish_feeds_multi_experimental", nullptr,
      /* description */ "publishes a set of feeds for BitAssets for all active delegates, most useful for testnets",
      /* returns */ "vector<std::pair<string, wallet_transaction_record>>",
      /* params: */ {
        {"symbol_to_price_map", "string_map", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "publishes a set of feeds for BitAssets for all active delegates, most useful for testnets\n\nParameters:\n  symbol_to_price_map (string_map, required): maps the BitAsset symbol to its price per share\n\nReturns:\n  vector<std::pair<string, wallet_transaction_record>>\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_publish_feeds_multi_experimental_method_metadata);
  }

  {
    // register method wallet_repair_records
    fbtc::api::method_data wallet_repair_records_method_metadata{"wallet_repair_records", nullptr,
      /* description */ "tries to repair any inconsistent wallet account, key, and transaction records",
      /* returns */ "void",
      /* params: */ {
        {"collecting_account_name", "account_name", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "tries to repair any inconsistent wallet account, key, and transaction records\n\nParameters:\n  collecting_account_name (account_name, optional, defaults to \"\"): collect any orphan balances into this account\n\nReturns:\n  void\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_repair_records_method_metadata);
  }

  {
    // register method wallet_regenerate_keys
    fbtc::api::method_data wallet_regenerate_keys_method_metadata{"wallet_regenerate_keys", nullptr,
      /* description */ "regenerates private keys as part of wallet recovery",
      /* returns */ "int32_t",
      /* params: */ {
        {"account_name", "account_name", fbtc::api::required_positional, fc::ovariant()},
        {"max_key_number", "uint32_t", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "regenerates private keys as part of wallet recovery\n\nParameters:\n  account_name (account_name, required): the account the generated keys should be a part of\n  max_key_number (uint32_t, required): the last key number to regenerate\n\nReturns:\n  int32_t\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_regenerate_keys_method_metadata);
  }

  {
    // register method wallet_account_retract
    fbtc::api::method_data wallet_account_retract_method_metadata{"wallet_account_retract", nullptr,
      /* description */ "Retract (permanently disable) the specified account in case of master key compromise.",
      /* returns */ "transaction_record",
      /* params: */ {
        {"account_to_retract", "account_name", fbtc::api::required_positional, fc::ovariant()},
        {"pay_from_account", "account_name", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Retract (permanently disable) the specified account in case of master key compromise.\n\nParameters:\n  account_to_retract (account_name, required): The name of the account to retract.\n  pay_from_account (account_name, required): The account from which fees will be paid.\n\nReturns:\n  transaction_record\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_account_retract_method_metadata);
  }

  {
    // register method wallet_generate_brain_seed
    fbtc::api::method_data wallet_generate_brain_seed_method_metadata{"wallet_generate_brain_seed", nullptr,
      /* description */ "Generates a human friendly brain wallet key starting with a public salt as the last word",
      /* returns */ "string",
      /* params: */ {},
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Generates a human friendly brain wallet key starting with a public salt as the last word\n\nParameters:\n  (none)\n\nReturns:\n  string\n",
      /* aliases */ {}, false};
    store_method_metadata(wallet_generate_brain_seed_method_metadata);
  }

  {
    // register method fetch_welcome_package
    fbtc::api::method_data fetch_welcome_package_method_metadata{"fetch_welcome_package", nullptr,
      /* description */ "Return all the data a light wallet needs to bootstrap itself.",
      /* returns */ "variant_object",
      /* params: */ {
        {"arguments", "variant_object", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Return all the data a light wallet needs to bootstrap itself.\n\nParameters:\n  arguments (variant_object, required): Arguments to fetch_welcome_package\n\nReturns:\n  variant_object\n",
      /* aliases */ {}, false};
    store_method_metadata(fetch_welcome_package_method_metadata);
  }

  {
    // register method request_register_account
    fbtc::api::method_data request_register_account_method_metadata{"request_register_account", nullptr,
      /* description */ "Adds an account record to the request queue",
      /* returns */ "bool",
      /* params: */ {
        {"account", "account_record", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Adds an account record to the request queue\n\nParameters:\n  account (account_record, required): the account to be registered\n\nReturns:\n  bool\n",
      /* aliases */ {}, false};
    store_method_metadata(request_register_account_method_metadata);
  }

  {
    // register method approve_register_account
    fbtc::api::method_data approve_register_account_method_metadata{"approve_register_account", nullptr,
      /* description */ "Adds an account record to the request queue",
      /* returns */ "bool",
      /* params: */ {
        {"account_salt", "string", fbtc::api::required_positional, fc::ovariant()},
        {"paying_account_name", "account_name", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 5,
      /* detailed description */ "Adds an account record to the request queue\n\nParameters:\n  account_salt (string, required): the salt property of the registered account\n  paying_account_name (account_name, required): the name of the account that should pay\n\nReturns:\n  bool\n",
      /* aliases */ {}, false};
    store_method_metadata(approve_register_account_method_metadata);
  }

  {
    // register method debug_start_simulated_time
    fbtc::api::method_data debug_start_simulated_time_method_metadata{"debug_start_simulated_time", nullptr,
      /* description */ "Begin using simulated time for testing",
      /* returns */ "void",
      /* params: */ {
        {"new_simulated_time", "timestamp", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "Begin using simulated time for testing\n\nParameters:\n  new_simulated_time (timestamp, required): The simulated time to start with\n\nReturns:\n  void\n",
      /* aliases */ {"start_simulated_time"}, false};
    store_method_metadata(debug_start_simulated_time_method_metadata);
  }

  {
    // register method debug_advance_time
    fbtc::api::method_data debug_advance_time_method_metadata{"debug_advance_time", nullptr,
      /* description */ "Advance simulated time",
      /* returns */ "void",
      /* params: */ {
        {"delta_time_seconds", "int32_t", fbtc::api::required_positional, fc::ovariant()},
        {"unit", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"seconds\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "Advance simulated time\n\nParameters:\n  delta_time_seconds (int32_t, required): How far in the future to advance the time\n  unit (string, optional, defaults to \"seconds\"): The unit of time (\"seconds\", \"blocks\", or \"rounds\")\n\nReturns:\n  void\n",
      /* aliases */ {"advance_time"}, false};
    store_method_metadata(debug_advance_time_method_metadata);
  }

  {
    // register method debug_trap
    fbtc::api::method_data debug_trap_method_metadata{"debug_trap", nullptr,
      /* description */ "Break into debugger (UNIX: SIGINT, win32: __debugbreak)",
      /* returns */ "void",
      /* params: */ {
        {"block_number", "uint32_t", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "Break into debugger (UNIX: SIGINT, win32: __debugbreak)\n\nParameters:\n  block_number (uint32_t, required): Delay trap until we start to process the given blocknum\n\nReturns:\n  void\n",
      /* aliases */ {}, false};
    store_method_metadata(debug_trap_method_metadata);
  }

  {
    // register method debug_wait
    fbtc::api::method_data debug_wait_method_metadata{"debug_wait", nullptr,
      /* description */ "wait for specified amount of time",
      /* returns */ "void",
      /* params: */ {
        {"wait_time", "uint32_t", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "wait for specified amount of time\n\nParameters:\n  wait_time (uint32_t, required): time in seconds to wait before accepting more input\n\nReturns:\n  void\n",
      /* aliases */ {"wait"}, false};
    store_method_metadata(debug_wait_method_metadata);
  }

  {
    // register method debug_wait_for_block_by_number
    fbtc::api::method_data debug_wait_for_block_by_number_method_metadata{"debug_wait_for_block_by_number", nullptr,
      /* description */ "Don't return until the specified block has arrived",
      /* returns */ "void",
      /* params: */ {
        {"block_number", "uint32_t", fbtc::api::required_positional, fc::ovariant()},
        {"type", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"absolute\""))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "Don't return until the specified block has arrived\n\nParameters:\n  block_number (uint32_t, required): The block number (or offset) to wait for\n  type (string, optional, defaults to \"absolute\"): Whether to wait for an \"absolute\" block number, or a count of blocks \"relative\" to the current block number\n\nReturns:\n  void\n",
      /* aliases */ {"wait_for_block_by_number"}, false};
    store_method_metadata(debug_wait_for_block_by_number_method_metadata);
  }

  {
    // register method debug_wait_block_interval
    fbtc::api::method_data debug_wait_block_interval_method_metadata{"debug_wait_block_interval", nullptr,
      /* description */ "wait for n block intervals",
      /* returns */ "void",
      /* params: */ {
        {"wait_time_in_block_intervals", "uint32_t", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "wait for n block intervals\n\nParameters:\n  wait_time_in_block_intervals (uint32_t, required): time in block intervals to wait before accepting more input\n\nReturns:\n  void\n",
      /* aliases */ {"wait_block_interval"}, false};
    store_method_metadata(debug_wait_block_interval_method_metadata);
  }

  {
    // register method debug_enable_output
    fbtc::api::method_data debug_enable_output_method_metadata{"debug_enable_output", nullptr,
      /* description */ "enables or disables output from the CLI",
      /* returns */ "void",
      /* params: */ {
        {"enable_flag", "bool", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "enables or disables output from the CLI\n\nParameters:\n  enable_flag (bool, required): true to enable output, false to disable it\n\nReturns:\n  void\n",
      /* aliases */ {"enable_output"}, false};
    store_method_metadata(debug_enable_output_method_metadata);
  }

  {
    // register method debug_filter_output_for_tests
    fbtc::api::method_data debug_filter_output_for_tests_method_metadata{"debug_filter_output_for_tests", nullptr,
      /* description */ "prevents printing any times or other unpredictable data",
      /* returns */ "void",
      /* params: */ {
        {"enable_flag", "bool", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "prevents printing any times or other unpredictable data\n\nParameters:\n  enable_flag (bool, required): true to enable filtering, false to disable it\n\nReturns:\n  void\n",
      /* aliases */ {"filter_output_for_tests"}, false};
    store_method_metadata(debug_filter_output_for_tests_method_metadata);
  }

  {
    // register method debug_update_logging_config
    fbtc::api::method_data debug_update_logging_config_method_metadata{"debug_update_logging_config", nullptr,
      /* description */ "updates logging configuration (level, etc) based on settings in config.json",
      /* returns */ "void",
      /* params: */ {},
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "updates logging configuration (level, etc) based on settings in config.json\n\nParameters:\n  (none)\n\nReturns:\n  void\n",
      /* aliases */ {}, false};
    store_method_metadata(debug_update_logging_config_method_metadata);
  }

  {
    // register method debug_get_call_statistics
    fbtc::api::method_data debug_get_call_statistics_method_metadata{"debug_get_call_statistics", nullptr,
      /* description */ "Returns call timings for node_delegate callbacks",
      /* returns */ "json_object",
      /* params: */ {},
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Returns call timings for node_delegate callbacks\n\nParameters:\n  (none)\n\nReturns:\n  json_object\n",
      /* aliases */ {}, false};
    store_method_metadata(debug_get_call_statistics_method_metadata);
  }

  {
    // register method debug_get_client_name
    fbtc::api::method_data debug_get_client_name_method_metadata{"debug_get_client_name", nullptr,
      /* description */ "Returns client's debug name specified in config.json",
      /* returns */ "string",
      /* params: */ {},
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "Returns client's debug name specified in config.json\n\nParameters:\n  (none)\n\nReturns:\n  string\n",
      /* aliases */ {}, false};
    store_method_metadata(debug_get_client_name_method_metadata);
  }

  {
    // register method debug_deterministic_private_keys
    fbtc::api::method_data debug_deterministic_private_keys_method_metadata{"debug_deterministic_private_keys", nullptr,
      /* description */ "Generate/import deterministically generated private keys",
      /* returns */ "variants",
      /* params: */ {
        {"start", "int32_t", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"-1\""))},
        {"count", "int32_t", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"1\""))},
        {"prefix", "string", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"\""))},
        {"import", "bool", fbtc::api::optional_positional, fc::variant(fc::json::from_string("\"false\""))},
        {"account_name", "account_name", fbtc::api::optional_positional, fc::variant(fc::json::from_string("null"))},
        {"create_new_account", "bool", fbtc::api::optional_positional, fc::variant(fc::json::from_string("false"))},
        {"rescan", "bool", fbtc::api::optional_positional, fc::variant(fc::json::from_string("false"))}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 4,
      /* detailed description */ "Generate/import deterministically generated private keys\n\nParameters:\n  start (int32_t, optional, defaults to \"-1\"): the number of the first key, or -1 to suppress suffix\n  count (int32_t, optional, defaults to \"1\"): the number of keys to generate\n  prefix (string, optional, defaults to \"\"): a string prefix added to the seed used to generate keys\n  import (bool, optional, defaults to \"false\"): whether to import generated keys\n  account_name (account_name, optional, defaults to null): the name of the account the key should be imported into, if null then the key must belong to an active account\n  create_new_account (bool, optional, defaults to false): If true, the wallet will attempt to create a new account for the name provided rather than import the key into an existing account\n  rescan (bool, optional, defaults to false): If true, the wallet will rescan the blockchain looking for transactions that involve this private key\n\nReturns:\n  variants\n",
      /* aliases */ {}, false};
    store_method_metadata(debug_deterministic_private_keys_method_metadata);
  }

  {
    // register method debug_stop_before_block
    fbtc::api::method_data debug_stop_before_block_method_metadata{"debug_stop_before_block", nullptr,
      /* description */ "stop before given block number",
      /* returns */ "void",
      /* params: */ {
        {"block_number", "uint32_t", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 1,
      /* detailed description */ "stop before given block number\n\nParameters:\n  block_number (uint32_t, required): The block number to stop before\n\nReturns:\n  void\n",
      /* aliases */ {"stop_before_block", "stop_b4_block", "debug_stop_b4_block", "stop_before", "stop_b4", "stopb4"}, false};
    store_method_metadata(debug_stop_before_block_method_metadata);
  }

  {
    // register method debug_verify_market_matching
    fbtc::api::method_data debug_verify_market_matching_method_metadata{"debug_verify_market_matching", nullptr,
      /* description */ "enables or disables (slow) market matching verification code",
      /* returns */ "void",
      /* params: */ {
        {"enable_flag", "bool", fbtc::api::required_positional, fc::ovariant()}
      },
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "enables or disables (slow) market matching verification code\n\nParameters:\n  enable_flag (bool, required): true to enable checking, false to disable it\n\nReturns:\n  void\n",
      /* aliases */ {}, false};
    store_method_metadata(debug_verify_market_matching_method_metadata);
  }

  {
    // register method debug_list_matching_errors
    fbtc::api::method_data debug_list_matching_errors_method_metadata{"debug_list_matching_errors", nullptr,
      /* description */ "returns a list of blocks flagged by debug_verify_market_matching",
      /* returns */ "variants",
      /* params: */ {},
      /* prerequisites */ (fbtc::api::method_prerequisites) 0,
      /* detailed description */ "returns a list of blocks flagged by debug_verify_market_matching\n\nParameters:\n  (none)\n\nReturns:\n  variants\n",
      /* aliases */ {}, false};
    store_method_metadata(debug_list_matching_errors_method_metadata);
  }

}

fc::variant common_api_rpc_server::direct_invoke_positional_method(const std::string& method_name, const fc::variants& parameters)
{
  if (method_name == "about")
    return about_positional(nullptr, parameters);
  if (method_name == "get_info")
    return get_info_positional(nullptr, parameters);
  if (method_name == "stop")
    return stop_positional(nullptr, parameters);
  if (method_name == "help")
    return help_positional(nullptr, parameters);
  if (method_name == "validate_address")
    return validate_address_positional(nullptr, parameters);
  if (method_name == "convert_to_native_address")
    return convert_to_native_address_positional(nullptr, parameters);
  if (method_name == "execute_command_line")
    return execute_command_line_positional(nullptr, parameters);
  if (method_name == "execute_script")
    return execute_script_positional(nullptr, parameters);
  if (method_name == "batch")
    return batch_positional(nullptr, parameters);
  if (method_name == "batch_authenticated")
    return batch_authenticated_positional(nullptr, parameters);
  if (method_name == "builder_finalize_and_sign")
    return builder_finalize_and_sign_positional(nullptr, parameters);
  if (method_name == "meta_help")
    return meta_help_positional(nullptr, parameters);
  if (method_name == "rpc_set_username")
    return rpc_set_username_positional(nullptr, parameters);
  if (method_name == "rpc_set_password")
    return rpc_set_password_positional(nullptr, parameters);
  if (method_name == "rpc_start_server")
    return rpc_start_server_positional(nullptr, parameters);
  if (method_name == "http_start_server")
    return http_start_server_positional(nullptr, parameters);
  if (method_name == "ntp_update_time")
    return ntp_update_time_positional(nullptr, parameters);
  if (method_name == "disk_usage")
    return disk_usage_positional(nullptr, parameters);
  if (method_name == "network_add_node")
    return network_add_node_positional(nullptr, parameters);
  if (method_name == "network_get_connection_count")
    return network_get_connection_count_positional(nullptr, parameters);
  if (method_name == "network_get_peer_info")
    return network_get_peer_info_positional(nullptr, parameters);
  if (method_name == "network_broadcast_transaction")
    return network_broadcast_transaction_positional(nullptr, parameters);
  if (method_name == "network_set_advanced_node_parameters")
    return network_set_advanced_node_parameters_positional(nullptr, parameters);
  if (method_name == "network_get_advanced_node_parameters")
    return network_get_advanced_node_parameters_positional(nullptr, parameters);
  if (method_name == "network_get_transaction_propagation_data")
    return network_get_transaction_propagation_data_positional(nullptr, parameters);
  if (method_name == "network_get_block_propagation_data")
    return network_get_block_propagation_data_positional(nullptr, parameters);
  if (method_name == "network_set_allowed_peers")
    return network_set_allowed_peers_positional(nullptr, parameters);
  if (method_name == "network_get_info")
    return network_get_info_positional(nullptr, parameters);
  if (method_name == "network_list_potential_peers")
    return network_list_potential_peers_positional(nullptr, parameters);
  if (method_name == "network_get_upnp_info")
    return network_get_upnp_info_positional(nullptr, parameters);
  if (method_name == "network_get_usage_stats")
    return network_get_usage_stats_positional(nullptr, parameters);
  if (method_name == "delegate_get_config")
    return delegate_get_config_positional(nullptr, parameters);
  if (method_name == "delegate_set_network_min_connection_count")
    return delegate_set_network_min_connection_count_positional(nullptr, parameters);
  if (method_name == "delegate_set_block_max_transaction_count")
    return delegate_set_block_max_transaction_count_positional(nullptr, parameters);
  if (method_name == "delegate_set_block_max_size")
    return delegate_set_block_max_size_positional(nullptr, parameters);
  if (method_name == "delegate_set_block_max_production_time")
    return delegate_set_block_max_production_time_positional(nullptr, parameters);
  if (method_name == "delegate_set_transaction_max_size")
    return delegate_set_transaction_max_size_positional(nullptr, parameters);
  if (method_name == "delegate_set_transaction_canonical_signatures_required")
    return delegate_set_transaction_canonical_signatures_required_positional(nullptr, parameters);
  if (method_name == "delegate_set_transaction_min_fee")
    return delegate_set_transaction_min_fee_positional(nullptr, parameters);
  if (method_name == "delegate_blacklist_add_transaction")
    return delegate_blacklist_add_transaction_positional(nullptr, parameters);
  if (method_name == "delegate_blacklist_remove_transaction")
    return delegate_blacklist_remove_transaction_positional(nullptr, parameters);
  if (method_name == "delegate_blacklist_add_operation")
    return delegate_blacklist_add_operation_positional(nullptr, parameters);
  if (method_name == "delegate_blacklist_remove_operation")
    return delegate_blacklist_remove_operation_positional(nullptr, parameters);
  if (method_name == "blockchain_get_info")
    return blockchain_get_info_positional(nullptr, parameters);
  if (method_name == "blockchain_generate_snapshot")
    return blockchain_generate_snapshot_positional(nullptr, parameters);
  if (method_name == "blockchain_graphene_snapshot")
    return blockchain_graphene_snapshot_positional(nullptr, parameters);
  if (method_name == "blockchain_generate_issuance_map")
    return blockchain_generate_issuance_map_positional(nullptr, parameters);
  if (method_name == "blockchain_calculate_supply")
    return blockchain_calculate_supply_positional(nullptr, parameters);
  if (method_name == "blockchain_calculate_debt")
    return blockchain_calculate_debt_positional(nullptr, parameters);
  if (method_name == "blockchain_calculate_max_supply")
    return blockchain_calculate_max_supply_positional(nullptr, parameters);
  if (method_name == "blockchain_get_block_count")
    return blockchain_get_block_count_positional(nullptr, parameters);
  if (method_name == "blockchain_list_accounts")
    return blockchain_list_accounts_positional(nullptr, parameters);
  if (method_name == "blockchain_list_recently_updated_accounts")
    return blockchain_list_recently_updated_accounts_positional(nullptr, parameters);
  if (method_name == "blockchain_list_recently_registered_accounts")
    return blockchain_list_recently_registered_accounts_positional(nullptr, parameters);
  if (method_name == "blockchain_list_assets")
    return blockchain_list_assets_positional(nullptr, parameters);
  if (method_name == "blockchain_list_feed_prices")
    return blockchain_list_feed_prices_positional(nullptr, parameters);
  if (method_name == "blockchain_get_account_wall")
    return blockchain_get_account_wall_positional(nullptr, parameters);
  if (method_name == "blockchain_list_pending_transactions")
    return blockchain_list_pending_transactions_positional(nullptr, parameters);
  if (method_name == "blockchain_get_pending_transactions_count")
    return blockchain_get_pending_transactions_count_positional(nullptr, parameters);
  if (method_name == "blockchain_get_transaction")
    return blockchain_get_transaction_positional(nullptr, parameters);
  if (method_name == "blockchain_get_block")
    return blockchain_get_block_positional(nullptr, parameters);
  if (method_name == "blockchain_get_block_transactions")
    return blockchain_get_block_transactions_positional(nullptr, parameters);
  if (method_name == "blockchain_get_account")
    return blockchain_get_account_positional(nullptr, parameters);
  if (method_name == "blockchain_get_slate")
    return blockchain_get_slate_positional(nullptr, parameters);
  if (method_name == "blockchain_get_balance")
    return blockchain_get_balance_positional(nullptr, parameters);
  if (method_name == "blockchain_list_balances")
    return blockchain_list_balances_positional(nullptr, parameters);
  if (method_name == "blockchain_list_address_balances")
    return blockchain_list_address_balances_positional(nullptr, parameters);
  if (method_name == "blockchain_list_address_transactions")
    return blockchain_list_address_transactions_positional(nullptr, parameters);
  if (method_name == "blockchain_get_account_public_balance")
    return blockchain_get_account_public_balance_positional(nullptr, parameters);
  if (method_name == "blockchain_median_feed_price")
    return blockchain_median_feed_price_positional(nullptr, parameters);
  if (method_name == "blockchain_list_key_balances")
    return blockchain_list_key_balances_positional(nullptr, parameters);
  if (method_name == "blockchain_get_asset")
    return blockchain_get_asset_positional(nullptr, parameters);
  if (method_name == "blockchain_get_feeds_for_asset")
    return blockchain_get_feeds_for_asset_positional(nullptr, parameters);
  if (method_name == "blockchain_get_feeds_from_delegate")
    return blockchain_get_feeds_from_delegate_positional(nullptr, parameters);
  if (method_name == "blockchain_market_list_bids")
    return blockchain_market_list_bids_positional(nullptr, parameters);
  if (method_name == "blockchain_market_list_asks")
    return blockchain_market_list_asks_positional(nullptr, parameters);
  if (method_name == "blockchain_market_list_shorts")
    return blockchain_market_list_shorts_positional(nullptr, parameters);
  if (method_name == "blockchain_market_list_covers")
    return blockchain_market_list_covers_positional(nullptr, parameters);
  if (method_name == "blockchain_market_get_asset_collateral")
    return blockchain_market_get_asset_collateral_positional(nullptr, parameters);
  if (method_name == "blockchain_market_order_book")
    return blockchain_market_order_book_positional(nullptr, parameters);
  if (method_name == "blockchain_get_market_order")
    return blockchain_get_market_order_positional(nullptr, parameters);
  if (method_name == "blockchain_list_address_orders")
    return blockchain_list_address_orders_positional(nullptr, parameters);
  if (method_name == "blockchain_market_order_history")
    return blockchain_market_order_history_positional(nullptr, parameters);
  if (method_name == "blockchain_market_price_history")
    return blockchain_market_price_history_positional(nullptr, parameters);
  if (method_name == "blockchain_list_active_delegates")
    return blockchain_list_active_delegates_positional(nullptr, parameters);
  if (method_name == "blockchain_list_delegates")
    return blockchain_list_delegates_positional(nullptr, parameters);
  if (method_name == "blockchain_list_blocks")
    return blockchain_list_blocks_positional(nullptr, parameters);
  if (method_name == "blockchain_list_missing_block_delegates")
    return blockchain_list_missing_block_delegates_positional(nullptr, parameters);
  if (method_name == "blockchain_export_fork_graph")
    return blockchain_export_fork_graph_positional(nullptr, parameters);
  if (method_name == "blockchain_list_forks")
    return blockchain_list_forks_positional(nullptr, parameters);
  if (method_name == "blockchain_get_delegate_slot_records")
    return blockchain_get_delegate_slot_records_positional(nullptr, parameters);
  if (method_name == "blockchain_get_block_signee")
    return blockchain_get_block_signee_positional(nullptr, parameters);
  if (method_name == "blockchain_list_markets")
    return blockchain_list_markets_positional(nullptr, parameters);
  if (method_name == "blockchain_list_market_transactions")
    return blockchain_list_market_transactions_positional(nullptr, parameters);
  if (method_name == "blockchain_market_status")
    return blockchain_market_status_positional(nullptr, parameters);
  if (method_name == "blockchain_unclaimed_genesis")
    return blockchain_unclaimed_genesis_positional(nullptr, parameters);
  if (method_name == "blockchain_verify_signature")
    return blockchain_verify_signature_positional(nullptr, parameters);
  if (method_name == "blockchain_broadcast_transaction")
    return blockchain_broadcast_transaction_positional(nullptr, parameters);
  if (method_name == "wallet_get_info")
    return wallet_get_info_positional(nullptr, parameters);
  if (method_name == "wallet_open")
    return wallet_open_positional(nullptr, parameters);
  if (method_name == "wallet_get_account_public_address")
    return wallet_get_account_public_address_positional(nullptr, parameters);
  if (method_name == "wallet_list_my_addresses")
    return wallet_list_my_addresses_positional(nullptr, parameters);
  if (method_name == "wallet_create")
    return wallet_create_positional(nullptr, parameters);
  if (method_name == "wallet_import_private_key")
    return wallet_import_private_key_positional(nullptr, parameters);
  if (method_name == "wallet_import_bitcoin")
    return wallet_import_bitcoin_positional(nullptr, parameters);
  if (method_name == "wallet_import_electrum")
    return wallet_import_electrum_positional(nullptr, parameters);
  if (method_name == "wallet_import_keyhotee")
    return wallet_import_keyhotee_positional(nullptr, parameters);
  if (method_name == "wallet_import_keys_from_json")
    return wallet_import_keys_from_json_positional(nullptr, parameters);
  if (method_name == "wallet_close")
    return wallet_close_positional(nullptr, parameters);
  if (method_name == "wallet_backup_create")
    return wallet_backup_create_positional(nullptr, parameters);
  if (method_name == "wallet_backup_restore")
    return wallet_backup_restore_positional(nullptr, parameters);
  if (method_name == "wallet_export_keys")
    return wallet_export_keys_positional(nullptr, parameters);
  if (method_name == "wallet_set_automatic_backups")
    return wallet_set_automatic_backups_positional(nullptr, parameters);
  if (method_name == "wallet_set_transaction_expiration_time")
    return wallet_set_transaction_expiration_time_positional(nullptr, parameters);
  if (method_name == "wallet_account_transaction_history")
    return wallet_account_transaction_history_positional(nullptr, parameters);
  if (method_name == "wallet_account_historic_balance")
    return wallet_account_historic_balance_positional(nullptr, parameters);
  if (method_name == "wallet_transaction_history_experimental")
    return wallet_transaction_history_experimental_positional(nullptr, parameters);
  if (method_name == "wallet_remove_transaction")
    return wallet_remove_transaction_positional(nullptr, parameters);
  if (method_name == "wallet_get_pending_transaction_errors")
    return wallet_get_pending_transaction_errors_positional(nullptr, parameters);
  if (method_name == "wallet_lock")
    return wallet_lock_positional(nullptr, parameters);
  if (method_name == "wallet_unlock")
    return wallet_unlock_positional(nullptr, parameters);
  if (method_name == "wallet_change_passphrase")
    return wallet_change_passphrase_positional(nullptr, parameters);
  if (method_name == "wallet_list")
    return wallet_list_positional(nullptr, parameters);
  if (method_name == "wallet_account_create")
    return wallet_account_create_positional(nullptr, parameters);
  if (method_name == "wallet_list_contacts")
    return wallet_list_contacts_positional(nullptr, parameters);
  if (method_name == "wallet_get_contact")
    return wallet_get_contact_positional(nullptr, parameters);
  if (method_name == "wallet_add_contact")
    return wallet_add_contact_positional(nullptr, parameters);
  if (method_name == "wallet_remove_contact")
    return wallet_remove_contact_positional(nullptr, parameters);
  if (method_name == "wallet_list_approvals")
    return wallet_list_approvals_positional(nullptr, parameters);
  if (method_name == "wallet_get_approval")
    return wallet_get_approval_positional(nullptr, parameters);
  if (method_name == "wallet_approve")
    return wallet_approve_positional(nullptr, parameters);
  if (method_name == "wallet_burn")
    return wallet_burn_positional(nullptr, parameters);
  if (method_name == "wallet_address_create")
    return wallet_address_create_positional(nullptr, parameters);
  if (method_name == "wallet_transfer_to_address")
    return wallet_transfer_to_address_positional(nullptr, parameters);
  if (method_name == "wallet_transfer_to_genesis_multisig_address")
    return wallet_transfer_to_genesis_multisig_address_positional(nullptr, parameters);
  if (method_name == "wallet_transfer_to_address_from_file")
    return wallet_transfer_to_address_from_file_positional(nullptr, parameters);
  if (method_name == "wallet_transfer_to_genesis_multisig_address_from_file")
    return wallet_transfer_to_genesis_multisig_address_from_file_positional(nullptr, parameters);
  if (method_name == "wallet_check_passphrase")
    return wallet_check_passphrase_positional(nullptr, parameters);
  if (method_name == "wallet_transfer")
    return wallet_transfer_positional(nullptr, parameters);
  if (method_name == "wallet_multisig_get_balance_id")
    return wallet_multisig_get_balance_id_positional(nullptr, parameters);
  if (method_name == "wallet_multisig_deposit")
    return wallet_multisig_deposit_positional(nullptr, parameters);
  if (method_name == "wallet_withdraw_from_address")
    return wallet_withdraw_from_address_positional(nullptr, parameters);
  if (method_name == "wallet_receive_genesis_multisig_blanace")
    return wallet_receive_genesis_multisig_blanace_positional(nullptr, parameters);
  if (method_name == "wallet_withdraw_from_legacy_address")
    return wallet_withdraw_from_legacy_address_positional(nullptr, parameters);
  if (method_name == "wallet_multisig_withdraw_start")
    return wallet_multisig_withdraw_start_positional(nullptr, parameters);
  if (method_name == "wallet_builder_add_signature")
    return wallet_builder_add_signature_positional(nullptr, parameters);
  if (method_name == "wallet_builder_file_add_signature")
    return wallet_builder_file_add_signature_positional(nullptr, parameters);
  if (method_name == "wallet_release_escrow")
    return wallet_release_escrow_positional(nullptr, parameters);
  if (method_name == "wallet_transfer_from_with_escrow")
    return wallet_transfer_from_with_escrow_positional(nullptr, parameters);
  if (method_name == "wallet_rescan_blockchain")
    return wallet_rescan_blockchain_positional(nullptr, parameters);
  if (method_name == "wallet_cancel_scan")
    return wallet_cancel_scan_positional(nullptr, parameters);
  if (method_name == "wallet_get_transaction")
    return wallet_get_transaction_positional(nullptr, parameters);
  if (method_name == "wallet_scan_transaction")
    return wallet_scan_transaction_positional(nullptr, parameters);
  if (method_name == "wallet_scan_transaction_experimental")
    return wallet_scan_transaction_experimental_positional(nullptr, parameters);
  if (method_name == "wallet_add_transaction_note_experimental")
    return wallet_add_transaction_note_experimental_positional(nullptr, parameters);
  if (method_name == "wallet_rebroadcast_transaction")
    return wallet_rebroadcast_transaction_positional(nullptr, parameters);
  if (method_name == "wallet_account_register")
    return wallet_account_register_positional(nullptr, parameters);
  if (method_name == "wallet_set_custom_data")
    return wallet_set_custom_data_positional(nullptr, parameters);
  if (method_name == "wallet_account_update_registration")
    return wallet_account_update_registration_positional(nullptr, parameters);
  if (method_name == "wallet_account_update_active_key")
    return wallet_account_update_active_key_positional(nullptr, parameters);
  if (method_name == "wallet_list_accounts")
    return wallet_list_accounts_positional(nullptr, parameters);
  if (method_name == "wallet_get_account")
    return wallet_get_account_positional(nullptr, parameters);
  if (method_name == "wallet_account_rename")
    return wallet_account_rename_positional(nullptr, parameters);
  if (method_name == "wallet_mia_create")
    return wallet_mia_create_positional(nullptr, parameters);
  if (method_name == "wallet_uia_create")
    return wallet_uia_create_positional(nullptr, parameters);
  if (method_name == "wallet_uia_issue")
    return wallet_uia_issue_positional(nullptr, parameters);
  if (method_name == "wallet_uia_issue_to_addresses")
    return wallet_uia_issue_to_addresses_positional(nullptr, parameters);
  if (method_name == "wallet_uia_collect_fees")
    return wallet_uia_collect_fees_positional(nullptr, parameters);
  if (method_name == "wallet_uia_update_description")
    return wallet_uia_update_description_positional(nullptr, parameters);
  if (method_name == "wallet_uia_update_supply")
    return wallet_uia_update_supply_positional(nullptr, parameters);
  if (method_name == "wallet_uia_update_fees")
    return wallet_uia_update_fees_positional(nullptr, parameters);
  if (method_name == "wallet_uia_update_active_flags")
    return wallet_uia_update_active_flags_positional(nullptr, parameters);
  if (method_name == "wallet_uia_update_authority_permissions")
    return wallet_uia_update_authority_permissions_positional(nullptr, parameters);
  if (method_name == "wallet_uia_update_whitelist")
    return wallet_uia_update_whitelist_positional(nullptr, parameters);
  if (method_name == "wallet_uia_retract_balance")
    return wallet_uia_retract_balance_positional(nullptr, parameters);
  if (method_name == "wallet_escrow_summary")
    return wallet_escrow_summary_positional(nullptr, parameters);
  if (method_name == "wallet_account_balance")
    return wallet_account_balance_positional(nullptr, parameters);
  if (method_name == "wallet_account_balance_ids")
    return wallet_account_balance_ids_positional(nullptr, parameters);
  if (method_name == "wallet_account_balance_extended")
    return wallet_account_balance_extended_positional(nullptr, parameters);
  if (method_name == "wallet_account_vesting_balances")
    return wallet_account_vesting_balances_positional(nullptr, parameters);
  if (method_name == "wallet_account_yield")
    return wallet_account_yield_positional(nullptr, parameters);
  if (method_name == "wallet_account_list_public_keys")
    return wallet_account_list_public_keys_positional(nullptr, parameters);
  if (method_name == "wallet_delegate_withdraw_pay")
    return wallet_delegate_withdraw_pay_positional(nullptr, parameters);
  if (method_name == "wallet_set_transaction_fee")
    return wallet_set_transaction_fee_positional(nullptr, parameters);
  if (method_name == "wallet_get_transaction_fee")
    return wallet_get_transaction_fee_positional(nullptr, parameters);
  if (method_name == "wallet_market_submit_bid")
    return wallet_market_submit_bid_positional(nullptr, parameters);
  if (method_name == "wallet_market_submit_ask")
    return wallet_market_submit_ask_positional(nullptr, parameters);
  if (method_name == "wallet_market_submit_short")
    return wallet_market_submit_short_positional(nullptr, parameters);
  if (method_name == "wallet_market_cover")
    return wallet_market_cover_positional(nullptr, parameters);
  if (method_name == "wallet_market_batch_update")
    return wallet_market_batch_update_positional(nullptr, parameters);
  if (method_name == "wallet_market_add_collateral")
    return wallet_market_add_collateral_positional(nullptr, parameters);
  if (method_name == "wallet_market_order_list")
    return wallet_market_order_list_positional(nullptr, parameters);
  if (method_name == "wallet_account_order_list")
    return wallet_account_order_list_positional(nullptr, parameters);
  if (method_name == "wallet_market_cancel_order")
    return wallet_market_cancel_order_positional(nullptr, parameters);
  if (method_name == "wallet_market_cancel_orders")
    return wallet_market_cancel_orders_positional(nullptr, parameters);
  if (method_name == "wallet_dump_private_key")
    return wallet_dump_private_key_positional(nullptr, parameters);
  if (method_name == "wallet_dump_account_private_key")
    return wallet_dump_account_private_key_positional(nullptr, parameters);
  if (method_name == "wallet_account_vote_summary")
    return wallet_account_vote_summary_positional(nullptr, parameters);
  if (method_name == "wallet_set_setting")
    return wallet_set_setting_positional(nullptr, parameters);
  if (method_name == "wallet_get_setting")
    return wallet_get_setting_positional(nullptr, parameters);
  if (method_name == "wallet_delegate_set_block_production")
    return wallet_delegate_set_block_production_positional(nullptr, parameters);
  if (method_name == "wallet_set_transaction_scanning")
    return wallet_set_transaction_scanning_positional(nullptr, parameters);
  if (method_name == "wallet_sign_hash")
    return wallet_sign_hash_positional(nullptr, parameters);
  if (method_name == "wallet_login_start")
    return wallet_login_start_positional(nullptr, parameters);
  if (method_name == "wallet_login_finish")
    return wallet_login_finish_positional(nullptr, parameters);
  if (method_name == "wallet_balance_set_vote_info")
    return wallet_balance_set_vote_info_positional(nullptr, parameters);
  if (method_name == "wallet_publish_slate")
    return wallet_publish_slate_positional(nullptr, parameters);
  if (method_name == "wallet_publish_version")
    return wallet_publish_version_positional(nullptr, parameters);
  if (method_name == "wallet_collect_genesis_balances")
    return wallet_collect_genesis_balances_positional(nullptr, parameters);
  if (method_name == "wallet_collect_vested_balances")
    return wallet_collect_vested_balances_positional(nullptr, parameters);
  if (method_name == "wallet_delegate_update_signing_key")
    return wallet_delegate_update_signing_key_positional(nullptr, parameters);
  if (method_name == "wallet_recover_accounts")
    return wallet_recover_accounts_positional(nullptr, parameters);
  if (method_name == "wallet_recover_titan_deposit_info")
    return wallet_recover_titan_deposit_info_positional(nullptr, parameters);
  if (method_name == "wallet_verify_titan_deposit")
    return wallet_verify_titan_deposit_positional(nullptr, parameters);
  if (method_name == "wallet_publish_price_feed")
    return wallet_publish_price_feed_positional(nullptr, parameters);
  if (method_name == "wallet_publish_feeds")
    return wallet_publish_feeds_positional(nullptr, parameters);
  if (method_name == "wallet_publish_feeds_multi_experimental")
    return wallet_publish_feeds_multi_experimental_positional(nullptr, parameters);
  if (method_name == "wallet_repair_records")
    return wallet_repair_records_positional(nullptr, parameters);
  if (method_name == "wallet_regenerate_keys")
    return wallet_regenerate_keys_positional(nullptr, parameters);
  if (method_name == "wallet_account_retract")
    return wallet_account_retract_positional(nullptr, parameters);
  if (method_name == "wallet_generate_brain_seed")
    return wallet_generate_brain_seed_positional(nullptr, parameters);
  if (method_name == "fetch_welcome_package")
    return fetch_welcome_package_positional(nullptr, parameters);
  if (method_name == "request_register_account")
    return request_register_account_positional(nullptr, parameters);
  if (method_name == "approve_register_account")
    return approve_register_account_positional(nullptr, parameters);
  if (method_name == "debug_start_simulated_time")
    return debug_start_simulated_time_positional(nullptr, parameters);
  if (method_name == "debug_advance_time")
    return debug_advance_time_positional(nullptr, parameters);
  if (method_name == "debug_trap")
    return debug_trap_positional(nullptr, parameters);
  if (method_name == "debug_wait")
    return debug_wait_positional(nullptr, parameters);
  if (method_name == "debug_wait_for_block_by_number")
    return debug_wait_for_block_by_number_positional(nullptr, parameters);
  if (method_name == "debug_wait_block_interval")
    return debug_wait_block_interval_positional(nullptr, parameters);
  if (method_name == "debug_enable_output")
    return debug_enable_output_positional(nullptr, parameters);
  if (method_name == "debug_filter_output_for_tests")
    return debug_filter_output_for_tests_positional(nullptr, parameters);
  if (method_name == "debug_update_logging_config")
    return debug_update_logging_config_positional(nullptr, parameters);
  if (method_name == "debug_get_call_statistics")
    return debug_get_call_statistics_positional(nullptr, parameters);
  if (method_name == "debug_get_client_name")
    return debug_get_client_name_positional(nullptr, parameters);
  if (method_name == "debug_deterministic_private_keys")
    return debug_deterministic_private_keys_positional(nullptr, parameters);
  if (method_name == "debug_stop_before_block")
    return debug_stop_before_block_positional(nullptr, parameters);
  if (method_name == "debug_verify_market_matching")
    return debug_verify_market_matching_positional(nullptr, parameters);
  if (method_name == "debug_list_matching_errors")
    return debug_list_matching_errors_positional(nullptr, parameters);
  FC_ASSERT(false, "shouldn't happen");
}

} } // end namespace fbtc::rpc_stubs
