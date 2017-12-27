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
#include <fbtc/rpc_stubs/common_api_rpc_client.hpp>
#include <fbtc/api/conversion_functions.hpp>

namespace fbtc { namespace rpc_stubs {

fc::variant_object common_api_rpc_client::about() const
{
  fc::variant result = get_json_connection()->async_call("about", std::vector<fc::variant>{}).wait();
  return result.as<fc::variant_object>();
}
fc::variant_object common_api_rpc_client::get_info() const
{
  fc::variant result = get_json_connection()->async_call("get_info", std::vector<fc::variant>{}).wait();
  return result.as<fc::variant_object>();
}
void common_api_rpc_client::stop()
{
  fc::variant result = get_json_connection()->async_call("stop", std::vector<fc::variant>{}).wait();
}
std::string common_api_rpc_client::help(const std::string& command_name /* = fc::json::from_string("\"\"").as<std::string>() */) const
{
  fc::variant result = get_json_connection()->async_call("help", std::vector<fc::variant>{fc::variant(command_name)}).wait();
  return result.as<std::string>();
}
fc::variant_object common_api_rpc_client::validate_address(const std::string& address) const
{
  fc::variant result = get_json_connection()->async_call("validate_address", std::vector<fc::variant>{fc::variant(address)}).wait();
  return result.as<fc::variant_object>();
}
fbtc::blockchain::address common_api_rpc_client::convert_to_native_address(const std::string& raw_address) const
{
  fc::variant result = get_json_connection()->async_call("convert_to_native_address", std::vector<fc::variant>{fc::variant(raw_address)}).wait();
  return result.as<fbtc::blockchain::address>();
}
std::string common_api_rpc_client::execute_command_line(const std::string& input) const
{
  fc::variant result = get_json_connection()->async_call("execute_command_line", std::vector<fc::variant>{fc::variant(input)}).wait();
  return result.as<std::string>();
}
void common_api_rpc_client::execute_script(const fc::path& script) const
{
  fc::variant result = get_json_connection()->async_call("execute_script", std::vector<fc::variant>{fc::variant(script)}).wait();
}
fc::variants common_api_rpc_client::batch(const std::string& method_name, const std::vector<fc::variants>& parameters_list) const
{
  fc::variant result = get_json_connection()->async_call("batch", std::vector<fc::variant>{fc::variant(method_name), fc::variant(parameters_list)}).wait();
  return result.as<fc::variants>();
}
fc::variants common_api_rpc_client::batch_authenticated(const std::string& method_name, const std::vector<fc::variants>& parameters_list) const
{
  fc::variant result = get_json_connection()->async_call("batch_authenticated", std::vector<fc::variant>{fc::variant(method_name), fc::variant(parameters_list)}).wait();
  return result.as<fc::variants>();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::builder_finalize_and_sign(const fbtc::wallet::transaction_builder& builder) const
{
  fc::variant result = get_json_connection()->async_call("builder_finalize_and_sign", std::vector<fc::variant>{fc::variant(builder)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
std::map<std::string, fbtc::api::method_data> common_api_rpc_client::meta_help() const
{
  fc::variant result = get_json_connection()->async_call("meta_help", std::vector<fc::variant>{}).wait();
  return result.as<std::map<std::string, fbtc::api::method_data>>();
}
void common_api_rpc_client::rpc_set_username(const std::string& username /* = fc::json::from_string("\"\"").as<std::string>() */)
{
  fc::variant result = get_json_connection()->async_call("rpc_set_username", std::vector<fc::variant>{fc::variant(username)}).wait();
}
void common_api_rpc_client::rpc_set_password(const std::string& password /* = fc::json::from_string("\"\"").as<std::string>() */)
{
  fc::variant result = get_json_connection()->async_call("rpc_set_password", std::vector<fc::variant>{fc::variant(password)}).wait();
}
void common_api_rpc_client::rpc_start_server(uint32_t port /* = fc::json::from_string("\"65065\"").as<uint32_t>() */)
{
  fc::variant result = get_json_connection()->async_call("rpc_start_server", std::vector<fc::variant>{fc::variant(port)}).wait();
}
void common_api_rpc_client::http_start_server(uint32_t port /* = fc::json::from_string("\"65066\"").as<uint32_t>() */)
{
  fc::variant result = get_json_connection()->async_call("http_start_server", std::vector<fc::variant>{fc::variant(port)}).wait();
}
void common_api_rpc_client::ntp_update_time()
{
  fc::variant result = get_json_connection()->async_call("ntp_update_time", std::vector<fc::variant>{}).wait();
}
fc::variant common_api_rpc_client::disk_usage() const
{
  fc::variant result = get_json_connection()->async_call("disk_usage", std::vector<fc::variant>{}).wait();
  return result.as<fc::variant>();
}
void common_api_rpc_client::network_add_node(const std::string& node, const std::string& command /* = fc::json::from_string("\"add\"").as<std::string>() */)
{
  fc::variant result = get_json_connection()->async_call("network_add_node", std::vector<fc::variant>{fc::variant(node), fc::variant(command)}).wait();
}
uint32_t common_api_rpc_client::network_get_connection_count() const
{
  fc::variant result = get_json_connection()->async_call("network_get_connection_count", std::vector<fc::variant>{}).wait();
  return result.as<uint32_t>();
}
std::vector<fc::variant_object> common_api_rpc_client::network_get_peer_info(bool not_firewalled /* = fc::json::from_string("false").as<bool>() */) const
{
  fc::variant result = get_json_connection()->async_call("network_get_peer_info", std::vector<fc::variant>{fc::variant(not_firewalled)}).wait();
  return result.as<std::vector<fc::variant_object>>();
}
fbtc::blockchain::transaction_id_type common_api_rpc_client::network_broadcast_transaction(const fbtc::blockchain::signed_transaction& transaction_to_broadcast)
{
  fc::variant result = get_json_connection()->async_call("network_broadcast_transaction", std::vector<fc::variant>{fc::variant(transaction_to_broadcast)}).wait();
  return result.as<fbtc::blockchain::transaction_id_type>();
}
void common_api_rpc_client::network_set_advanced_node_parameters(const fc::variant_object& params)
{
  fc::variant result = get_json_connection()->async_call("network_set_advanced_node_parameters", std::vector<fc::variant>{fc::variant(params)}).wait();
}
fc::variant_object common_api_rpc_client::network_get_advanced_node_parameters() const
{
  fc::variant result = get_json_connection()->async_call("network_get_advanced_node_parameters", std::vector<fc::variant>{}).wait();
  return result.as<fc::variant_object>();
}
fbtc::net::message_propagation_data common_api_rpc_client::network_get_transaction_propagation_data(const fbtc::blockchain::transaction_id_type& transaction_id)
{
  fc::variant result = get_json_connection()->async_call("network_get_transaction_propagation_data", std::vector<fc::variant>{fc::variant(transaction_id)}).wait();
  return result.as<fbtc::net::message_propagation_data>();
}
fbtc::net::message_propagation_data common_api_rpc_client::network_get_block_propagation_data(const fbtc::blockchain::block_id_type& block_hash)
{
  fc::variant result = get_json_connection()->async_call("network_get_block_propagation_data", std::vector<fc::variant>{fc::variant(block_hash)}).wait();
  return result.as<fbtc::net::message_propagation_data>();
}
void common_api_rpc_client::network_set_allowed_peers(const std::vector<fbtc::net::node_id_t>& allowed_peers)
{
  fc::variant result = get_json_connection()->async_call("network_set_allowed_peers", std::vector<fc::variant>{fc::variant(allowed_peers)}).wait();
}
fc::variant_object common_api_rpc_client::network_get_info() const
{
  fc::variant result = get_json_connection()->async_call("network_get_info", std::vector<fc::variant>{}).wait();
  return result.as<fc::variant_object>();
}
std::vector<fbtc::net::potential_peer_record> common_api_rpc_client::network_list_potential_peers() const
{
  fc::variant result = get_json_connection()->async_call("network_list_potential_peers", std::vector<fc::variant>{}).wait();
  return result.as<std::vector<fbtc::net::potential_peer_record>>();
}
fc::variant_object common_api_rpc_client::network_get_upnp_info() const
{
  fc::variant result = get_json_connection()->async_call("network_get_upnp_info", std::vector<fc::variant>{}).wait();
  return result.as<fc::variant_object>();
}
fc::variant_object common_api_rpc_client::network_get_usage_stats() const
{
  fc::variant result = get_json_connection()->async_call("network_get_usage_stats", std::vector<fc::variant>{}).wait();
  return result.as<fc::variant_object>();
}
fc::variant common_api_rpc_client::delegate_get_config() const
{
  fc::variant result = get_json_connection()->async_call("delegate_get_config", std::vector<fc::variant>{}).wait();
  return result.as<fc::variant>();
}
void common_api_rpc_client::delegate_set_network_min_connection_count(uint32_t count)
{
  fc::variant result = get_json_connection()->async_call("delegate_set_network_min_connection_count", std::vector<fc::variant>{fc::variant(count)}).wait();
}
void common_api_rpc_client::delegate_set_block_max_transaction_count(uint32_t count)
{
  fc::variant result = get_json_connection()->async_call("delegate_set_block_max_transaction_count", std::vector<fc::variant>{fc::variant(count)}).wait();
}
void common_api_rpc_client::delegate_set_block_max_size(uint32_t size)
{
  fc::variant result = get_json_connection()->async_call("delegate_set_block_max_size", std::vector<fc::variant>{fc::variant(size)}).wait();
}
void common_api_rpc_client::delegate_set_block_max_production_time(uint64_t time)
{
  fc::variant result = get_json_connection()->async_call("delegate_set_block_max_production_time", std::vector<fc::variant>{fc::variant(time)}).wait();
}
void common_api_rpc_client::delegate_set_transaction_max_size(uint32_t size)
{
  fc::variant result = get_json_connection()->async_call("delegate_set_transaction_max_size", std::vector<fc::variant>{fc::variant(size)}).wait();
}
void common_api_rpc_client::delegate_set_transaction_canonical_signatures_required(bool required)
{
  fc::variant result = get_json_connection()->async_call("delegate_set_transaction_canonical_signatures_required", std::vector<fc::variant>{fc::variant(required)}).wait();
}
void common_api_rpc_client::delegate_set_transaction_min_fee(uint64_t fee)
{
  fc::variant result = get_json_connection()->async_call("delegate_set_transaction_min_fee", std::vector<fc::variant>{fc::variant(fee)}).wait();
}
void common_api_rpc_client::delegate_blacklist_add_transaction(const fbtc::blockchain::transaction_id_type& id)
{
  fc::variant result = get_json_connection()->async_call("delegate_blacklist_add_transaction", std::vector<fc::variant>{fc::variant(id)}).wait();
}
void common_api_rpc_client::delegate_blacklist_remove_transaction(const fbtc::blockchain::transaction_id_type& id)
{
  fc::variant result = get_json_connection()->async_call("delegate_blacklist_remove_transaction", std::vector<fc::variant>{fc::variant(id)}).wait();
}
void common_api_rpc_client::delegate_blacklist_add_operation(const fbtc::blockchain::operation_type_enum& id)
{
  fc::variant result = get_json_connection()->async_call("delegate_blacklist_add_operation", std::vector<fc::variant>{fc::variant(id)}).wait();
}
void common_api_rpc_client::delegate_blacklist_remove_operation(const fbtc::blockchain::operation_type_enum& id)
{
  fc::variant result = get_json_connection()->async_call("delegate_blacklist_remove_operation", std::vector<fc::variant>{fc::variant(id)}).wait();
}
fc::variant_object common_api_rpc_client::blockchain_get_info() const
{
  fc::variant result = get_json_connection()->async_call("blockchain_get_info", std::vector<fc::variant>{}).wait();
  return result.as<fc::variant_object>();
}
void common_api_rpc_client::blockchain_generate_snapshot(const std::string& filename) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_generate_snapshot", std::vector<fc::variant>{fc::variant(filename)}).wait();
}
void common_api_rpc_client::blockchain_graphene_snapshot(const std::string& filename, const std::string& whitelist_filename /* = fc::json::from_string("\"\"").as<std::string>() */) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_graphene_snapshot", std::vector<fc::variant>{fc::variant(filename), fc::variant(whitelist_filename)}).wait();
}
void common_api_rpc_client::blockchain_generate_issuance_map(const std::string& symbol, const std::string& filename) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_generate_issuance_map", std::vector<fc::variant>{fc::variant(symbol), fc::variant(filename)}).wait();
}
fbtc::blockchain::asset common_api_rpc_client::blockchain_calculate_supply(const std::string& asset) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_calculate_supply", std::vector<fc::variant>{fc::variant(asset)}).wait();
  return result.as<fbtc::blockchain::asset>();
}
fbtc::blockchain::asset common_api_rpc_client::blockchain_calculate_debt(const std::string& asset, bool include_interest /* = fc::json::from_string("\"false\"").as<bool>() */) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_calculate_debt", std::vector<fc::variant>{fc::variant(asset), fc::variant(include_interest)}).wait();
  return result.as<fbtc::blockchain::asset>();
}
fbtc::blockchain::asset common_api_rpc_client::blockchain_calculate_max_supply(uint8_t average_delegate_pay_rate /* = fc::json::from_string("100").as<uint8_t>() */) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_calculate_max_supply", std::vector<fc::variant>{fc::variant(average_delegate_pay_rate)}).wait();
  return result.as<fbtc::blockchain::asset>();
}
uint32_t common_api_rpc_client::blockchain_get_block_count() const
{
  fc::variant result = get_json_connection()->async_call("blockchain_get_block_count", std::vector<fc::variant>{}).wait();
  return result.as<uint32_t>();
}
std::vector<fbtc::blockchain::account_record> common_api_rpc_client::blockchain_list_accounts(const std::string& first_account_name /* = fc::json::from_string("\"\"").as<std::string>() */, uint32_t limit /* = fc::json::from_string("20").as<uint32_t>() */) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_list_accounts", std::vector<fc::variant>{fc::variant(first_account_name), fc::variant(limit)}).wait();
  return result.as<std::vector<fbtc::blockchain::account_record>>();
}
std::vector<fbtc::blockchain::account_record> common_api_rpc_client::blockchain_list_recently_updated_accounts() const
{
  fc::variant result = get_json_connection()->async_call("blockchain_list_recently_updated_accounts", std::vector<fc::variant>{}).wait();
  return result.as<std::vector<fbtc::blockchain::account_record>>();
}
std::vector<fbtc::blockchain::account_record> common_api_rpc_client::blockchain_list_recently_registered_accounts() const
{
  fc::variant result = get_json_connection()->async_call("blockchain_list_recently_registered_accounts", std::vector<fc::variant>{}).wait();
  return result.as<std::vector<fbtc::blockchain::account_record>>();
}
std::vector<fbtc::blockchain::asset_record> common_api_rpc_client::blockchain_list_assets(const std::string& first_symbol /* = fc::json::from_string("\"\"").as<std::string>() */, uint32_t limit /* = fc::json::from_string("20").as<uint32_t>() */) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_list_assets", std::vector<fc::variant>{fc::variant(first_symbol), fc::variant(limit)}).wait();
  return result.as<std::vector<fbtc::blockchain::asset_record>>();
}
std::map<std::string, std::string> common_api_rpc_client::blockchain_list_feed_prices() const
{
  fc::variant result = get_json_connection()->async_call("blockchain_list_feed_prices", std::vector<fc::variant>{}).wait();
  return result.as<std::map<std::string, std::string>>();
}
std::vector<fbtc::blockchain::burn_record> common_api_rpc_client::blockchain_get_account_wall(const std::string& account_name /* = fc::json::from_string("\"\"").as<std::string>() */) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_get_account_wall", std::vector<fc::variant>{fc::variant(account_name)}).wait();
  return result.as<std::vector<fbtc::blockchain::burn_record>>();
}
std::vector<fbtc::blockchain::signed_transaction> common_api_rpc_client::blockchain_list_pending_transactions() const
{
  fc::variant result = get_json_connection()->async_call("blockchain_list_pending_transactions", std::vector<fc::variant>{}).wait();
  return result.as<std::vector<fbtc::blockchain::signed_transaction>>();
}
int32_t common_api_rpc_client::blockchain_get_pending_transactions_count() const
{
  fc::variant result = get_json_connection()->async_call("blockchain_get_pending_transactions_count", std::vector<fc::variant>{}).wait();
  return result.as<int32_t>();
}
std::pair<fbtc::blockchain::transaction_id_type, fbtc::blockchain::transaction_record> common_api_rpc_client::blockchain_get_transaction(const std::string& transaction_id_prefix, bool exact /* = fc::json::from_string("false").as<bool>() */) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_get_transaction", std::vector<fc::variant>{fc::variant(transaction_id_prefix), fc::variant(exact)}).wait();
  return result.as<std::pair<fbtc::blockchain::transaction_id_type, fbtc::blockchain::transaction_record>>();
}
fc::optional<fbtc::blockchain::block_record> common_api_rpc_client::blockchain_get_block(const std::string& block) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_get_block", std::vector<fc::variant>{fc::variant(block)}).wait();
  return result.as<fc::optional<fbtc::blockchain::block_record>>();
}
std::map<fbtc::blockchain::transaction_id_type, fbtc::blockchain::transaction_record> common_api_rpc_client::blockchain_get_block_transactions(const std::string& block) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_get_block_transactions", std::vector<fc::variant>{fc::variant(block)}).wait();
  return result.as<std::map<fbtc::blockchain::transaction_id_type, fbtc::blockchain::transaction_record>>();
}
fc::optional<fbtc::blockchain::account_record> common_api_rpc_client::blockchain_get_account(const std::string& account) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_get_account", std::vector<fc::variant>{fc::variant(account)}).wait();
  return result.as<fc::optional<fbtc::blockchain::account_record>>();
}
std::map<fbtc::blockchain::account_id_type, std::string> common_api_rpc_client::blockchain_get_slate(const std::string& slate) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_get_slate", std::vector<fc::variant>{fc::variant(slate)}).wait();
  return result.as<std::map<fbtc::blockchain::account_id_type, std::string>>();
}
fbtc::blockchain::balance_record common_api_rpc_client::blockchain_get_balance(const fbtc::blockchain::address& balance_id) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_get_balance", std::vector<fc::variant>{fc::variant(balance_id)}).wait();
  return result.as<fbtc::blockchain::balance_record>();
}
std::unordered_map<fbtc::blockchain::balance_id_type, fbtc::blockchain::balance_record> common_api_rpc_client::blockchain_list_balances(const std::string& asset /* = fc::json::from_string("\"0\"").as<std::string>() */, uint32_t limit /* = fc::json::from_string("20").as<uint32_t>() */) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_list_balances", std::vector<fc::variant>{fc::variant(asset), fc::variant(limit)}).wait();
  return result.as<std::unordered_map<fbtc::blockchain::balance_id_type, fbtc::blockchain::balance_record>>();
}
std::unordered_map<fbtc::blockchain::balance_id_type, fbtc::blockchain::balance_record> common_api_rpc_client::blockchain_list_address_balances(const std::string& addr, const fc::time_point& chanced_since /* = fc::json::from_string("\"1970-1-1T00:00:01\"").as<fc::time_point>() */) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_list_address_balances", std::vector<fc::variant>{fc::variant(addr), fc::variant(chanced_since)}).wait();
  return result.as<std::unordered_map<fbtc::blockchain::balance_id_type, fbtc::blockchain::balance_record>>();
}
fc::variant_object common_api_rpc_client::blockchain_list_address_transactions(const std::string& addr, uint32_t filter_before /* = fc::json::from_string("\"0\"").as<uint32_t>() */) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_list_address_transactions", std::vector<fc::variant>{fc::variant(addr), fc::variant(filter_before)}).wait();
  return result.as<fc::variant_object>();
}
std::map<fbtc::blockchain::asset_id_type, fbtc::blockchain::share_type> common_api_rpc_client::blockchain_get_account_public_balance(const std::string& account_name) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_get_account_public_balance", std::vector<fc::variant>{fc::variant(account_name)}).wait();
  return result.as<std::map<fbtc::blockchain::asset_id_type, fbtc::blockchain::share_type>>();
}
std::string common_api_rpc_client::blockchain_median_feed_price(const std::string& symbol) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_median_feed_price", std::vector<fc::variant>{fc::variant(symbol)}).wait();
  return result.as<std::string>();
}
std::unordered_map<fbtc::blockchain::balance_id_type, fbtc::blockchain::balance_record> common_api_rpc_client::blockchain_list_key_balances(const fbtc::blockchain::public_key_type& key) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_list_key_balances", std::vector<fc::variant>{fc::variant(key)}).wait();
  return result.as<std::unordered_map<fbtc::blockchain::balance_id_type, fbtc::blockchain::balance_record>>();
}
fc::optional<fbtc::blockchain::asset_record> common_api_rpc_client::blockchain_get_asset(const std::string& asset) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_get_asset", std::vector<fc::variant>{fc::variant(asset)}).wait();
  return result.as<fc::optional<fbtc::blockchain::asset_record>>();
}
std::vector<fbtc::blockchain::feed_entry> common_api_rpc_client::blockchain_get_feeds_for_asset(const std::string& asset) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_get_feeds_for_asset", std::vector<fc::variant>{fc::variant(asset)}).wait();
  return result.as<std::vector<fbtc::blockchain::feed_entry>>();
}
std::vector<fbtc::blockchain::feed_entry> common_api_rpc_client::blockchain_get_feeds_from_delegate(const std::string& delegate_name) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_get_feeds_from_delegate", std::vector<fc::variant>{fc::variant(delegate_name)}).wait();
  return result.as<std::vector<fbtc::blockchain::feed_entry>>();
}
std::vector<fbtc::blockchain::market_order> common_api_rpc_client::blockchain_market_list_bids(const std::string& quote_symbol, const std::string& base_symbol, uint32_t limit /* = fc::json::from_string("\"-1\"").as<uint32_t>() */) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_market_list_bids", std::vector<fc::variant>{fc::variant(quote_symbol), fc::variant(base_symbol), fc::variant(limit)}).wait();
  return result.as<std::vector<fbtc::blockchain::market_order>>();
}
std::vector<fbtc::blockchain::market_order> common_api_rpc_client::blockchain_market_list_asks(const std::string& quote_symbol, const std::string& base_symbol, uint32_t limit /* = fc::json::from_string("\"-1\"").as<uint32_t>() */) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_market_list_asks", std::vector<fc::variant>{fc::variant(quote_symbol), fc::variant(base_symbol), fc::variant(limit)}).wait();
  return result.as<std::vector<fbtc::blockchain::market_order>>();
}
std::vector<fbtc::blockchain::market_order> common_api_rpc_client::blockchain_market_list_shorts(const std::string& quote_symbol, uint32_t limit /* = fc::json::from_string("\"-1\"").as<uint32_t>() */) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_market_list_shorts", std::vector<fc::variant>{fc::variant(quote_symbol), fc::variant(limit)}).wait();
  return result.as<std::vector<fbtc::blockchain::market_order>>();
}
std::vector<fbtc::blockchain::market_order> common_api_rpc_client::blockchain_market_list_covers(const std::string& quote_symbol, const std::string& base_symbol /* = fc::json::from_string("\"XTS\"").as<std::string>() */, uint32_t limit /* = fc::json::from_string("\"-1\"").as<uint32_t>() */) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_market_list_covers", std::vector<fc::variant>{fc::variant(quote_symbol), fc::variant(base_symbol), fc::variant(limit)}).wait();
  return result.as<std::vector<fbtc::blockchain::market_order>>();
}
fbtc::blockchain::share_type common_api_rpc_client::blockchain_market_get_asset_collateral(const std::string& symbol) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_market_get_asset_collateral", std::vector<fc::variant>{fc::variant(symbol)}).wait();
  return result.as<fbtc::blockchain::share_type>();
}
std::pair<std::vector<fbtc::blockchain::market_order>,std::vector<fbtc::blockchain::market_order>> common_api_rpc_client::blockchain_market_order_book(const std::string& quote_symbol, const std::string& base_symbol, uint32_t limit /* = fc::json::from_string("\"10\"").as<uint32_t>() */) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_market_order_book", std::vector<fc::variant>{fc::variant(quote_symbol), fc::variant(base_symbol), fc::variant(limit)}).wait();
  return result.as<std::pair<std::vector<fbtc::blockchain::market_order>,std::vector<fbtc::blockchain::market_order>>>();
}
fbtc::blockchain::market_order common_api_rpc_client::blockchain_get_market_order(const std::string& order_id) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_get_market_order", std::vector<fc::variant>{fc::variant(order_id)}).wait();
  return result.as<fbtc::blockchain::market_order>();
}
std::map<fbtc::blockchain::order_id_type, fbtc::blockchain::market_order> common_api_rpc_client::blockchain_list_address_orders(const std::string& base_symbol, const std::string& quote_symbol, const std::string& account_address, uint32_t limit /* = fc::json::from_string("\"10\"").as<uint32_t>() */) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_list_address_orders", std::vector<fc::variant>{fc::variant(base_symbol), fc::variant(quote_symbol), fc::variant(account_address), fc::variant(limit)}).wait();
  return result.as<std::map<fbtc::blockchain::order_id_type, fbtc::blockchain::market_order>>();
}
std::vector<fbtc::blockchain::order_history_record> common_api_rpc_client::blockchain_market_order_history(const std::string& quote_symbol, const std::string& base_symbol, uint32_t skip_count /* = fc::json::from_string("\"0\"").as<uint32_t>() */, uint32_t limit /* = fc::json::from_string("\"20\"").as<uint32_t>() */, const std::string& owner /* = fc::json::from_string("\"\"").as<std::string>() */) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_market_order_history", std::vector<fc::variant>{fc::variant(quote_symbol), fc::variant(base_symbol), fc::variant(skip_count), fc::variant(limit), fc::variant(owner)}).wait();
  return result.as<std::vector<fbtc::blockchain::order_history_record>>();
}
fbtc::blockchain::market_history_points common_api_rpc_client::blockchain_market_price_history(const std::string& quote_symbol, const std::string& base_symbol, const fc::time_point& start_time, const fc::microseconds& duration, const fbtc::blockchain::market_history_key::time_granularity_enum& granularity /* = fc::json::from_string("\"each_block\"").as<fbtc::blockchain::market_history_key::time_granularity_enum>() */) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_market_price_history", std::vector<fc::variant>{fc::variant(quote_symbol), fc::variant(base_symbol), fc::variant(start_time), fbtc::api::time_interval_in_seconds_to_variant(duration), fc::variant(granularity)}).wait();
  return result.as<fbtc::blockchain::market_history_points>();
}
std::vector<fbtc::blockchain::account_record> common_api_rpc_client::blockchain_list_active_delegates(uint32_t first /* = fc::json::from_string("0").as<uint32_t>() */, uint32_t count /* = fc::json::from_string("20").as<uint32_t>() */) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_list_active_delegates", std::vector<fc::variant>{fc::variant(first), fc::variant(count)}).wait();
  return result.as<std::vector<fbtc::blockchain::account_record>>();
}
std::vector<fbtc::blockchain::account_record> common_api_rpc_client::blockchain_list_delegates(uint32_t first /* = fc::json::from_string("0").as<uint32_t>() */, uint32_t count /* = fc::json::from_string("20").as<uint32_t>() */) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_list_delegates", std::vector<fc::variant>{fc::variant(first), fc::variant(count)}).wait();
  return result.as<std::vector<fbtc::blockchain::account_record>>();
}
std::vector<fbtc::blockchain::block_record> common_api_rpc_client::blockchain_list_blocks(uint32_t max_block_num /* = fc::json::from_string("-1").as<uint32_t>() */, uint32_t limit /* = fc::json::from_string("20").as<uint32_t>() */)
{
  fc::variant result = get_json_connection()->async_call("blockchain_list_blocks", std::vector<fc::variant>{fc::variant(max_block_num), fc::variant(limit)}).wait();
  return result.as<std::vector<fbtc::blockchain::block_record>>();
}
std::vector<std::string> common_api_rpc_client::blockchain_list_missing_block_delegates(uint32_t block_number)
{
  fc::variant result = get_json_connection()->async_call("blockchain_list_missing_block_delegates", std::vector<fc::variant>{fc::variant(block_number)}).wait();
  return result.as<std::vector<std::string>>();
}
std::string common_api_rpc_client::blockchain_export_fork_graph(uint32_t start_block /* = fc::json::from_string("1").as<uint32_t>() */, uint32_t end_block /* = fc::json::from_string("-1").as<uint32_t>() */, const std::string& filename /* = fc::json::from_string("\"\"").as<std::string>() */) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_export_fork_graph", std::vector<fc::variant>{fc::variant(start_block), fc::variant(end_block), fc::variant(filename)}).wait();
  return result.as<std::string>();
}
std::map<uint32_t, std::vector<fbtc::blockchain::fork_record>> common_api_rpc_client::blockchain_list_forks() const
{
  fc::variant result = get_json_connection()->async_call("blockchain_list_forks", std::vector<fc::variant>{}).wait();
  return result.as<std::map<uint32_t, std::vector<fbtc::blockchain::fork_record>>>();
}
std::vector<fbtc::blockchain::slot_record> common_api_rpc_client::blockchain_get_delegate_slot_records(const std::string& delegate_name, uint32_t limit /* = fc::json::from_string("\"10\"").as<uint32_t>() */) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_get_delegate_slot_records", std::vector<fc::variant>{fc::variant(delegate_name), fc::variant(limit)}).wait();
  return result.as<std::vector<fbtc::blockchain::slot_record>>();
}
std::string common_api_rpc_client::blockchain_get_block_signee(const std::string& block) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_get_block_signee", std::vector<fc::variant>{fc::variant(block)}).wait();
  return result.as<std::string>();
}
std::vector<fbtc::blockchain::string_status_record> common_api_rpc_client::blockchain_list_markets() const
{
  fc::variant result = get_json_connection()->async_call("blockchain_list_markets", std::vector<fc::variant>{}).wait();
  return result.as<std::vector<fbtc::blockchain::string_status_record>>();
}
std::vector<fbtc::blockchain::market_transaction> common_api_rpc_client::blockchain_list_market_transactions(uint32_t block_number) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_list_market_transactions", std::vector<fc::variant>{fc::variant(block_number)}).wait();
  return result.as<std::vector<fbtc::blockchain::market_transaction>>();
}
fbtc::blockchain::string_status_record common_api_rpc_client::blockchain_market_status(const std::string& quote_symbol, const std::string& base_symbol) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_market_status", std::vector<fc::variant>{fc::variant(quote_symbol), fc::variant(base_symbol)}).wait();
  return result.as<fbtc::blockchain::string_status_record>();
}
fbtc::blockchain::asset common_api_rpc_client::blockchain_unclaimed_genesis() const
{
  fc::variant result = get_json_connection()->async_call("blockchain_unclaimed_genesis", std::vector<fc::variant>{}).wait();
  return result.as<fbtc::blockchain::asset>();
}
bool common_api_rpc_client::blockchain_verify_signature(const std::string& signer, const fc::sha256& hash, const fc::ecc::compact_signature& signature) const
{
  fc::variant result = get_json_connection()->async_call("blockchain_verify_signature", std::vector<fc::variant>{fc::variant(signer), fc::variant(hash), fc::variant(signature)}).wait();
  return result.as<bool>();
}
void common_api_rpc_client::blockchain_broadcast_transaction(const fbtc::blockchain::signed_transaction& trx)
{
  fc::variant result = get_json_connection()->async_call("blockchain_broadcast_transaction", std::vector<fc::variant>{fc::variant(trx)}).wait();
}
fc::variant_object common_api_rpc_client::wallet_get_info()
{
  fc::variant result = get_json_connection()->async_call("wallet_get_info", std::vector<fc::variant>{}).wait();
  return result.as<fc::variant_object>();
}
void common_api_rpc_client::wallet_open(const std::string& wallet_name)
{
  fc::variant result = get_json_connection()->async_call("wallet_open", std::vector<fc::variant>{fc::variant(wallet_name)}).wait();
}
std::string common_api_rpc_client::wallet_get_account_public_address(const std::string& account_name) const
{
  fc::variant result = get_json_connection()->async_call("wallet_get_account_public_address", std::vector<fc::variant>{fc::variant(account_name)}).wait();
  return result.as<std::string>();
}
std::vector<fbtc::wallet::account_address_data> common_api_rpc_client::wallet_list_my_addresses() const
{
  fc::variant result = get_json_connection()->async_call("wallet_list_my_addresses", std::vector<fc::variant>{}).wait();
  return result.as<std::vector<fbtc::wallet::account_address_data>>();
}
void common_api_rpc_client::wallet_create(const std::string& wallet_name, const std::string& new_passphrase, const std::string& brain_key /* = fc::json::from_string("\"\"").as<std::string>() */, const std::string& new_passphrase_verify /* = fc::json::from_string("\"\"").as<std::string>() */)
{
  fc::variant result = get_json_connection()->async_call("wallet_create", std::vector<fc::variant>{fc::variant(wallet_name), fc::variant(new_passphrase), fc::variant(brain_key), fc::variant(new_passphrase_verify)}).wait();
}
std::string common_api_rpc_client::wallet_import_private_key(const std::string& wif_key, const std::string& account_name /* = fc::json::from_string("null").as<std::string>() */, bool create_new_account /* = fc::json::from_string("false").as<bool>() */, bool rescan /* = fc::json::from_string("false").as<bool>() */)
{
  fc::variant result = get_json_connection()->async_call("wallet_import_private_key", std::vector<fc::variant>{fc::variant(wif_key), fc::variant(account_name), fc::variant(create_new_account), fc::variant(rescan)}).wait();
  return result.as<std::string>();
}
uint32_t common_api_rpc_client::wallet_import_bitcoin(const fc::path& wallet_filename, const std::string& passphrase, const std::string& account_name)
{
  fc::variant result = get_json_connection()->async_call("wallet_import_bitcoin", std::vector<fc::variant>{fc::variant(wallet_filename), fc::variant(passphrase), fc::variant(account_name)}).wait();
  return result.as<uint32_t>();
}
uint32_t common_api_rpc_client::wallet_import_electrum(const fc::path& wallet_filename, const std::string& passphrase, const std::string& account_name)
{
  fc::variant result = get_json_connection()->async_call("wallet_import_electrum", std::vector<fc::variant>{fc::variant(wallet_filename), fc::variant(passphrase), fc::variant(account_name)}).wait();
  return result.as<uint32_t>();
}
void common_api_rpc_client::wallet_import_keyhotee(const std::string& firstname, const std::string& middlename, const std::string& lastname, const std::string& brainkey, const std::string& keyhoteeid)
{
  fc::variant result = get_json_connection()->async_call("wallet_import_keyhotee", std::vector<fc::variant>{fc::variant(firstname), fc::variant(middlename), fc::variant(lastname), fc::variant(brainkey), fc::variant(keyhoteeid)}).wait();
}
uint32_t common_api_rpc_client::wallet_import_keys_from_json(const fc::path& json_filename, const std::string& imported_wallet_passphrase, const std::string& account)
{
  fc::variant result = get_json_connection()->async_call("wallet_import_keys_from_json", std::vector<fc::variant>{fc::variant(json_filename), fc::variant(imported_wallet_passphrase), fc::variant(account)}).wait();
  return result.as<uint32_t>();
}
void common_api_rpc_client::wallet_close()
{
  fc::variant result = get_json_connection()->async_call("wallet_close", std::vector<fc::variant>{}).wait();
}
void common_api_rpc_client::wallet_backup_create(const fc::path& json_filename) const
{
  fc::variant result = get_json_connection()->async_call("wallet_backup_create", std::vector<fc::variant>{fc::variant(json_filename)}).wait();
}
void common_api_rpc_client::wallet_backup_restore(const fc::path& json_filename, const std::string& wallet_name, const std::string& imported_wallet_passphrase)
{
  fc::variant result = get_json_connection()->async_call("wallet_backup_restore", std::vector<fc::variant>{fc::variant(json_filename), fc::variant(wallet_name), fc::variant(imported_wallet_passphrase)}).wait();
}
void common_api_rpc_client::wallet_export_keys(const fc::path& json_filename) const
{
  fc::variant result = get_json_connection()->async_call("wallet_export_keys", std::vector<fc::variant>{fc::variant(json_filename)}).wait();
}
bool common_api_rpc_client::wallet_set_automatic_backups(bool enabled)
{
  fc::variant result = get_json_connection()->async_call("wallet_set_automatic_backups", std::vector<fc::variant>{fc::variant(enabled)}).wait();
  return result.as<bool>();
}
uint32_t common_api_rpc_client::wallet_set_transaction_expiration_time(uint32_t seconds)
{
  fc::variant result = get_json_connection()->async_call("wallet_set_transaction_expiration_time", std::vector<fc::variant>{fc::variant(seconds)}).wait();
  return result.as<uint32_t>();
}
std::vector<fbtc::wallet::pretty_transaction> common_api_rpc_client::wallet_account_transaction_history(const std::string& account_name /* = fc::json::from_string("\"\"").as<std::string>() */, const std::string& asset_symbol /* = fc::json::from_string("\"\"").as<std::string>() */, int32_t limit /* = fc::json::from_string("0").as<int32_t>() */, uint32_t start_block_num /* = fc::json::from_string("0").as<uint32_t>() */, uint32_t end_block_num /* = fc::json::from_string("-1").as<uint32_t>() */) const
{
  fc::variant result = get_json_connection()->async_call("wallet_account_transaction_history", std::vector<fc::variant>{fc::variant(account_name), fc::variant(asset_symbol), fc::variant(limit), fc::variant(start_block_num), fc::variant(end_block_num)}).wait();
  return result.as<std::vector<fbtc::wallet::pretty_transaction>>();
}
fbtc::wallet::account_balance_summary_type common_api_rpc_client::wallet_account_historic_balance(const fc::time_point& time, const std::string& account_name /* = fc::json::from_string("\"\"").as<std::string>() */) const
{
  fc::variant result = get_json_connection()->async_call("wallet_account_historic_balance", std::vector<fc::variant>{fc::variant(time), fc::variant(account_name)}).wait();
  return result.as<fbtc::wallet::account_balance_summary_type>();
}
std::set<fbtc::wallet::pretty_transaction_experimental> common_api_rpc_client::wallet_transaction_history_experimental(const std::string& account_name /* = fc::json::from_string("\"\"").as<std::string>() */) const
{
  fc::variant result = get_json_connection()->async_call("wallet_transaction_history_experimental", std::vector<fc::variant>{fc::variant(account_name)}).wait();
  return result.as<std::set<fbtc::wallet::pretty_transaction_experimental>>();
}
void common_api_rpc_client::wallet_remove_transaction(const std::string& transaction_id)
{
  fc::variant result = get_json_connection()->async_call("wallet_remove_transaction", std::vector<fc::variant>{fc::variant(transaction_id)}).wait();
}
std::map<fbtc::blockchain::transaction_id_type, fc::exception> common_api_rpc_client::wallet_get_pending_transaction_errors(const std::string& filename /* = fc::json::from_string("\"\"").as<std::string>() */) const
{
  fc::variant result = get_json_connection()->async_call("wallet_get_pending_transaction_errors", std::vector<fc::variant>{fc::variant(filename)}).wait();
  return result.as<std::map<fbtc::blockchain::transaction_id_type, fc::exception>>();
}
void common_api_rpc_client::wallet_lock()
{
  fc::variant result = get_json_connection()->async_call("wallet_lock", std::vector<fc::variant>{}).wait();
}
void common_api_rpc_client::wallet_unlock(uint32_t timeout, const std::string& passphrase)
{
  fc::variant result = get_json_connection()->async_call("wallet_unlock", std::vector<fc::variant>{fc::variant(timeout), fc::variant(passphrase)}).wait();
}
void common_api_rpc_client::wallet_change_passphrase(const std::string& new_passphrase, const std::string& new_passphrase_verify /* = fc::json::from_string("\"\"").as<std::string>() */)
{
  fc::variant result = get_json_connection()->async_call("wallet_change_passphrase", std::vector<fc::variant>{fc::variant(new_passphrase), fc::variant(new_passphrase_verify)}).wait();
}
std::vector<std::string> common_api_rpc_client::wallet_list() const
{
  fc::variant result = get_json_connection()->async_call("wallet_list", std::vector<fc::variant>{}).wait();
  return result.as<std::vector<std::string>>();
}
fbtc::blockchain::public_key_type common_api_rpc_client::wallet_account_create(const std::string& account_name)
{
  fc::variant result = get_json_connection()->async_call("wallet_account_create", std::vector<fc::variant>{fc::variant(account_name)}).wait();
  return result.as<fbtc::blockchain::public_key_type>();
}
std::vector<fbtc::wallet::wallet_contact_record> common_api_rpc_client::wallet_list_contacts() const
{
  fc::variant result = get_json_connection()->async_call("wallet_list_contacts", std::vector<fc::variant>{}).wait();
  return result.as<std::vector<fbtc::wallet::wallet_contact_record>>();
}
fbtc::wallet::owallet_contact_record common_api_rpc_client::wallet_get_contact(const std::string& contact) const
{
  fc::variant result = get_json_connection()->async_call("wallet_get_contact", std::vector<fc::variant>{fc::variant(contact)}).wait();
  return result.as<fbtc::wallet::owallet_contact_record>();
}
fbtc::wallet::wallet_contact_record common_api_rpc_client::wallet_add_contact(const std::string& contact, const std::string& label /* = fc::json::from_string("\"\"").as<std::string>() */)
{
  fc::variant result = get_json_connection()->async_call("wallet_add_contact", std::vector<fc::variant>{fc::variant(contact), fc::variant(label)}).wait();
  return result.as<fbtc::wallet::wallet_contact_record>();
}
fbtc::wallet::owallet_contact_record common_api_rpc_client::wallet_remove_contact(const std::string& contact)
{
  fc::variant result = get_json_connection()->async_call("wallet_remove_contact", std::vector<fc::variant>{fc::variant(contact)}).wait();
  return result.as<fbtc::wallet::owallet_contact_record>();
}
std::vector<fbtc::wallet::wallet_approval_record> common_api_rpc_client::wallet_list_approvals() const
{
  fc::variant result = get_json_connection()->async_call("wallet_list_approvals", std::vector<fc::variant>{}).wait();
  return result.as<std::vector<fbtc::wallet::wallet_approval_record>>();
}
fbtc::wallet::owallet_approval_record common_api_rpc_client::wallet_get_approval(const std::string& approval) const
{
  fc::variant result = get_json_connection()->async_call("wallet_get_approval", std::vector<fc::variant>{fc::variant(approval)}).wait();
  return result.as<fbtc::wallet::owallet_approval_record>();
}
fbtc::wallet::wallet_approval_record common_api_rpc_client::wallet_approve(const std::string& name, int8_t approval /* = fc::json::from_string("1").as<int8_t>() */)
{
  fc::variant result = get_json_connection()->async_call("wallet_approve", std::vector<fc::variant>{fc::variant(name), fc::variant(approval)}).wait();
  return result.as<fbtc::wallet::wallet_approval_record>();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_burn(const std::string& amount_to_burn, const std::string& asset_symbol, const std::string& from_account_name, const std::string& for_or_against, const std::string& to_account_name, const std::string& public_message /* = fc::json::from_string("\"\"").as<std::string>() */, bool anonymous /* = fc::json::from_string("\"false\"").as<bool>() */)
{
  fc::variant result = get_json_connection()->async_call("wallet_burn", std::vector<fc::variant>{fc::variant(amount_to_burn), fc::variant(asset_symbol), fc::variant(from_account_name), fc::variant(for_or_against), fc::variant(to_account_name), fc::variant(public_message), fc::variant(anonymous)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
std::string common_api_rpc_client::wallet_address_create(const std::string& account_name, const std::string& label /* = fc::json::from_string("\"\"").as<std::string>() */, int32_t legacy_network_byte /* = fc::json::from_string("-1").as<int32_t>() */)
{
  fc::variant result = get_json_connection()->async_call("wallet_address_create", std::vector<fc::variant>{fc::variant(account_name), fc::variant(label), fc::variant(legacy_network_byte)}).wait();
  return result.as<std::string>();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_transfer_to_address(const std::string& amount_to_transfer, const std::string& asset_symbol, const std::string& from_account_name, const std::string& to_address, const std::string& memo_message /* = fc::json::from_string("\"\"").as<std::string>() */, const fbtc::wallet::vote_strategy& strategy /* = fc::json::from_string("\"vote_recommended\"").as<fbtc::wallet::vote_strategy>() */)
{
  fc::variant result = get_json_connection()->async_call("wallet_transfer_to_address", std::vector<fc::variant>{fc::variant(amount_to_transfer), fc::variant(asset_symbol), fc::variant(from_account_name), fc::variant(to_address), fc::variant(memo_message), fc::variant(strategy)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_transfer_to_genesis_multisig_address(const std::string& amount_to_transfer, const std::string& asset_symbol, const std::string& from_account_name, const std::string& to_address, const std::string& memo_message /* = fc::json::from_string("\"\"").as<std::string>() */, const fbtc::wallet::vote_strategy& strategy /* = fc::json::from_string("\"vote_recommended\"").as<fbtc::wallet::vote_strategy>() */)
{
  fc::variant result = get_json_connection()->async_call("wallet_transfer_to_genesis_multisig_address", std::vector<fc::variant>{fc::variant(amount_to_transfer), fc::variant(asset_symbol), fc::variant(from_account_name), fc::variant(to_address), fc::variant(memo_message), fc::variant(strategy)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_transfer_to_address_from_file(const std::string& from_account_name, const std::string& file_path, const std::string& memo_message /* = fc::json::from_string("\"\"").as<std::string>() */, const fbtc::wallet::vote_strategy& strategy /* = fc::json::from_string("\"vote_recommended\"").as<fbtc::wallet::vote_strategy>() */)
{
  fc::variant result = get_json_connection()->async_call("wallet_transfer_to_address_from_file", std::vector<fc::variant>{fc::variant(from_account_name), fc::variant(file_path), fc::variant(memo_message), fc::variant(strategy)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_transfer_to_genesis_multisig_address_from_file(const std::string& from_account_name, const std::string& file_path, const std::string& memo_message /* = fc::json::from_string("\"\"").as<std::string>() */, const fbtc::wallet::vote_strategy& strategy /* = fc::json::from_string("\"vote_recommended\"").as<fbtc::wallet::vote_strategy>() */)
{
  fc::variant result = get_json_connection()->async_call("wallet_transfer_to_genesis_multisig_address_from_file", std::vector<fc::variant>{fc::variant(from_account_name), fc::variant(file_path), fc::variant(memo_message), fc::variant(strategy)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
bool common_api_rpc_client::wallet_check_passphrase(const std::string& passphrase)
{
  fc::variant result = get_json_connection()->async_call("wallet_check_passphrase", std::vector<fc::variant>{fc::variant(passphrase)}).wait();
  return result.as<bool>();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_transfer(const std::string& amount_to_transfer, const std::string& asset_symbol, const std::string& from_account_name, const std::string& recipient, const std::string& memo_message /* = fc::json::from_string("\"\"").as<std::string>() */, const fbtc::wallet::vote_strategy& strategy /* = fc::json::from_string("\"vote_recommended\"").as<fbtc::wallet::vote_strategy>() */)
{
  fc::variant result = get_json_connection()->async_call("wallet_transfer", std::vector<fc::variant>{fc::variant(amount_to_transfer), fc::variant(asset_symbol), fc::variant(from_account_name), fc::variant(recipient), fc::variant(memo_message), fc::variant(strategy)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
fbtc::blockchain::address common_api_rpc_client::wallet_multisig_get_balance_id(const std::string& symbol, uint32_t m, const std::vector<fbtc::blockchain::address>& addresses) const
{
  fc::variant result = get_json_connection()->async_call("wallet_multisig_get_balance_id", std::vector<fc::variant>{fc::variant(symbol), fc::variant(m), fc::variant(addresses)}).wait();
  return result.as<fbtc::blockchain::address>();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_multisig_deposit(const std::string& amount, const std::string& symbol, const std::string& from_name, uint32_t m, const std::vector<fbtc::blockchain::address>& addresses, const fbtc::wallet::vote_strategy& strategy /* = fc::json::from_string("\"vote_none\"").as<fbtc::wallet::vote_strategy>() */)
{
  fc::variant result = get_json_connection()->async_call("wallet_multisig_deposit", std::vector<fc::variant>{fc::variant(amount), fc::variant(symbol), fc::variant(from_name), fc::variant(m), fc::variant(addresses), fc::variant(strategy)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
fbtc::wallet::transaction_builder common_api_rpc_client::wallet_withdraw_from_address(const std::string& amount, const std::string& symbol, const fbtc::blockchain::address& from_address, const std::string& to, const fbtc::wallet::vote_strategy& strategy /* = fc::json::from_string("\"vote_none\"").as<fbtc::wallet::vote_strategy>() */, bool sign_and_broadcast /* = fc::json::from_string("true").as<bool>() */, const std::string& builder_path /* = fc::json::from_string("\"\"").as<std::string>() */)
{
  fc::variant result = get_json_connection()->async_call("wallet_withdraw_from_address", std::vector<fc::variant>{fc::variant(amount), fc::variant(symbol), fc::variant(from_address), fc::variant(to), fc::variant(strategy), fc::variant(sign_and_broadcast), fc::variant(builder_path)}).wait();
  return result.as<fbtc::wallet::transaction_builder>();
}
fbtc::wallet::transaction_builder common_api_rpc_client::wallet_receive_genesis_multisig_blanace(const fbtc::blockchain::address& from_address, const std::string& from_address_redeemscript, const std::string& to, const fbtc::wallet::vote_strategy& strategy /* = fc::json::from_string("\"vote_none\"").as<fbtc::wallet::vote_strategy>() */, bool sign_and_broadcast /* = fc::json::from_string("true").as<bool>() */, const std::string& builder_path /* = fc::json::from_string("\"\"").as<std::string>() */)
{
  fc::variant result = get_json_connection()->async_call("wallet_receive_genesis_multisig_blanace", std::vector<fc::variant>{fc::variant(from_address), fc::variant(from_address_redeemscript), fc::variant(to), fc::variant(strategy), fc::variant(sign_and_broadcast), fc::variant(builder_path)}).wait();
  return result.as<fbtc::wallet::transaction_builder>();
}
fbtc::wallet::transaction_builder common_api_rpc_client::wallet_withdraw_from_legacy_address(const std::string& amount, const std::string& symbol, const fbtc::blockchain::pts_address& from_address, const std::string& to, const fbtc::wallet::vote_strategy& strategy /* = fc::json::from_string("\"vote_none\"").as<fbtc::wallet::vote_strategy>() */, bool sign_and_broadcast /* = fc::json::from_string("true").as<bool>() */, const std::string& builder_path /* = fc::json::from_string("\"\"").as<std::string>() */) const
{
  fc::variant result = get_json_connection()->async_call("wallet_withdraw_from_legacy_address", std::vector<fc::variant>{fc::variant(amount), fc::variant(symbol), fc::variant(from_address), fc::variant(to), fc::variant(strategy), fc::variant(sign_and_broadcast), fc::variant(builder_path)}).wait();
  return result.as<fbtc::wallet::transaction_builder>();
}
fbtc::wallet::transaction_builder common_api_rpc_client::wallet_multisig_withdraw_start(const std::string& amount, const std::string& symbol, const fbtc::blockchain::address& from, const fbtc::blockchain::address& to_address, const fbtc::wallet::vote_strategy& strategy /* = fc::json::from_string("\"vote_none\"").as<fbtc::wallet::vote_strategy>() */, const std::string& builder_path /* = fc::json::from_string("\"\"").as<std::string>() */) const
{
  fc::variant result = get_json_connection()->async_call("wallet_multisig_withdraw_start", std::vector<fc::variant>{fc::variant(amount), fc::variant(symbol), fc::variant(from), fc::variant(to_address), fc::variant(strategy), fc::variant(builder_path)}).wait();
  return result.as<fbtc::wallet::transaction_builder>();
}
fbtc::wallet::transaction_builder common_api_rpc_client::wallet_builder_add_signature(const fbtc::wallet::transaction_builder& builder, bool broadcast /* = fc::json::from_string("false").as<bool>() */)
{
  fc::variant result = get_json_connection()->async_call("wallet_builder_add_signature", std::vector<fc::variant>{fc::variant(builder), fc::variant(broadcast)}).wait();
  return result.as<fbtc::wallet::transaction_builder>();
}
fbtc::wallet::transaction_builder common_api_rpc_client::wallet_builder_file_add_signature(const std::string& builder_path /* = fc::json::from_string("\"\"").as<std::string>() */, bool broadcast /* = fc::json::from_string("false").as<bool>() */)
{
  fc::variant result = get_json_connection()->async_call("wallet_builder_file_add_signature", std::vector<fc::variant>{fc::variant(builder_path), fc::variant(broadcast)}).wait();
  return result.as<fbtc::wallet::transaction_builder>();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_release_escrow(const std::string& pay_fee_with_account_name, const fbtc::blockchain::address& escrow_balance_id, const std::string& released_by_account, const std::string& amount_to_sender /* = fc::json::from_string("0").as<std::string>() */, const std::string& amount_to_receiver /* = fc::json::from_string("0").as<std::string>() */)
{
  fc::variant result = get_json_connection()->async_call("wallet_release_escrow", std::vector<fc::variant>{fc::variant(pay_fee_with_account_name), fc::variant(escrow_balance_id), fc::variant(released_by_account), fc::variant(amount_to_sender), fc::variant(amount_to_receiver)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_transfer_from_with_escrow(const std::string& amount_to_transfer, const std::string& asset_symbol, const std::string& paying_account_name, const std::string& from_account_name, const std::string& to_account_name, const std::string& escrow_account_name, const fbtc::blockchain::digest_type& agreement /* = fc::json::from_string("\"\"").as<fbtc::blockchain::digest_type>() */, const std::string& memo_message /* = fc::json::from_string("\"\"").as<std::string>() */, const fbtc::wallet::vote_strategy& strategy /* = fc::json::from_string("\"vote_recommended\"").as<fbtc::wallet::vote_strategy>() */)
{
  fc::variant result = get_json_connection()->async_call("wallet_transfer_from_with_escrow", std::vector<fc::variant>{fc::variant(amount_to_transfer), fc::variant(asset_symbol), fc::variant(paying_account_name), fc::variant(from_account_name), fc::variant(to_account_name), fc::variant(escrow_account_name), fc::variant(agreement), fc::variant(memo_message), fc::variant(strategy)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
void common_api_rpc_client::wallet_rescan_blockchain(uint32_t start_block_num /* = fc::json::from_string("0").as<uint32_t>() */, uint32_t limit /* = fc::json::from_string("-1").as<uint32_t>() */, bool scan_in_background /* = fc::json::from_string("true").as<bool>() */)
{
  fc::variant result = get_json_connection()->async_call("wallet_rescan_blockchain", std::vector<fc::variant>{fc::variant(start_block_num), fc::variant(limit), fc::variant(scan_in_background)}).wait();
}
void common_api_rpc_client::wallet_cancel_scan()
{
  fc::variant result = get_json_connection()->async_call("wallet_cancel_scan", std::vector<fc::variant>{}).wait();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_get_transaction(const std::string& transaction_id)
{
  fc::variant result = get_json_connection()->async_call("wallet_get_transaction", std::vector<fc::variant>{fc::variant(transaction_id)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_scan_transaction(const std::string& transaction_id, bool overwrite_existing /* = fc::json::from_string("false").as<bool>() */)
{
  fc::variant result = get_json_connection()->async_call("wallet_scan_transaction", std::vector<fc::variant>{fc::variant(transaction_id), fc::variant(overwrite_existing)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
void common_api_rpc_client::wallet_scan_transaction_experimental(const std::string& transaction_id, bool overwrite_existing /* = fc::json::from_string("false").as<bool>() */)
{
  fc::variant result = get_json_connection()->async_call("wallet_scan_transaction_experimental", std::vector<fc::variant>{fc::variant(transaction_id), fc::variant(overwrite_existing)}).wait();
}
void common_api_rpc_client::wallet_add_transaction_note_experimental(const std::string& transaction_id, const std::string& note)
{
  fc::variant result = get_json_connection()->async_call("wallet_add_transaction_note_experimental", std::vector<fc::variant>{fc::variant(transaction_id), fc::variant(note)}).wait();
}
void common_api_rpc_client::wallet_rebroadcast_transaction(const std::string& transaction_id)
{
  fc::variant result = get_json_connection()->async_call("wallet_rebroadcast_transaction", std::vector<fc::variant>{fc::variant(transaction_id)}).wait();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_account_register(const std::string& account_name, const std::string& pay_from_account, const fc::variant& public_data /* = fc::json::from_string("null").as<fc::variant>() */, uint8_t delegate_pay_rate /* = fc::json::from_string("-1").as<uint8_t>() */, const std::string& account_type /* = fc::json::from_string("\"titan_account\"").as<std::string>() */)
{
  fc::variant result = get_json_connection()->async_call("wallet_account_register", std::vector<fc::variant>{fc::variant(account_name), fc::variant(pay_from_account), fc::variant(public_data), fc::variant(delegate_pay_rate), fc::variant(account_type)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
void common_api_rpc_client::wallet_set_custom_data(const fbtc::wallet::wallet_record_type_enum& type, const std::string& item, const fc::variant_object& custom_data)
{
  fc::variant result = get_json_connection()->async_call("wallet_set_custom_data", std::vector<fc::variant>{fc::variant(type), fc::variant(item), fc::variant(custom_data)}).wait();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_account_update_registration(const std::string& account_name, const std::string& pay_from_account, const fc::variant& public_data /* = fc::json::from_string("null").as<fc::variant>() */, uint8_t delegate_pay_rate /* = fc::json::from_string("-1").as<uint8_t>() */)
{
  fc::variant result = get_json_connection()->async_call("wallet_account_update_registration", std::vector<fc::variant>{fc::variant(account_name), fc::variant(pay_from_account), fc::variant(public_data), fc::variant(delegate_pay_rate)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_account_update_active_key(const std::string& account_to_update, const std::string& pay_from_account, const std::string& new_active_key /* = fc::json::from_string("\"\"").as<std::string>() */)
{
  fc::variant result = get_json_connection()->async_call("wallet_account_update_active_key", std::vector<fc::variant>{fc::variant(account_to_update), fc::variant(pay_from_account), fc::variant(new_active_key)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
std::vector<fbtc::wallet::wallet_account_record> common_api_rpc_client::wallet_list_accounts() const
{
  fc::variant result = get_json_connection()->async_call("wallet_list_accounts", std::vector<fc::variant>{}).wait();
  return result.as<std::vector<fbtc::wallet::wallet_account_record>>();
}
fbtc::wallet::owallet_account_record common_api_rpc_client::wallet_get_account(const std::string& account) const
{
  fc::variant result = get_json_connection()->async_call("wallet_get_account", std::vector<fc::variant>{fc::variant(account)}).wait();
  return result.as<fbtc::wallet::owallet_account_record>();
}
void common_api_rpc_client::wallet_account_rename(const std::string& current_account_name, const std::string& new_account_name)
{
  fc::variant result = get_json_connection()->async_call("wallet_account_rename", std::vector<fc::variant>{fc::variant(current_account_name), fc::variant(new_account_name)}).wait();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_mia_create(const std::string& payer_account, const std::string& symbol, const std::string& name, const std::string& description, const std::string& max_divisibility)
{
  fc::variant result = get_json_connection()->async_call("wallet_mia_create", std::vector<fc::variant>{fc::variant(payer_account), fc::variant(symbol), fc::variant(name), fc::variant(description), fc::variant(max_divisibility)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_uia_create(const std::string& issuer_account, const std::string& symbol, const std::string& name, const std::string& description, const std::string& max_supply_with_trailing_decimals)
{
  fc::variant result = get_json_connection()->async_call("wallet_uia_create", std::vector<fc::variant>{fc::variant(issuer_account), fc::variant(symbol), fc::variant(name), fc::variant(description), fc::variant(max_supply_with_trailing_decimals)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_uia_issue(const std::string& asset_amount, const std::string& asset_symbol, const std::string& recipient, const std::string& memo_message /* = fc::json::from_string("\"\"").as<std::string>() */)
{
  fc::variant result = get_json_connection()->async_call("wallet_uia_issue", std::vector<fc::variant>{fc::variant(asset_amount), fc::variant(asset_symbol), fc::variant(recipient), fc::variant(memo_message)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_uia_issue_to_addresses(const std::string& symbol, const std::map<std::string, fbtc::blockchain::share_type>& addresses)
{
  fc::variant result = get_json_connection()->async_call("wallet_uia_issue_to_addresses", std::vector<fc::variant>{fc::variant(symbol), fc::variant(addresses)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_uia_collect_fees(const std::string& asset_symbol, const std::string& recipient, const std::string& memo_message /* = fc::json::from_string("\"\"").as<std::string>() */)
{
  fc::variant result = get_json_connection()->async_call("wallet_uia_collect_fees", std::vector<fc::variant>{fc::variant(asset_symbol), fc::variant(recipient), fc::variant(memo_message)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_uia_update_description(const std::string& paying_account, const std::string& asset_symbol, const std::string& name /* = fc::json::from_string("\"\"").as<std::string>() */, const std::string& description /* = fc::json::from_string("\"\"").as<std::string>() */, const fc::variant& public_data /* = fc::json::from_string("null").as<fc::variant>() */)
{
  fc::variant result = get_json_connection()->async_call("wallet_uia_update_description", std::vector<fc::variant>{fc::variant(paying_account), fc::variant(asset_symbol), fc::variant(name), fc::variant(description), fc::variant(public_data)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_uia_update_supply(const std::string& paying_account, const std::string& asset_symbol, const std::string& max_supply_with_trailing_decimals)
{
  fc::variant result = get_json_connection()->async_call("wallet_uia_update_supply", std::vector<fc::variant>{fc::variant(paying_account), fc::variant(asset_symbol), fc::variant(max_supply_with_trailing_decimals)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_uia_update_fees(const std::string& paying_account, const std::string& asset_symbol, const std::string& withdrawal_fee /* = fc::json::from_string("\"\"").as<std::string>() */, const std::string& market_fee_rate /* = fc::json::from_string("\"\"").as<std::string>() */)
{
  fc::variant result = get_json_connection()->async_call("wallet_uia_update_fees", std::vector<fc::variant>{fc::variant(paying_account), fc::variant(asset_symbol), fc::variant(withdrawal_fee), fc::variant(market_fee_rate)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_uia_update_active_flags(const std::string& paying_account, const std::string& asset_symbol, const fbtc::blockchain::asset_record::flag_enum& flag, bool enable_instead_of_disable)
{
  fc::variant result = get_json_connection()->async_call("wallet_uia_update_active_flags", std::vector<fc::variant>{fc::variant(paying_account), fc::variant(asset_symbol), fc::variant(flag), fc::variant(enable_instead_of_disable)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_uia_update_authority_permissions(const std::string& paying_account, const std::string& asset_symbol, const fbtc::blockchain::asset_record::flag_enum& permission, bool add_instead_of_remove)
{
  fc::variant result = get_json_connection()->async_call("wallet_uia_update_authority_permissions", std::vector<fc::variant>{fc::variant(paying_account), fc::variant(asset_symbol), fc::variant(permission), fc::variant(add_instead_of_remove)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_uia_update_whitelist(const std::string& paying_account, const std::string& asset_symbol, const std::string& account_name, bool add_to_whitelist)
{
  fc::variant result = get_json_connection()->async_call("wallet_uia_update_whitelist", std::vector<fc::variant>{fc::variant(paying_account), fc::variant(asset_symbol), fc::variant(account_name), fc::variant(add_to_whitelist)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_uia_retract_balance(const fbtc::blockchain::address& balance_id, const std::string& account_name)
{
  fc::variant result = get_json_connection()->async_call("wallet_uia_retract_balance", std::vector<fc::variant>{fc::variant(balance_id), fc::variant(account_name)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
std::vector<fbtc::wallet::escrow_summary> common_api_rpc_client::wallet_escrow_summary(const std::string& account_name /* = fc::json::from_string("\"\"").as<std::string>() */) const
{
  fc::variant result = get_json_connection()->async_call("wallet_escrow_summary", std::vector<fc::variant>{fc::variant(account_name)}).wait();
  return result.as<std::vector<fbtc::wallet::escrow_summary>>();
}
fbtc::wallet::account_balance_summary_type common_api_rpc_client::wallet_account_balance(const std::string& account_name /* = fc::json::from_string("\"\"").as<std::string>() */) const
{
  fc::variant result = get_json_connection()->async_call("wallet_account_balance", std::vector<fc::variant>{fc::variant(account_name)}).wait();
  return result.as<fbtc::wallet::account_balance_summary_type>();
}
fbtc::wallet::account_balance_id_summary_type common_api_rpc_client::wallet_account_balance_ids(const std::string& account_name /* = fc::json::from_string("\"\"").as<std::string>() */) const
{
  fc::variant result = get_json_connection()->async_call("wallet_account_balance_ids", std::vector<fc::variant>{fc::variant(account_name)}).wait();
  return result.as<fbtc::wallet::account_balance_id_summary_type>();
}
fbtc::wallet::account_extended_balance_type common_api_rpc_client::wallet_account_balance_extended(const std::string& account_name /* = fc::json::from_string("\"\"").as<std::string>() */) const
{
  fc::variant result = get_json_connection()->async_call("wallet_account_balance_extended", std::vector<fc::variant>{fc::variant(account_name)}).wait();
  return result.as<fbtc::wallet::account_extended_balance_type>();
}
fbtc::wallet::account_vesting_balance_summary_type common_api_rpc_client::wallet_account_vesting_balances(const std::string& account_name /* = fc::json::from_string("\"\"").as<std::string>() */) const
{
  fc::variant result = get_json_connection()->async_call("wallet_account_vesting_balances", std::vector<fc::variant>{fc::variant(account_name)}).wait();
  return result.as<fbtc::wallet::account_vesting_balance_summary_type>();
}
fbtc::wallet::account_balance_summary_type common_api_rpc_client::wallet_account_yield(const std::string& account_name /* = fc::json::from_string("\"\"").as<std::string>() */) const
{
  fc::variant result = get_json_connection()->async_call("wallet_account_yield", std::vector<fc::variant>{fc::variant(account_name)}).wait();
  return result.as<fbtc::wallet::account_balance_summary_type>();
}
std::vector<fbtc::wallet::public_key_summary> common_api_rpc_client::wallet_account_list_public_keys(const std::string& account_name)
{
  fc::variant result = get_json_connection()->async_call("wallet_account_list_public_keys", std::vector<fc::variant>{fc::variant(account_name)}).wait();
  return result.as<std::vector<fbtc::wallet::public_key_summary>>();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_delegate_withdraw_pay(const std::string& delegate_name, const std::string& to_account_name, const std::string& amount_to_withdraw)
{
  fc::variant result = get_json_connection()->async_call("wallet_delegate_withdraw_pay", std::vector<fc::variant>{fc::variant(delegate_name), fc::variant(to_account_name), fc::variant(amount_to_withdraw)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
fbtc::blockchain::asset common_api_rpc_client::wallet_set_transaction_fee(const std::string& fee)
{
  fc::variant result = get_json_connection()->async_call("wallet_set_transaction_fee", std::vector<fc::variant>{fc::variant(fee)}).wait();
  return result.as<fbtc::blockchain::asset>();
}
fbtc::blockchain::asset common_api_rpc_client::wallet_get_transaction_fee(const std::string& symbol /* = fc::json::from_string("\"\"").as<std::string>() */)
{
  fc::variant result = get_json_connection()->async_call("wallet_get_transaction_fee", std::vector<fc::variant>{fc::variant(symbol)}).wait();
  return result.as<fbtc::blockchain::asset>();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_market_submit_bid(const std::string& from_account_name, const std::string& quantity, const std::string& quantity_symbol, const std::string& base_price, const std::string& base_symbol, bool allow_stupid_bid /* = fc::json::from_string("\"false\"").as<bool>() */)
{
  fc::variant result = get_json_connection()->async_call("wallet_market_submit_bid", std::vector<fc::variant>{fc::variant(from_account_name), fc::variant(quantity), fc::variant(quantity_symbol), fc::variant(base_price), fc::variant(base_symbol), fc::variant(allow_stupid_bid)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_market_submit_ask(const std::string& from_account_name, const std::string& sell_quantity, const std::string& sell_quantity_symbol, const std::string& ask_price, const std::string& ask_price_symbol, bool allow_stupid_ask /* = fc::json::from_string("\"false\"").as<bool>() */)
{
  fc::variant result = get_json_connection()->async_call("wallet_market_submit_ask", std::vector<fc::variant>{fc::variant(from_account_name), fc::variant(sell_quantity), fc::variant(sell_quantity_symbol), fc::variant(ask_price), fc::variant(ask_price_symbol), fc::variant(allow_stupid_ask)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_market_submit_short(const std::string& from_account_name, const std::string& short_collateral, const std::string& collateral_symbol, const std::string& interest_rate, const std::string& quote_symbol, const std::string& short_price_limit /* = fc::json::from_string("0").as<std::string>() */)
{
  fc::variant result = get_json_connection()->async_call("wallet_market_submit_short", std::vector<fc::variant>{fc::variant(from_account_name), fc::variant(short_collateral), fc::variant(collateral_symbol), fc::variant(interest_rate), fc::variant(quote_symbol), fc::variant(short_price_limit)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_market_cover(const std::string& from_account_name, const std::string& quantity, const std::string& quantity_symbol, const fbtc::blockchain::order_id_type& cover_id)
{
  fc::variant result = get_json_connection()->async_call("wallet_market_cover", std::vector<fc::variant>{fc::variant(from_account_name), fc::variant(quantity), fc::variant(quantity_symbol), fc::variant(cover_id)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_market_batch_update(const std::vector<fbtc::blockchain::order_id_type>& cancel_order_ids, const std::vector<fbtc::wallet::order_description>& new_orders, bool sign)
{
  fc::variant result = get_json_connection()->async_call("wallet_market_batch_update", std::vector<fc::variant>{fc::variant(cancel_order_ids), fc::variant(new_orders), fc::variant(sign)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_market_add_collateral(const std::string& from_account_name, const fbtc::blockchain::order_id_type& cover_id, const std::string& real_quantity_collateral_to_add)
{
  fc::variant result = get_json_connection()->async_call("wallet_market_add_collateral", std::vector<fc::variant>{fc::variant(from_account_name), fc::variant(cover_id), fc::variant(real_quantity_collateral_to_add)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
std::map<fbtc::blockchain::order_id_type, fbtc::blockchain::market_order> common_api_rpc_client::wallet_market_order_list(const std::string& base_symbol, const std::string& quote_symbol, uint32_t limit /* = fc::json::from_string("-1").as<uint32_t>() */, const std::string& account_name /* = fc::json::from_string("\"\"").as<std::string>() */)
{
  fc::variant result = get_json_connection()->async_call("wallet_market_order_list", std::vector<fc::variant>{fc::variant(base_symbol), fc::variant(quote_symbol), fc::variant(limit), fc::variant(account_name)}).wait();
  return result.as<std::map<fbtc::blockchain::order_id_type, fbtc::blockchain::market_order>>();
}
std::map<fbtc::blockchain::order_id_type, fbtc::blockchain::market_order> common_api_rpc_client::wallet_account_order_list(const std::string& account_name /* = fc::json::from_string("\"\"").as<std::string>() */, uint32_t limit /* = fc::json::from_string("-1").as<uint32_t>() */)
{
  fc::variant result = get_json_connection()->async_call("wallet_account_order_list", std::vector<fc::variant>{fc::variant(account_name), fc::variant(limit)}).wait();
  return result.as<std::map<fbtc::blockchain::order_id_type, fbtc::blockchain::market_order>>();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_market_cancel_order(const fbtc::blockchain::order_id_type& order_id)
{
  fc::variant result = get_json_connection()->async_call("wallet_market_cancel_order", std::vector<fc::variant>{fc::variant(order_id)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_market_cancel_orders(const std::vector<fbtc::blockchain::order_id_type>& order_ids)
{
  fc::variant result = get_json_connection()->async_call("wallet_market_cancel_orders", std::vector<fc::variant>{fc::variant(order_ids)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
fc::optional<std::string> common_api_rpc_client::wallet_dump_private_key(const std::string& input) const
{
  fc::variant result = get_json_connection()->async_call("wallet_dump_private_key", std::vector<fc::variant>{fc::variant(input)}).wait();
  return result.as<fc::optional<std::string>>();
}
fc::optional<std::string> common_api_rpc_client::wallet_dump_account_private_key(const std::string& account_name, const fbtc::wallet::account_key_type& key_type) const
{
  fc::variant result = get_json_connection()->async_call("wallet_dump_account_private_key", std::vector<fc::variant>{fc::variant(account_name), fc::variant(key_type)}).wait();
  return result.as<fc::optional<std::string>>();
}
fbtc::wallet::account_vote_summary_type common_api_rpc_client::wallet_account_vote_summary(const std::string& account_name /* = fc::json::from_string("\"\"").as<std::string>() */) const
{
  fc::variant result = get_json_connection()->async_call("wallet_account_vote_summary", std::vector<fc::variant>{fc::variant(account_name)}).wait();
  return result.as<fbtc::wallet::account_vote_summary_type>();
}
void common_api_rpc_client::wallet_set_setting(const std::string& name, const fc::variant& value)
{
  fc::variant result = get_json_connection()->async_call("wallet_set_setting", std::vector<fc::variant>{fc::variant(name), fc::variant(value)}).wait();
}
fc::optional<fc::variant> common_api_rpc_client::wallet_get_setting(const std::string& name)
{
  fc::variant result = get_json_connection()->async_call("wallet_get_setting", std::vector<fc::variant>{fc::variant(name)}).wait();
  return result.as<fc::optional<fc::variant>>();
}
void common_api_rpc_client::wallet_delegate_set_block_production(const std::string& delegate_name, bool enabled)
{
  fc::variant result = get_json_connection()->async_call("wallet_delegate_set_block_production", std::vector<fc::variant>{fc::variant(delegate_name), fc::variant(enabled)}).wait();
}
bool common_api_rpc_client::wallet_set_transaction_scanning(bool enabled)
{
  fc::variant result = get_json_connection()->async_call("wallet_set_transaction_scanning", std::vector<fc::variant>{fc::variant(enabled)}).wait();
  return result.as<bool>();
}
fc::ecc::compact_signature common_api_rpc_client::wallet_sign_hash(const std::string& signer, const fc::sha256& hash)
{
  fc::variant result = get_json_connection()->async_call("wallet_sign_hash", std::vector<fc::variant>{fc::variant(signer), fc::variant(hash)}).wait();
  return result.as<fc::ecc::compact_signature>();
}
std::string common_api_rpc_client::wallet_login_start(const std::string& server_account)
{
  fc::variant result = get_json_connection()->async_call("wallet_login_start", std::vector<fc::variant>{fc::variant(server_account)}).wait();
  return result.as<std::string>();
}
fc::variant common_api_rpc_client::wallet_login_finish(const fbtc::blockchain::public_key_type& server_key, const fbtc::blockchain::public_key_type& client_key, const fc::ecc::compact_signature& client_signature)
{
  fc::variant result = get_json_connection()->async_call("wallet_login_finish", std::vector<fc::variant>{fc::variant(server_key), fc::variant(client_key), fc::variant(client_signature)}).wait();
  return result.as<fc::variant>();
}
fbtc::wallet::transaction_builder common_api_rpc_client::wallet_balance_set_vote_info(const fbtc::blockchain::address& balance_id, const std::string& voter_address /* = fc::json::from_string("\"\"").as<std::string>() */, const fbtc::wallet::vote_strategy& strategy /* = fc::json::from_string("\"vote_all\"").as<fbtc::wallet::vote_strategy>() */, bool sign_and_broadcast /* = fc::json::from_string("\"true\"").as<bool>() */, const std::string& builder_path /* = fc::json::from_string("\"\"").as<std::string>() */)
{
  fc::variant result = get_json_connection()->async_call("wallet_balance_set_vote_info", std::vector<fc::variant>{fc::variant(balance_id), fc::variant(voter_address), fc::variant(strategy), fc::variant(sign_and_broadcast), fc::variant(builder_path)}).wait();
  return result.as<fbtc::wallet::transaction_builder>();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_publish_slate(const std::string& publishing_account_name, const std::string& paying_account_name /* = fc::json::from_string("\"\"").as<std::string>() */)
{
  fc::variant result = get_json_connection()->async_call("wallet_publish_slate", std::vector<fc::variant>{fc::variant(publishing_account_name), fc::variant(paying_account_name)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_publish_version(const std::string& publishing_account_name, const std::string& paying_account_name /* = fc::json::from_string("\"\"").as<std::string>() */)
{
  fc::variant result = get_json_connection()->async_call("wallet_publish_version", std::vector<fc::variant>{fc::variant(publishing_account_name), fc::variant(paying_account_name)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_collect_genesis_balances(const std::string& account_name)
{
  fc::variant result = get_json_connection()->async_call("wallet_collect_genesis_balances", std::vector<fc::variant>{fc::variant(account_name)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_collect_vested_balances(const std::string& account_name)
{
  fc::variant result = get_json_connection()->async_call("wallet_collect_vested_balances", std::vector<fc::variant>{fc::variant(account_name)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_delegate_update_signing_key(const std::string& authorizing_account_name, const std::string& delegate_name, const fbtc::blockchain::public_key_type& signing_key)
{
  fc::variant result = get_json_connection()->async_call("wallet_delegate_update_signing_key", std::vector<fc::variant>{fc::variant(authorizing_account_name), fc::variant(delegate_name), fc::variant(signing_key)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
int32_t common_api_rpc_client::wallet_recover_accounts(int32_t accounts_to_recover, int32_t maximum_number_of_attempts /* = fc::json::from_string("1000").as<int32_t>() */)
{
  fc::variant result = get_json_connection()->async_call("wallet_recover_accounts", std::vector<fc::variant>{fc::variant(accounts_to_recover), fc::variant(maximum_number_of_attempts)}).wait();
  return result.as<int32_t>();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_recover_titan_deposit_info(const std::string& transaction_id_prefix, const std::string& recipient_account /* = fc::json::from_string("\"\"").as<std::string>() */)
{
  fc::variant result = get_json_connection()->async_call("wallet_recover_titan_deposit_info", std::vector<fc::variant>{fc::variant(transaction_id_prefix), fc::variant(recipient_account)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
fc::optional<fc::variant_object> common_api_rpc_client::wallet_verify_titan_deposit(const std::string& transaction_id_prefix)
{
  fc::variant result = get_json_connection()->async_call("wallet_verify_titan_deposit", std::vector<fc::variant>{fc::variant(transaction_id_prefix)}).wait();
  return result.as<fc::optional<fc::variant_object>>();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_publish_price_feed(const std::string& delegate_account, const std::string& price, const std::string& asset_symbol)
{
  fc::variant result = get_json_connection()->async_call("wallet_publish_price_feed", std::vector<fc::variant>{fc::variant(delegate_account), fc::variant(price), fc::variant(asset_symbol)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_publish_feeds(const std::string& delegate_account, const std::map<std::string, std::string>& symbol_to_price_map)
{
  fc::variant result = get_json_connection()->async_call("wallet_publish_feeds", std::vector<fc::variant>{fc::variant(delegate_account), fc::variant(symbol_to_price_map)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
std::vector<std::pair<std::string, fbtc::wallet::wallet_transaction_record>> common_api_rpc_client::wallet_publish_feeds_multi_experimental(const std::map<std::string, std::string>& symbol_to_price_map)
{
  fc::variant result = get_json_connection()->async_call("wallet_publish_feeds_multi_experimental", std::vector<fc::variant>{fc::variant(symbol_to_price_map)}).wait();
  return result.as<std::vector<std::pair<std::string, fbtc::wallet::wallet_transaction_record>>>();
}
void common_api_rpc_client::wallet_repair_records(const std::string& collecting_account_name /* = fc::json::from_string("\"\"").as<std::string>() */)
{
  fc::variant result = get_json_connection()->async_call("wallet_repair_records", std::vector<fc::variant>{fc::variant(collecting_account_name)}).wait();
}
int32_t common_api_rpc_client::wallet_regenerate_keys(const std::string& account_name, uint32_t max_key_number)
{
  fc::variant result = get_json_connection()->async_call("wallet_regenerate_keys", std::vector<fc::variant>{fc::variant(account_name), fc::variant(max_key_number)}).wait();
  return result.as<int32_t>();
}
fbtc::wallet::wallet_transaction_record common_api_rpc_client::wallet_account_retract(const std::string& account_to_retract, const std::string& pay_from_account)
{
  fc::variant result = get_json_connection()->async_call("wallet_account_retract", std::vector<fc::variant>{fc::variant(account_to_retract), fc::variant(pay_from_account)}).wait();
  return result.as<fbtc::wallet::wallet_transaction_record>();
}
std::string common_api_rpc_client::wallet_generate_brain_seed() const
{
  fc::variant result = get_json_connection()->async_call("wallet_generate_brain_seed", std::vector<fc::variant>{}).wait();
  return result.as<std::string>();
}
fc::variant_object common_api_rpc_client::fetch_welcome_package(const fc::variant_object& arguments)
{
  fc::variant result = get_json_connection()->async_call("fetch_welcome_package", std::vector<fc::variant>{fc::variant(arguments)}).wait();
  return result.as<fc::variant_object>();
}
bool common_api_rpc_client::request_register_account(const fbtc::blockchain::account_record& account)
{
  fc::variant result = get_json_connection()->async_call("request_register_account", std::vector<fc::variant>{fc::variant(account)}).wait();
  return result.as<bool>();
}
bool common_api_rpc_client::approve_register_account(const std::string& account_salt, const std::string& paying_account_name)
{
  fc::variant result = get_json_connection()->async_call("approve_register_account", std::vector<fc::variant>{fc::variant(account_salt), fc::variant(paying_account_name)}).wait();
  return result.as<bool>();
}
void common_api_rpc_client::debug_start_simulated_time(const fc::time_point& new_simulated_time)
{
  fc::variant result = get_json_connection()->async_call("debug_start_simulated_time", std::vector<fc::variant>{fc::variant(new_simulated_time)}).wait();
}
void common_api_rpc_client::debug_advance_time(int32_t delta_time_seconds, const std::string& unit /* = fc::json::from_string("\"seconds\"").as<std::string>() */)
{
  fc::variant result = get_json_connection()->async_call("debug_advance_time", std::vector<fc::variant>{fc::variant(delta_time_seconds), fc::variant(unit)}).wait();
}
void common_api_rpc_client::debug_trap(uint32_t block_number)
{
  fc::variant result = get_json_connection()->async_call("debug_trap", std::vector<fc::variant>{fc::variant(block_number)}).wait();
}
void common_api_rpc_client::debug_wait(uint32_t wait_time) const
{
  fc::variant result = get_json_connection()->async_call("debug_wait", std::vector<fc::variant>{fc::variant(wait_time)}).wait();
}
void common_api_rpc_client::debug_wait_for_block_by_number(uint32_t block_number, const std::string& type /* = fc::json::from_string("\"absolute\"").as<std::string>() */)
{
  fc::variant result = get_json_connection()->async_call("debug_wait_for_block_by_number", std::vector<fc::variant>{fc::variant(block_number), fc::variant(type)}).wait();
}
void common_api_rpc_client::debug_wait_block_interval(uint32_t wait_time_in_block_intervals) const
{
  fc::variant result = get_json_connection()->async_call("debug_wait_block_interval", std::vector<fc::variant>{fc::variant(wait_time_in_block_intervals)}).wait();
}
void common_api_rpc_client::debug_enable_output(bool enable_flag)
{
  fc::variant result = get_json_connection()->async_call("debug_enable_output", std::vector<fc::variant>{fc::variant(enable_flag)}).wait();
}
void common_api_rpc_client::debug_filter_output_for_tests(bool enable_flag)
{
  fc::variant result = get_json_connection()->async_call("debug_filter_output_for_tests", std::vector<fc::variant>{fc::variant(enable_flag)}).wait();
}
void common_api_rpc_client::debug_update_logging_config()
{
  fc::variant result = get_json_connection()->async_call("debug_update_logging_config", std::vector<fc::variant>{}).wait();
}
fc::variant_object common_api_rpc_client::debug_get_call_statistics() const
{
  fc::variant result = get_json_connection()->async_call("debug_get_call_statistics", std::vector<fc::variant>{}).wait();
  return result.as<fc::variant_object>();
}
std::string common_api_rpc_client::debug_get_client_name() const
{
  fc::variant result = get_json_connection()->async_call("debug_get_client_name", std::vector<fc::variant>{}).wait();
  return result.as<std::string>();
}
fc::variants common_api_rpc_client::debug_deterministic_private_keys(int32_t start /* = fc::json::from_string("\"-1\"").as<int32_t>() */, int32_t count /* = fc::json::from_string("\"1\"").as<int32_t>() */, const std::string& prefix /* = fc::json::from_string("\"\"").as<std::string>() */, bool import /* = fc::json::from_string("\"false\"").as<bool>() */, const std::string& account_name /* = fc::json::from_string("null").as<std::string>() */, bool create_new_account /* = fc::json::from_string("false").as<bool>() */, bool rescan /* = fc::json::from_string("false").as<bool>() */)
{
  fc::variant result = get_json_connection()->async_call("debug_deterministic_private_keys", std::vector<fc::variant>{fc::variant(start), fc::variant(count), fc::variant(prefix), fc::variant(import), fc::variant(account_name), fc::variant(create_new_account), fc::variant(rescan)}).wait();
  return result.as<fc::variants>();
}
void common_api_rpc_client::debug_stop_before_block(uint32_t block_number)
{
  fc::variant result = get_json_connection()->async_call("debug_stop_before_block", std::vector<fc::variant>{fc::variant(block_number)}).wait();
}
void common_api_rpc_client::debug_verify_market_matching(bool enable_flag)
{
  fc::variant result = get_json_connection()->async_call("debug_verify_market_matching", std::vector<fc::variant>{fc::variant(enable_flag)}).wait();
}
fc::variants common_api_rpc_client::debug_list_matching_errors() const
{
  fc::variant result = get_json_connection()->async_call("debug_list_matching_errors", std::vector<fc::variant>{}).wait();
  return result.as<fc::variants>();
}

} } // end namespace fbtc::rpc_stubs
