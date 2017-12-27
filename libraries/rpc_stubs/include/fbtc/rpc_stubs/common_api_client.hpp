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
#pragma once
#include <fbtc/api/api_metadata.hpp>
#include <fbtc/api/common_api.hpp>

namespace fbtc { namespace rpc_stubs {
  class common_api_client : public fbtc::api::common_api
  {
  protected:
    virtual fbtc::api::common_api* get_impl() const = 0;

  public:
    fc::variant_object about() const override;
    fc::variant_object get_info() const override;
    void stop() override;
    std::string help(const std::string& command_name = fc::json::from_string("\"\"").as<std::string>()) const override;
    fc::variant_object validate_address(const std::string& address) const override;
    fbtc::blockchain::address convert_to_native_address(const std::string& raw_address) const override;
    std::string execute_command_line(const std::string& input) const override;
    void execute_script(const fc::path& script) const override;
    fc::variants batch(const std::string& method_name, const std::vector<fc::variants>& parameters_list) const override;
    fc::variants batch_authenticated(const std::string& method_name, const std::vector<fc::variants>& parameters_list) const override;
    fbtc::wallet::wallet_transaction_record builder_finalize_and_sign(const fbtc::wallet::transaction_builder& builder) const override;
    std::map<std::string, fbtc::api::method_data> meta_help() const override;
    void rpc_set_username(const std::string& username = fc::json::from_string("\"\"").as<std::string>()) override;
    void rpc_set_password(const std::string& password = fc::json::from_string("\"\"").as<std::string>()) override;
    void rpc_start_server(uint32_t port = fc::json::from_string("\"65065\"").as<uint32_t>()) override;
    void http_start_server(uint32_t port = fc::json::from_string("\"65066\"").as<uint32_t>()) override;
    void ntp_update_time() override;
    fc::variant disk_usage() const override;
    void network_add_node(const std::string& node, const std::string& command = fc::json::from_string("\"add\"").as<std::string>()) override;
    uint32_t network_get_connection_count() const override;
    std::vector<fc::variant_object> network_get_peer_info(bool not_firewalled = fc::json::from_string("false").as<bool>()) const override;
    fbtc::blockchain::transaction_id_type network_broadcast_transaction(const fbtc::blockchain::signed_transaction& transaction_to_broadcast) override;
    void network_set_advanced_node_parameters(const fc::variant_object& params) override;
    fc::variant_object network_get_advanced_node_parameters() const override;
    fbtc::net::message_propagation_data network_get_transaction_propagation_data(const fbtc::blockchain::transaction_id_type& transaction_id) override;
    fbtc::net::message_propagation_data network_get_block_propagation_data(const fbtc::blockchain::block_id_type& block_hash) override;
    void network_set_allowed_peers(const std::vector<fbtc::net::node_id_t>& allowed_peers) override;
    fc::variant_object network_get_info() const override;
    std::vector<fbtc::net::potential_peer_record> network_list_potential_peers() const override;
    fc::variant_object network_get_upnp_info() const override;
    fc::variant_object network_get_usage_stats() const override;
    fc::variant delegate_get_config() const override;
    void delegate_set_network_min_connection_count(uint32_t count) override;
    void delegate_set_block_max_transaction_count(uint32_t count) override;
    void delegate_set_block_max_size(uint32_t size) override;
    void delegate_set_block_max_production_time(uint64_t time) override;
    void delegate_set_transaction_max_size(uint32_t size) override;
    void delegate_set_transaction_canonical_signatures_required(bool required) override;
    void delegate_set_transaction_min_fee(uint64_t fee) override;
    void delegate_blacklist_add_transaction(const fbtc::blockchain::transaction_id_type& id) override;
    void delegate_blacklist_remove_transaction(const fbtc::blockchain::transaction_id_type& id) override;
    void delegate_blacklist_add_operation(const fbtc::blockchain::operation_type_enum& id) override;
    void delegate_blacklist_remove_operation(const fbtc::blockchain::operation_type_enum& id) override;
    fc::variant_object blockchain_get_info() const override;
    void blockchain_generate_snapshot(const std::string& filename) const override;
    void blockchain_graphene_snapshot(const std::string& filename, const std::string& whitelist_filename = fc::json::from_string("\"\"").as<std::string>()) const override;
    void blockchain_generate_issuance_map(const std::string& symbol, const std::string& filename) const override;
    fbtc::blockchain::asset blockchain_calculate_supply(const std::string& asset) const override;
    fbtc::blockchain::asset blockchain_calculate_debt(const std::string& asset, bool include_interest = fc::json::from_string("\"false\"").as<bool>()) const override;
    fbtc::blockchain::asset blockchain_calculate_max_supply(uint8_t average_delegate_pay_rate = fc::json::from_string("100").as<uint8_t>()) const override;
    uint32_t blockchain_get_block_count() const override;
    std::vector<fbtc::blockchain::account_record> blockchain_list_accounts(const std::string& first_account_name = fc::json::from_string("\"\"").as<std::string>(), uint32_t limit = fc::json::from_string("20").as<uint32_t>()) const override;
    std::vector<fbtc::blockchain::account_record> blockchain_list_recently_updated_accounts() const override;
    std::vector<fbtc::blockchain::account_record> blockchain_list_recently_registered_accounts() const override;
    std::vector<fbtc::blockchain::asset_record> blockchain_list_assets(const std::string& first_symbol = fc::json::from_string("\"\"").as<std::string>(), uint32_t limit = fc::json::from_string("20").as<uint32_t>()) const override;
    std::map<std::string, std::string> blockchain_list_feed_prices() const override;
    std::vector<fbtc::blockchain::burn_record> blockchain_get_account_wall(const std::string& account_name = fc::json::from_string("\"\"").as<std::string>()) const override;
    std::vector<fbtc::blockchain::signed_transaction> blockchain_list_pending_transactions() const override;
    int32_t blockchain_get_pending_transactions_count() const override;
    std::pair<fbtc::blockchain::transaction_id_type, fbtc::blockchain::transaction_record> blockchain_get_transaction(const std::string& transaction_id_prefix, bool exact = fc::json::from_string("false").as<bool>()) const override;
    fc::optional<fbtc::blockchain::block_record> blockchain_get_block(const std::string& block) const override;
    std::map<fbtc::blockchain::transaction_id_type, fbtc::blockchain::transaction_record> blockchain_get_block_transactions(const std::string& block) const override;
    fc::optional<fbtc::blockchain::account_record> blockchain_get_account(const std::string& account) const override;
    std::map<fbtc::blockchain::account_id_type, std::string> blockchain_get_slate(const std::string& slate) const override;
    fbtc::blockchain::balance_record blockchain_get_balance(const fbtc::blockchain::address& balance_id) const override;
    std::unordered_map<fbtc::blockchain::balance_id_type, fbtc::blockchain::balance_record> blockchain_list_balances(const std::string& asset = fc::json::from_string("\"0\"").as<std::string>(), uint32_t limit = fc::json::from_string("20").as<uint32_t>()) const override;
    std::unordered_map<fbtc::blockchain::balance_id_type, fbtc::blockchain::balance_record> blockchain_list_address_balances(const std::string& addr, const fc::time_point& chanced_since = fc::json::from_string("\"1970-1-1T00:00:01\"").as<fc::time_point>()) const override;
    fc::variant_object blockchain_list_address_transactions(const std::string& addr, uint32_t filter_before = fc::json::from_string("\"0\"").as<uint32_t>()) const override;
    std::map<fbtc::blockchain::asset_id_type, fbtc::blockchain::share_type> blockchain_get_account_public_balance(const std::string& account_name) const override;
    std::string blockchain_median_feed_price(const std::string& symbol) const override;
    std::unordered_map<fbtc::blockchain::balance_id_type, fbtc::blockchain::balance_record> blockchain_list_key_balances(const fbtc::blockchain::public_key_type& key) const override;
    fc::optional<fbtc::blockchain::asset_record> blockchain_get_asset(const std::string& asset) const override;
    std::vector<fbtc::blockchain::feed_entry> blockchain_get_feeds_for_asset(const std::string& asset) const override;
    std::vector<fbtc::blockchain::feed_entry> blockchain_get_feeds_from_delegate(const std::string& delegate_name) const override;
    std::vector<fbtc::blockchain::market_order> blockchain_market_list_bids(const std::string& quote_symbol, const std::string& base_symbol, uint32_t limit = fc::json::from_string("\"-1\"").as<uint32_t>()) const override;
    std::vector<fbtc::blockchain::market_order> blockchain_market_list_asks(const std::string& quote_symbol, const std::string& base_symbol, uint32_t limit = fc::json::from_string("\"-1\"").as<uint32_t>()) const override;
    std::vector<fbtc::blockchain::market_order> blockchain_market_list_shorts(const std::string& quote_symbol, uint32_t limit = fc::json::from_string("\"-1\"").as<uint32_t>()) const override;
    std::vector<fbtc::blockchain::market_order> blockchain_market_list_covers(const std::string& quote_symbol, const std::string& base_symbol = fc::json::from_string("\"XTS\"").as<std::string>(), uint32_t limit = fc::json::from_string("\"-1\"").as<uint32_t>()) const override;
    fbtc::blockchain::share_type blockchain_market_get_asset_collateral(const std::string& symbol) const override;
    std::pair<std::vector<fbtc::blockchain::market_order>,std::vector<fbtc::blockchain::market_order>> blockchain_market_order_book(const std::string& quote_symbol, const std::string& base_symbol, uint32_t limit = fc::json::from_string("\"10\"").as<uint32_t>()) const override;
    fbtc::blockchain::market_order blockchain_get_market_order(const std::string& order_id) const override;
    std::map<fbtc::blockchain::order_id_type, fbtc::blockchain::market_order> blockchain_list_address_orders(const std::string& base_symbol, const std::string& quote_symbol, const std::string& account_address, uint32_t limit = fc::json::from_string("\"10\"").as<uint32_t>()) const override;
    std::vector<fbtc::blockchain::order_history_record> blockchain_market_order_history(const std::string& quote_symbol, const std::string& base_symbol, uint32_t skip_count = fc::json::from_string("\"0\"").as<uint32_t>(), uint32_t limit = fc::json::from_string("\"20\"").as<uint32_t>(), const std::string& owner = fc::json::from_string("\"\"").as<std::string>()) const override;
    fbtc::blockchain::market_history_points blockchain_market_price_history(const std::string& quote_symbol, const std::string& base_symbol, const fc::time_point& start_time, const fc::microseconds& duration, const fbtc::blockchain::market_history_key::time_granularity_enum& granularity = fc::json::from_string("\"each_block\"").as<fbtc::blockchain::market_history_key::time_granularity_enum>()) const override;
    std::vector<fbtc::blockchain::account_record> blockchain_list_active_delegates(uint32_t first = fc::json::from_string("0").as<uint32_t>(), uint32_t count = fc::json::from_string("20").as<uint32_t>()) const override;
    std::vector<fbtc::blockchain::account_record> blockchain_list_delegates(uint32_t first = fc::json::from_string("0").as<uint32_t>(), uint32_t count = fc::json::from_string("20").as<uint32_t>()) const override;
    std::vector<fbtc::blockchain::block_record> blockchain_list_blocks(uint32_t max_block_num = fc::json::from_string("-1").as<uint32_t>(), uint32_t limit = fc::json::from_string("20").as<uint32_t>()) override;
    std::vector<std::string> blockchain_list_missing_block_delegates(uint32_t block_number) override;
    std::string blockchain_export_fork_graph(uint32_t start_block = fc::json::from_string("1").as<uint32_t>(), uint32_t end_block = fc::json::from_string("-1").as<uint32_t>(), const std::string& filename = fc::json::from_string("\"\"").as<std::string>()) const override;
    std::map<uint32_t, std::vector<fbtc::blockchain::fork_record>> blockchain_list_forks() const override;
    std::vector<fbtc::blockchain::slot_record> blockchain_get_delegate_slot_records(const std::string& delegate_name, uint32_t limit = fc::json::from_string("\"10\"").as<uint32_t>()) const override;
    std::string blockchain_get_block_signee(const std::string& block) const override;
    std::vector<fbtc::blockchain::string_status_record> blockchain_list_markets() const override;
    std::vector<fbtc::blockchain::market_transaction> blockchain_list_market_transactions(uint32_t block_number) const override;
    fbtc::blockchain::string_status_record blockchain_market_status(const std::string& quote_symbol, const std::string& base_symbol) const override;
    fbtc::blockchain::asset blockchain_unclaimed_genesis() const override;
    bool blockchain_verify_signature(const std::string& signer, const fc::sha256& hash, const fc::ecc::compact_signature& signature) const override;
    void blockchain_broadcast_transaction(const fbtc::blockchain::signed_transaction& trx) override;
    fc::variant_object wallet_get_info() override;
    void wallet_open(const std::string& wallet_name) override;
    std::string wallet_get_account_public_address(const std::string& account_name) const override;
    std::vector<fbtc::wallet::account_address_data> wallet_list_my_addresses() const override;
    void wallet_create(const std::string& wallet_name, const std::string& new_passphrase, const std::string& brain_key = fc::json::from_string("\"\"").as<std::string>(), const std::string& new_passphrase_verify = fc::json::from_string("\"\"").as<std::string>()) override;
    std::string wallet_import_private_key(const std::string& wif_key, const std::string& account_name = fc::json::from_string("null").as<std::string>(), bool create_new_account = fc::json::from_string("false").as<bool>(), bool rescan = fc::json::from_string("false").as<bool>()) override;
    uint32_t wallet_import_bitcoin(const fc::path& wallet_filename, const std::string& passphrase, const std::string& account_name) override;
    uint32_t wallet_import_electrum(const fc::path& wallet_filename, const std::string& passphrase, const std::string& account_name) override;
    void wallet_import_keyhotee(const std::string& firstname, const std::string& middlename, const std::string& lastname, const std::string& brainkey, const std::string& keyhoteeid) override;
    uint32_t wallet_import_keys_from_json(const fc::path& json_filename, const std::string& imported_wallet_passphrase, const std::string& account) override;
    void wallet_close() override;
    void wallet_backup_create(const fc::path& json_filename) const override;
    void wallet_backup_restore(const fc::path& json_filename, const std::string& wallet_name, const std::string& imported_wallet_passphrase) override;
    void wallet_export_keys(const fc::path& json_filename) const override;
    bool wallet_set_automatic_backups(bool enabled) override;
    uint32_t wallet_set_transaction_expiration_time(uint32_t seconds) override;
    std::vector<fbtc::wallet::pretty_transaction> wallet_account_transaction_history(const std::string& account_name = fc::json::from_string("\"\"").as<std::string>(), const std::string& asset_symbol = fc::json::from_string("\"\"").as<std::string>(), int32_t limit = fc::json::from_string("0").as<int32_t>(), uint32_t start_block_num = fc::json::from_string("0").as<uint32_t>(), uint32_t end_block_num = fc::json::from_string("-1").as<uint32_t>()) const override;
    fbtc::wallet::account_balance_summary_type wallet_account_historic_balance(const fc::time_point& time, const std::string& account_name = fc::json::from_string("\"\"").as<std::string>()) const override;
    std::set<fbtc::wallet::pretty_transaction_experimental> wallet_transaction_history_experimental(const std::string& account_name = fc::json::from_string("\"\"").as<std::string>()) const override;
    void wallet_remove_transaction(const std::string& transaction_id) override;
    std::map<fbtc::blockchain::transaction_id_type, fc::exception> wallet_get_pending_transaction_errors(const std::string& filename = fc::json::from_string("\"\"").as<std::string>()) const override;
    void wallet_lock() override;
    void wallet_unlock(uint32_t timeout, const std::string& passphrase) override;
    void wallet_change_passphrase(const std::string& new_passphrase, const std::string& new_passphrase_verify = fc::json::from_string("\"\"").as<std::string>()) override;
    std::vector<std::string> wallet_list() const override;
    fbtc::blockchain::public_key_type wallet_account_create(const std::string& account_name) override;
    std::vector<fbtc::wallet::wallet_contact_record> wallet_list_contacts() const override;
    fbtc::wallet::owallet_contact_record wallet_get_contact(const std::string& contact) const override;
    fbtc::wallet::wallet_contact_record wallet_add_contact(const std::string& contact, const std::string& label = fc::json::from_string("\"\"").as<std::string>()) override;
    fbtc::wallet::owallet_contact_record wallet_remove_contact(const std::string& contact) override;
    std::vector<fbtc::wallet::wallet_approval_record> wallet_list_approvals() const override;
    fbtc::wallet::owallet_approval_record wallet_get_approval(const std::string& approval) const override;
    fbtc::wallet::wallet_approval_record wallet_approve(const std::string& name, int8_t approval = fc::json::from_string("1").as<int8_t>()) override;
    fbtc::wallet::wallet_transaction_record wallet_burn(const std::string& amount_to_burn, const std::string& asset_symbol, const std::string& from_account_name, const std::string& for_or_against, const std::string& to_account_name, const std::string& public_message = fc::json::from_string("\"\"").as<std::string>(), bool anonymous = fc::json::from_string("\"false\"").as<bool>()) override;
    std::string wallet_address_create(const std::string& account_name, const std::string& label = fc::json::from_string("\"\"").as<std::string>(), int32_t legacy_network_byte = fc::json::from_string("-1").as<int32_t>()) override;
    fbtc::wallet::wallet_transaction_record wallet_transfer_to_address(const std::string& amount_to_transfer, const std::string& asset_symbol, const std::string& from_account_name, const std::string& to_address, const std::string& memo_message = fc::json::from_string("\"\"").as<std::string>(), const fbtc::wallet::vote_strategy& strategy = fc::json::from_string("\"vote_recommended\"").as<fbtc::wallet::vote_strategy>()) override;
    fbtc::wallet::wallet_transaction_record wallet_transfer_to_genesis_multisig_address(const std::string& amount_to_transfer, const std::string& asset_symbol, const std::string& from_account_name, const std::string& to_address, const std::string& memo_message = fc::json::from_string("\"\"").as<std::string>(), const fbtc::wallet::vote_strategy& strategy = fc::json::from_string("\"vote_recommended\"").as<fbtc::wallet::vote_strategy>()) override;
    fbtc::wallet::wallet_transaction_record wallet_transfer_to_address_from_file(const std::string& from_account_name, const std::string& file_path, const std::string& memo_message = fc::json::from_string("\"\"").as<std::string>(), const fbtc::wallet::vote_strategy& strategy = fc::json::from_string("\"vote_recommended\"").as<fbtc::wallet::vote_strategy>()) override;
    fbtc::wallet::wallet_transaction_record wallet_transfer_to_genesis_multisig_address_from_file(const std::string& from_account_name, const std::string& file_path, const std::string& memo_message = fc::json::from_string("\"\"").as<std::string>(), const fbtc::wallet::vote_strategy& strategy = fc::json::from_string("\"vote_recommended\"").as<fbtc::wallet::vote_strategy>()) override;
    bool wallet_check_passphrase(const std::string& passphrase) override;
    fbtc::wallet::wallet_transaction_record wallet_transfer(const std::string& amount_to_transfer, const std::string& asset_symbol, const std::string& from_account_name, const std::string& recipient, const std::string& memo_message = fc::json::from_string("\"\"").as<std::string>(), const fbtc::wallet::vote_strategy& strategy = fc::json::from_string("\"vote_recommended\"").as<fbtc::wallet::vote_strategy>()) override;
    fbtc::blockchain::address wallet_multisig_get_balance_id(const std::string& symbol, uint32_t m, const std::vector<fbtc::blockchain::address>& addresses) const override;
    fbtc::wallet::wallet_transaction_record wallet_multisig_deposit(const std::string& amount, const std::string& symbol, const std::string& from_name, uint32_t m, const std::vector<fbtc::blockchain::address>& addresses, const fbtc::wallet::vote_strategy& strategy = fc::json::from_string("\"vote_none\"").as<fbtc::wallet::vote_strategy>()) override;
    fbtc::wallet::transaction_builder wallet_withdraw_from_address(const std::string& amount, const std::string& symbol, const fbtc::blockchain::address& from_address, const std::string& to, const fbtc::wallet::vote_strategy& strategy = fc::json::from_string("\"vote_none\"").as<fbtc::wallet::vote_strategy>(), bool sign_and_broadcast = fc::json::from_string("true").as<bool>(), const std::string& builder_path = fc::json::from_string("\"\"").as<std::string>()) override;
    fbtc::wallet::transaction_builder wallet_receive_genesis_multisig_blanace(const fbtc::blockchain::address& from_address, const std::string& from_address_redeemscript, const std::string& to, const fbtc::wallet::vote_strategy& strategy = fc::json::from_string("\"vote_none\"").as<fbtc::wallet::vote_strategy>(), bool sign_and_broadcast = fc::json::from_string("true").as<bool>(), const std::string& builder_path = fc::json::from_string("\"\"").as<std::string>()) override;
    fbtc::wallet::transaction_builder wallet_withdraw_from_legacy_address(const std::string& amount, const std::string& symbol, const fbtc::blockchain::pts_address& from_address, const std::string& to, const fbtc::wallet::vote_strategy& strategy = fc::json::from_string("\"vote_none\"").as<fbtc::wallet::vote_strategy>(), bool sign_and_broadcast = fc::json::from_string("true").as<bool>(), const std::string& builder_path = fc::json::from_string("\"\"").as<std::string>()) const override;
    fbtc::wallet::transaction_builder wallet_multisig_withdraw_start(const std::string& amount, const std::string& symbol, const fbtc::blockchain::address& from, const fbtc::blockchain::address& to_address, const fbtc::wallet::vote_strategy& strategy = fc::json::from_string("\"vote_none\"").as<fbtc::wallet::vote_strategy>(), const std::string& builder_path = fc::json::from_string("\"\"").as<std::string>()) const override;
    fbtc::wallet::transaction_builder wallet_builder_add_signature(const fbtc::wallet::transaction_builder& builder, bool broadcast = fc::json::from_string("false").as<bool>()) override;
    fbtc::wallet::transaction_builder wallet_builder_file_add_signature(const std::string& builder_path = fc::json::from_string("\"\"").as<std::string>(), bool broadcast = fc::json::from_string("false").as<bool>()) override;
    fbtc::wallet::wallet_transaction_record wallet_release_escrow(const std::string& pay_fee_with_account_name, const fbtc::blockchain::address& escrow_balance_id, const std::string& released_by_account, const std::string& amount_to_sender = fc::json::from_string("0").as<std::string>(), const std::string& amount_to_receiver = fc::json::from_string("0").as<std::string>()) override;
    fbtc::wallet::wallet_transaction_record wallet_transfer_from_with_escrow(const std::string& amount_to_transfer, const std::string& asset_symbol, const std::string& paying_account_name, const std::string& from_account_name, const std::string& to_account_name, const std::string& escrow_account_name, const fbtc::blockchain::digest_type& agreement = fc::json::from_string("\"\"").as<fbtc::blockchain::digest_type>(), const std::string& memo_message = fc::json::from_string("\"\"").as<std::string>(), const fbtc::wallet::vote_strategy& strategy = fc::json::from_string("\"vote_recommended\"").as<fbtc::wallet::vote_strategy>()) override;
    void wallet_rescan_blockchain(uint32_t start_block_num = fc::json::from_string("0").as<uint32_t>(), uint32_t limit = fc::json::from_string("-1").as<uint32_t>(), bool scan_in_background = fc::json::from_string("true").as<bool>()) override;
    void wallet_cancel_scan() override;
    fbtc::wallet::wallet_transaction_record wallet_get_transaction(const std::string& transaction_id) override;
    fbtc::wallet::wallet_transaction_record wallet_scan_transaction(const std::string& transaction_id, bool overwrite_existing = fc::json::from_string("false").as<bool>()) override;
    void wallet_scan_transaction_experimental(const std::string& transaction_id, bool overwrite_existing = fc::json::from_string("false").as<bool>()) override;
    void wallet_add_transaction_note_experimental(const std::string& transaction_id, const std::string& note) override;
    void wallet_rebroadcast_transaction(const std::string& transaction_id) override;
    fbtc::wallet::wallet_transaction_record wallet_account_register(const std::string& account_name, const std::string& pay_from_account, const fc::variant& public_data = fc::json::from_string("null").as<fc::variant>(), uint8_t delegate_pay_rate = fc::json::from_string("-1").as<uint8_t>(), const std::string& account_type = fc::json::from_string("\"titan_account\"").as<std::string>()) override;
    void wallet_set_custom_data(const fbtc::wallet::wallet_record_type_enum& type, const std::string& item, const fc::variant_object& custom_data) override;
    fbtc::wallet::wallet_transaction_record wallet_account_update_registration(const std::string& account_name, const std::string& pay_from_account, const fc::variant& public_data = fc::json::from_string("null").as<fc::variant>(), uint8_t delegate_pay_rate = fc::json::from_string("-1").as<uint8_t>()) override;
    fbtc::wallet::wallet_transaction_record wallet_account_update_active_key(const std::string& account_to_update, const std::string& pay_from_account, const std::string& new_active_key = fc::json::from_string("\"\"").as<std::string>()) override;
    std::vector<fbtc::wallet::wallet_account_record> wallet_list_accounts() const override;
    fbtc::wallet::owallet_account_record wallet_get_account(const std::string& account) const override;
    void wallet_account_rename(const std::string& current_account_name, const std::string& new_account_name) override;
    fbtc::wallet::wallet_transaction_record wallet_mia_create(const std::string& payer_account, const std::string& symbol, const std::string& name, const std::string& description, const std::string& max_divisibility) override;
    fbtc::wallet::wallet_transaction_record wallet_uia_create(const std::string& issuer_account, const std::string& symbol, const std::string& name, const std::string& description, const std::string& max_supply_with_trailing_decimals) override;
    fbtc::wallet::wallet_transaction_record wallet_uia_issue(const std::string& asset_amount, const std::string& asset_symbol, const std::string& recipient, const std::string& memo_message = fc::json::from_string("\"\"").as<std::string>()) override;
    fbtc::wallet::wallet_transaction_record wallet_uia_issue_to_addresses(const std::string& symbol, const std::map<std::string, fbtc::blockchain::share_type>& addresses) override;
    fbtc::wallet::wallet_transaction_record wallet_uia_collect_fees(const std::string& asset_symbol, const std::string& recipient, const std::string& memo_message = fc::json::from_string("\"\"").as<std::string>()) override;
    fbtc::wallet::wallet_transaction_record wallet_uia_update_description(const std::string& paying_account, const std::string& asset_symbol, const std::string& name = fc::json::from_string("\"\"").as<std::string>(), const std::string& description = fc::json::from_string("\"\"").as<std::string>(), const fc::variant& public_data = fc::json::from_string("null").as<fc::variant>()) override;
    fbtc::wallet::wallet_transaction_record wallet_uia_update_supply(const std::string& paying_account, const std::string& asset_symbol, const std::string& max_supply_with_trailing_decimals) override;
    fbtc::wallet::wallet_transaction_record wallet_uia_update_fees(const std::string& paying_account, const std::string& asset_symbol, const std::string& withdrawal_fee = fc::json::from_string("\"\"").as<std::string>(), const std::string& market_fee_rate = fc::json::from_string("\"\"").as<std::string>()) override;
    fbtc::wallet::wallet_transaction_record wallet_uia_update_active_flags(const std::string& paying_account, const std::string& asset_symbol, const fbtc::blockchain::asset_record::flag_enum& flag, bool enable_instead_of_disable) override;
    fbtc::wallet::wallet_transaction_record wallet_uia_update_authority_permissions(const std::string& paying_account, const std::string& asset_symbol, const fbtc::blockchain::asset_record::flag_enum& permission, bool add_instead_of_remove) override;
    fbtc::wallet::wallet_transaction_record wallet_uia_update_whitelist(const std::string& paying_account, const std::string& asset_symbol, const std::string& account_name, bool add_to_whitelist) override;
    fbtc::wallet::wallet_transaction_record wallet_uia_retract_balance(const fbtc::blockchain::address& balance_id, const std::string& account_name) override;
    std::vector<fbtc::wallet::escrow_summary> wallet_escrow_summary(const std::string& account_name = fc::json::from_string("\"\"").as<std::string>()) const override;
    fbtc::wallet::account_balance_summary_type wallet_account_balance(const std::string& account_name = fc::json::from_string("\"\"").as<std::string>()) const override;
    fbtc::wallet::account_balance_id_summary_type wallet_account_balance_ids(const std::string& account_name = fc::json::from_string("\"\"").as<std::string>()) const override;
    fbtc::wallet::account_extended_balance_type wallet_account_balance_extended(const std::string& account_name = fc::json::from_string("\"\"").as<std::string>()) const override;
    fbtc::wallet::account_vesting_balance_summary_type wallet_account_vesting_balances(const std::string& account_name = fc::json::from_string("\"\"").as<std::string>()) const override;
    fbtc::wallet::account_balance_summary_type wallet_account_yield(const std::string& account_name = fc::json::from_string("\"\"").as<std::string>()) const override;
    std::vector<fbtc::wallet::public_key_summary> wallet_account_list_public_keys(const std::string& account_name) override;
    fbtc::wallet::wallet_transaction_record wallet_delegate_withdraw_pay(const std::string& delegate_name, const std::string& to_account_name, const std::string& amount_to_withdraw) override;
    fbtc::blockchain::asset wallet_set_transaction_fee(const std::string& fee) override;
    fbtc::blockchain::asset wallet_get_transaction_fee(const std::string& symbol = fc::json::from_string("\"\"").as<std::string>()) override;
    fbtc::wallet::wallet_transaction_record wallet_market_submit_bid(const std::string& from_account_name, const std::string& quantity, const std::string& quantity_symbol, const std::string& base_price, const std::string& base_symbol, bool allow_stupid_bid = fc::json::from_string("\"false\"").as<bool>()) override;
    fbtc::wallet::wallet_transaction_record wallet_market_submit_ask(const std::string& from_account_name, const std::string& sell_quantity, const std::string& sell_quantity_symbol, const std::string& ask_price, const std::string& ask_price_symbol, bool allow_stupid_ask = fc::json::from_string("\"false\"").as<bool>()) override;
    fbtc::wallet::wallet_transaction_record wallet_market_submit_short(const std::string& from_account_name, const std::string& short_collateral, const std::string& collateral_symbol, const std::string& interest_rate, const std::string& quote_symbol, const std::string& short_price_limit = fc::json::from_string("0").as<std::string>()) override;
    fbtc::wallet::wallet_transaction_record wallet_market_cover(const std::string& from_account_name, const std::string& quantity, const std::string& quantity_symbol, const fbtc::blockchain::order_id_type& cover_id) override;
    fbtc::wallet::wallet_transaction_record wallet_market_batch_update(const std::vector<fbtc::blockchain::order_id_type>& cancel_order_ids, const std::vector<fbtc::wallet::order_description>& new_orders, bool sign) override;
    fbtc::wallet::wallet_transaction_record wallet_market_add_collateral(const std::string& from_account_name, const fbtc::blockchain::order_id_type& cover_id, const std::string& real_quantity_collateral_to_add) override;
    std::map<fbtc::blockchain::order_id_type, fbtc::blockchain::market_order> wallet_market_order_list(const std::string& base_symbol, const std::string& quote_symbol, uint32_t limit = fc::json::from_string("-1").as<uint32_t>(), const std::string& account_name = fc::json::from_string("\"\"").as<std::string>()) override;
    std::map<fbtc::blockchain::order_id_type, fbtc::blockchain::market_order> wallet_account_order_list(const std::string& account_name = fc::json::from_string("\"\"").as<std::string>(), uint32_t limit = fc::json::from_string("-1").as<uint32_t>()) override;
    fbtc::wallet::wallet_transaction_record wallet_market_cancel_order(const fbtc::blockchain::order_id_type& order_id) override;
    fbtc::wallet::wallet_transaction_record wallet_market_cancel_orders(const std::vector<fbtc::blockchain::order_id_type>& order_ids) override;
    fc::optional<std::string> wallet_dump_private_key(const std::string& input) const override;
    fc::optional<std::string> wallet_dump_account_private_key(const std::string& account_name, const fbtc::wallet::account_key_type& key_type) const override;
    fbtc::wallet::account_vote_summary_type wallet_account_vote_summary(const std::string& account_name = fc::json::from_string("\"\"").as<std::string>()) const override;
    void wallet_set_setting(const std::string& name, const fc::variant& value) override;
    fc::optional<fc::variant> wallet_get_setting(const std::string& name) override;
    void wallet_delegate_set_block_production(const std::string& delegate_name, bool enabled) override;
    bool wallet_set_transaction_scanning(bool enabled) override;
    fc::ecc::compact_signature wallet_sign_hash(const std::string& signer, const fc::sha256& hash) override;
    std::string wallet_login_start(const std::string& server_account) override;
    fc::variant wallet_login_finish(const fbtc::blockchain::public_key_type& server_key, const fbtc::blockchain::public_key_type& client_key, const fc::ecc::compact_signature& client_signature) override;
    fbtc::wallet::transaction_builder wallet_balance_set_vote_info(const fbtc::blockchain::address& balance_id, const std::string& voter_address = fc::json::from_string("\"\"").as<std::string>(), const fbtc::wallet::vote_strategy& strategy = fc::json::from_string("\"vote_all\"").as<fbtc::wallet::vote_strategy>(), bool sign_and_broadcast = fc::json::from_string("\"true\"").as<bool>(), const std::string& builder_path = fc::json::from_string("\"\"").as<std::string>()) override;
    fbtc::wallet::wallet_transaction_record wallet_publish_slate(const std::string& publishing_account_name, const std::string& paying_account_name = fc::json::from_string("\"\"").as<std::string>()) override;
    fbtc::wallet::wallet_transaction_record wallet_publish_version(const std::string& publishing_account_name, const std::string& paying_account_name = fc::json::from_string("\"\"").as<std::string>()) override;
    fbtc::wallet::wallet_transaction_record wallet_collect_genesis_balances(const std::string& account_name) override;
    fbtc::wallet::wallet_transaction_record wallet_collect_vested_balances(const std::string& account_name) override;
    fbtc::wallet::wallet_transaction_record wallet_delegate_update_signing_key(const std::string& authorizing_account_name, const std::string& delegate_name, const fbtc::blockchain::public_key_type& signing_key) override;
    int32_t wallet_recover_accounts(int32_t accounts_to_recover, int32_t maximum_number_of_attempts = fc::json::from_string("1000").as<int32_t>()) override;
    fbtc::wallet::wallet_transaction_record wallet_recover_titan_deposit_info(const std::string& transaction_id_prefix, const std::string& recipient_account = fc::json::from_string("\"\"").as<std::string>()) override;
    fc::optional<fc::variant_object> wallet_verify_titan_deposit(const std::string& transaction_id_prefix) override;
    fbtc::wallet::wallet_transaction_record wallet_publish_price_feed(const std::string& delegate_account, const std::string& price, const std::string& asset_symbol) override;
    fbtc::wallet::wallet_transaction_record wallet_publish_feeds(const std::string& delegate_account, const std::map<std::string, std::string>& symbol_to_price_map) override;
    std::vector<std::pair<std::string, fbtc::wallet::wallet_transaction_record>> wallet_publish_feeds_multi_experimental(const std::map<std::string, std::string>& symbol_to_price_map) override;
    void wallet_repair_records(const std::string& collecting_account_name = fc::json::from_string("\"\"").as<std::string>()) override;
    int32_t wallet_regenerate_keys(const std::string& account_name, uint32_t max_key_number) override;
    fbtc::wallet::wallet_transaction_record wallet_account_retract(const std::string& account_to_retract, const std::string& pay_from_account) override;
    std::string wallet_generate_brain_seed() const override;
    fc::variant_object fetch_welcome_package(const fc::variant_object& arguments) override;
    bool request_register_account(const fbtc::blockchain::account_record& account) override;
    bool approve_register_account(const std::string& account_salt, const std::string& paying_account_name) override;
    void debug_start_simulated_time(const fc::time_point& new_simulated_time) override;
    void debug_advance_time(int32_t delta_time_seconds, const std::string& unit = fc::json::from_string("\"seconds\"").as<std::string>()) override;
    void debug_trap(uint32_t block_number) override;
    void debug_wait(uint32_t wait_time) const override;
    void debug_wait_for_block_by_number(uint32_t block_number, const std::string& type = fc::json::from_string("\"absolute\"").as<std::string>()) override;
    void debug_wait_block_interval(uint32_t wait_time_in_block_intervals) const override;
    void debug_enable_output(bool enable_flag) override;
    void debug_filter_output_for_tests(bool enable_flag) override;
    void debug_update_logging_config() override;
    fc::variant_object debug_get_call_statistics() const override;
    std::string debug_get_client_name() const override;
    fc::variants debug_deterministic_private_keys(int32_t start = fc::json::from_string("\"-1\"").as<int32_t>(), int32_t count = fc::json::from_string("\"1\"").as<int32_t>(), const std::string& prefix = fc::json::from_string("\"\"").as<std::string>(), bool import = fc::json::from_string("\"false\"").as<bool>(), const std::string& account_name = fc::json::from_string("null").as<std::string>(), bool create_new_account = fc::json::from_string("false").as<bool>(), bool rescan = fc::json::from_string("false").as<bool>()) override;
    void debug_stop_before_block(uint32_t block_number) override;
    void debug_verify_market_matching(bool enable_flag) override;
    fc::variants debug_list_matching_errors() const override;
  };

} } // end namespace fbtc::rpc_stubs
