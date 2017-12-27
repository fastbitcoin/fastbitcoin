#include <fbtc/blockchain/account_operations.hpp>
#include <fbtc/blockchain/asset_operations.hpp>
#include <fbtc/blockchain/balance_operations.hpp>
#include <fbtc/blockchain/data_operations.hpp>
#include <fbtc/blockchain/feed_operations.hpp>
#include <fbtc/blockchain/market_operations.hpp>
#include <fbtc/blockchain/operation_factory.hpp>
#include <fbtc/blockchain/operations.hpp>
#include <fbtc/blockchain/slate_operations.hpp>

#include <fc/io/raw_variant.hpp>
#include <fc/reflect/variant.hpp>

namespace fbtc { namespace blockchain {

    const operation_type_enum withdraw_operation::type                  = withdraw_op_type;
    const operation_type_enum deposit_operation::type                   = deposit_op_type;

    const operation_type_enum register_account_operation::type          = register_account_op_type;
    const operation_type_enum update_account_operation::type            = update_account_op_type;
    const operation_type_enum withdraw_pay_operation::type              = withdraw_pay_op_type;

    const operation_type_enum create_asset_operation::type              = create_asset_op_type;
    const operation_type_enum issue_asset_operation::type               = issue_asset_op_type;

    const operation_type_enum asset_update_properties_operation::type   = asset_update_properties_op_type;
    const operation_type_enum asset_update_permissions_operation::type  = asset_update_permissions_op_type;
    const operation_type_enum asset_update_whitelist_operation::type    = asset_update_whitelist_op_type;

    const operation_type_enum bid_operation::type                       = bid_op_type;
    const operation_type_enum ask_operation::type                       = ask_op_type;
    const operation_type_enum short_operation::type                     = short_op_v2_type;
    const operation_type_enum short_operation_v1::type                  = short_op_type;
    const operation_type_enum cover_operation::type                     = cover_op_type;
    const operation_type_enum add_collateral_operation::type            = add_collateral_op_type;

    const operation_type_enum define_slate_operation::type              = define_slate_op_type;

    const operation_type_enum update_feed_operation::type               = update_feed_op_type;

    const operation_type_enum burn_operation::type                      = burn_op_type;

    const operation_type_enum release_escrow_operation::type            = release_escrow_op_type;

    const operation_type_enum update_signing_key_operation::type        = update_signing_key_op_type;
    const operation_type_enum update_balance_vote_operation::type       = update_balance_vote_op_type;
    const operation_type_enum limit_fee_operation::type                 = limit_fee_op_type;

    const operation_type_enum data_operation::type                      = data_op_type;

    static bool first_chain = []() -> bool
    {
        fbtc::blockchain::operation_factory::instance().register_operation<withdraw_operation>();
        fbtc::blockchain::operation_factory::instance().register_operation<deposit_operation>();

        fbtc::blockchain::operation_factory::instance().register_operation<register_account_operation>();
        fbtc::blockchain::operation_factory::instance().register_operation<update_account_operation>();
        fbtc::blockchain::operation_factory::instance().register_operation<withdraw_pay_operation>();

        fbtc::blockchain::operation_factory::instance().register_operation<create_asset_operation>();
        fbtc::blockchain::operation_factory::instance().register_operation<issue_asset_operation>();
        fbtc::blockchain::operation_factory::instance().register_operation<asset_update_properties_operation>();
        fbtc::blockchain::operation_factory::instance().register_operation<asset_update_permissions_operation>();
        fbtc::blockchain::operation_factory::instance().register_operation<asset_update_whitelist_operation>();

        fbtc::blockchain::operation_factory::instance().register_operation<bid_operation>();
        fbtc::blockchain::operation_factory::instance().register_operation<ask_operation>();
        fbtc::blockchain::operation_factory::instance().register_operation<short_operation>();
        fbtc::blockchain::operation_factory::instance().register_operation<short_operation_v1>();
        fbtc::blockchain::operation_factory::instance().register_operation<cover_operation>();
        fbtc::blockchain::operation_factory::instance().register_operation<add_collateral_operation>();

        fbtc::blockchain::operation_factory::instance().register_operation<define_slate_operation>();

        fbtc::blockchain::operation_factory::instance().register_operation<update_feed_operation>();

        fbtc::blockchain::operation_factory::instance().register_operation<burn_operation>();

        fbtc::blockchain::operation_factory::instance().register_operation<release_escrow_operation>();

        fbtc::blockchain::operation_factory::instance().register_operation<update_signing_key_operation>();
        fbtc::blockchain::operation_factory::instance().register_operation<update_balance_vote_operation>();
        fbtc::blockchain::operation_factory::instance().register_operation<limit_fee_operation>();

        fbtc::blockchain::operation_factory::instance().register_operation<data_operation>();

        return true;
    }();

    operation_factory& operation_factory::instance()
    { try {
        static std::unique_ptr<operation_factory> inst( new operation_factory() );
        return *inst;
    } FC_CAPTURE_AND_RETHROW() }

    void operation_factory::to_variant( const fbtc::blockchain::operation& in, fc::variant& output )
    { try {
        auto converter_itr = _converters.find( in.type.value );
        FC_ASSERT( converter_itr != _converters.end() );
        converter_itr->second->to_variant( in, output );
    } FC_CAPTURE_AND_RETHROW() }

    void operation_factory::from_variant( const fc::variant& in, fbtc::blockchain::operation& output )
    { try {
        auto obj = in.get_object();

        if( obj[ "type" ].as_string() == "define_delegate_slate_op_type" )
        {
            output.type = define_slate_op_type;
            return;
        }

        output.type = obj["type"].as<operation_type_enum>();

        auto converter_itr = _converters.find( output.type.value );
        FC_ASSERT( converter_itr != _converters.end() );
        converter_itr->second->from_variant( in, output );
    } FC_CAPTURE_AND_RETHROW( (in) ) }

} } // fbtc::blockchain

namespace fc
{
    void to_variant( const fbtc::blockchain::operation& var, variant& vo )
    {
        fbtc::blockchain::operation_factory::instance().to_variant( var, vo );
    }

    void from_variant( const variant& var, fbtc::blockchain::operation& vo )
    {
        fbtc::blockchain::operation_factory::instance().from_variant( var, vo );
    }
}
