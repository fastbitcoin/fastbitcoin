
#pragma once

#include <fbtc/api/global_api_logger.hpp>

#if FBTC_GLOBAL_API_LOG

#include <fc/io/iostream.hpp>
#include <fc/thread/mutex.hpp>
#include <fc/variant.hpp>

namespace fbtc { namespace client {

class stream_api_logger : public fbtc::api::api_logger
{
public:
    stream_api_logger(fc::ostream_ptr output);
    virtual ~stream_api_logger();

    virtual void log_call_started ( uint64_t call_id, const fbtc::api::common_api* target, const fc::string& name, const fc::variants& args ) override;
    virtual void log_call_finished( uint64_t call_id, const fbtc::api::common_api* target, const fc::string& name, const fc::variants& args, const fc::variant& result ) override;
    
    virtual void close();
    
    fc::ostream_ptr output;
    fc::mutex output_mutex;
    bool is_first_item;
    bool is_closed;
};

} } // end namespace fbtc::client

#endif
