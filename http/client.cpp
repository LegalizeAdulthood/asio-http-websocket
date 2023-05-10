//
// Copyright (c) 2016-2019 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/boostorg/beast
//

//------------------------------------------------------------------------------
//
// Example: HTTP SSL client, asynchronous
//
//------------------------------------------------------------------------------
// Adapted by Richard Thomson, Utah C++ Programmers.

//#define USE_SSL
#ifdef USE_SSL
#include "../common/root_certificates.hpp"
#endif

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#ifdef USE_SSL
#include <boost/beast/ssl.hpp>
#endif
#include <boost/beast/version.hpp>
#include <boost/asio/strand.hpp>

#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>

#include <comicsdb.h>
#include <json.h>

namespace ComicsDb = comicsdb::v2;

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace net = boost::asio;            // from <boost/asio.hpp>
#ifdef USE_SSL
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
#endif
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>

//------------------------------------------------------------------------------

namespace comicClient
{

struct State
{
    ComicsDb::ComicDb       &db;
    net::io_context         &ioc;
#ifdef USE_SSL
    ssl::context            &ctx;
#endif
    int                      httpVersion;
    std::vector<std::size_t> ids;
};

// Report a failure
void
fail(beast::error_code ec, char const* what)
{
    std::cerr << what << ": " << ec.message() << "\n";
}

// Performs an HTTP GET and prints the response
class session : public std::enable_shared_from_this<session>
{
public:
    explicit session(net::any_io_executor ex, State &state) :
        state_(state),
        resolver_(ex),
#ifdef USE_SSL
        stream_(ex, state.ctx)
#else
        stream_(ex)
#endif
    {
    }

    // Start the asynchronous operation
    void run(char const *host, char const *service, char const *path)
    {
#ifdef USE_SSL
        // Set SNI Hostname (many hosts need this to handshake successfully)
        if(! SSL_set_tlsext_host_name(stream_.native_handle(), host))
        {
            beast::error_code ec{static_cast<int>(::ERR_get_error()), net::error::get_ssl_category()};
            std::cerr << ec.message() << "\n";
            return;
        }
#endif

        // Set up an HTTP GET request message
        req_.version(state_.httpVersion);
        req_.method(http::verb::get);
        req_.target(path);
        req_.set(http::field::host, host);
        req_.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
        std::cout << "Requesting comic " << path << '\n';

        // Look up the domain name
        resolver_.async_resolve(
            host,
            service,

            beast::bind_front_handler(
                &session::on_resolve,
                shared_from_this()));
    }

    void
    on_resolve(
        beast::error_code ec,
        tcp::resolver::results_type results)
    {
        if(ec)
            return fail(ec, "resolve");

        // Set a timeout on the operation
        beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));

        // Make the connection on the IP address we get from a lookup
        beast::get_lowest_layer(stream_).async_connect(
            results,
            beast::bind_front_handler(
                &session::on_connect,
                shared_from_this()));
    }

    void
    on_connect(beast::error_code ec, tcp::resolver::results_type::endpoint_type)
    {
        if(ec)
            return fail(ec, "connect");

#ifdef USE_SSL
        // Perform the SSL handshake
        stream_.async_handshake(
            ssl::stream_base::client,
            beast::bind_front_handler(
                &session::on_handshake,
                shared_from_this()));
#else
        do_write();
#endif
    }

    void
    on_handshake(beast::error_code ec)
    {
        if(ec)
            return fail(ec, "handshake");

        do_write();
    }

    void do_write()
    {
        // Set a timeout on the operation
        beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));

        // Send the HTTP request to the remote host
        http::async_write(stream_, req_,
            beast::bind_front_handler(
                &session::on_write,
                shared_from_this()));
    }

    void
    on_write(
        beast::error_code ec,
        std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);

        if(ec)
            return fail(ec, "write");

        // Receive the HTTP response
        http::async_read(stream_, buffer_, res_,
            beast::bind_front_handler(
                &session::on_read,
                shared_from_this()));
    }

    void
    on_read(
        beast::error_code ec,
        std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);

        if(ec)
            return fail(ec, "read");

        try
        {
            size_t id = createComic(state_.db, ComicsDb::fromJson(res_.body()));
            std::cout << "Received remote comic: " << res_.body() << '\n';
            std::cout << "Created local comic with id " << id << '\n';
            state_.ids.push_back(id);
        }
        catch (...)
        {
            std::cerr << "Creating comic failed\n";
        }

        // Set a timeout on the operation
        beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));

#ifdef USE_SSL
        // Gracefully close the stream
        stream_.async_shutdown(
            beast::bind_front_handler(
                &session::on_shutdown,
                shared_from_this()));
#endif
    }

    void
    on_shutdown(beast::error_code ec)
    {
        if(ec == net::error::eof)
        {
            // Rationale:
            // http://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
            ec = {};
        }
        if(ec)
            return fail(ec, "shutdown");

        // If we get here then the connection is closed gracefully
    }

private:
    State &state_;
    tcp::resolver resolver_;
#ifdef USE_SSL
    beast::ssl_stream<beast::tcp_stream> stream_;
#else
    beast::tcp_stream stream_;
#endif
    beast::flat_buffer buffer_; // (Must persist between reads)
    http::request<http::empty_body> req_;
    http::response<http::string_body> res_;
};

int run( const char *host, const char *service, int version )
{
    ComicsDb::ComicDb db;

    // The io_context is required for all I/O
    net::io_context ioc;

#ifdef USE_SSL
    // The SSL context is required, and holds certificates
    ssl::context ctx{ssl::context::tlsv12_client};

    // This holds the root certificate used for verification
    load_root_certificates(ctx);

    // Verify the remote server's certificate
    ctx.set_verify_mode(ssl::verify_peer);
    ctx.set_default_verify_paths();
#endif

#ifdef USE_SSL
    State state{db, ioc, ctx, version};
#else
    State state{db, ioc, version};
#endif

    // Launch the asynchronous operation
    // The session is constructed with a strand to
    // ensure that handlers do not execute concurrently.
    for (const char *path : {"/comic/1", "/comic/0"})
        std::make_shared<session>(net::make_strand(ioc), state)->run(host, service, path);

    // Run the I/O service. The call will return when
    // the get operation is complete.
    ioc.run();

    for(auto id : state.ids)
    {
        std::cout << "Comic " << id << ": " << toJson(readComic(db, id)) << '\n';
    }

    return EXIT_SUCCESS;
}

} // namespace comicClient

//------------------------------------------------------------------------------

int main(int argc, char** argv)
{
    // Check command line arguments.
    if(argc != 3 && argc != 4)
    {
        std::cerr <<
            "Usage: " << argv[0] << " <host> <port> [<HTTP version: 1.0 or 1.1(default)>]\n" <<
            "Example:\n" <<
            "    " << argv[0] << " www.example.com 443\n" <<
            "    " << argv[0] << " www.example.com 443 1.0\n";
        return EXIT_FAILURE;
    }
    auto const host = argv[1];
    auto const service = argv[2];
    int version = argc == 5 && !std::strcmp("1.0", argv[4]) ? 10 : 11;

    return comicClient::run(host, service, version);
}
