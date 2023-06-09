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
// Example: HTTP flex server (plain and SSL), asynchronous
//
//------------------------------------------------------------------------------
// Adapted by Richard Thomson, Utah C++ Programmers.

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/strand.hpp>
#include <boost/config.hpp>

#include <algorithm>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <regex>
#include <string>
#include <thread>
#include <vector>

#include "../common/server_certificate.hpp"

#include <comicsdb.h>
#include <json.h>

namespace ComicsDb = comicsdb::v2;

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace net = boost::asio;            // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>

namespace comicServer
{

struct State
{
    ComicsDb::ComicDb &db;
    net::io_context   &ioc;
    ssl::context      &ctx;
};

template <class Body, class Allocator>
using Request = http::request<Body, http::basic_fields<Allocator>>;
using Response = http::response<http::string_body>;

// Returns a bad request response
template <class Body, class Allocator>
Response bad_request(const Request<Body, Allocator> &req, beast::string_view why)
{
    Response res{http::status::bad_request, req.version()};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::content_type, "text/html");
    res.keep_alive(req.keep_alive());
    res.body() = std::string(why);
    res.prepare_payload();
    return res;
};

// Returns a not found response
template <class Body, class Allocator>
Response not_found(const Request<Body, Allocator> &req, beast::string_view target)
{
    Response res{http::status::not_found, req.version()};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::content_type, "text/html");
    res.keep_alive(req.keep_alive());
    res.body() = "The resource '" + std::string(target) + "' was not found.";
    res.prepare_payload();
    return res;
};

    // Returns a server error response
template <class Body, class Allocator>
Response server_error(const Request<Body, Allocator> &req, beast::string_view what)
{
    Response res{http::status::internal_server_error, req.version()};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::content_type, "text/html");
    res.keep_alive(req.keep_alive());
    res.body() = "An error occurred: '" + std::string(what) + "'";
    res.prepare_payload();
    return res;
};

template <class Body, class Allocator>
http::message_generator handle_get(ComicsDb::ComicDb &db, Request<Body, Allocator> &&req)
{    
    // Request path must match /comic/{:id}
    if( !std::regex_match(std::string{req.target()}, std::regex{"^/comic/[0-9]+$"}))
        return bad_request(req, "Illegal request-target " + std::string{req.target()});

    // Respond to GET request
    try
    {
        const auto      slash = req.target().find_last_of('/');
        const int       id = std::atoi(std::string{req.target().substr(slash + 1)}.c_str());
        ComicsDb::Comic comic = readComic(db, id);
        Response        res{http::status::ok, req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "application/json");
        res.keep_alive(req.keep_alive());
        res.body() = toJson(comic);
        res.prepare_payload();
        return res;
    }
    catch (const std::exception &bang)
    {
        return server_error(req, bang.what());
    }
}

template <class Body, class Allocator>
http::message_generator handle_put(ComicsDb::ComicDb &db, Request<Body, Allocator> &&req)
{    
    return bad_request(req, "Not implemented");
}

template <class Body, class Allocator>
http::message_generator handle_delete(ComicsDb::ComicDb &db, Request<Body, Allocator> &&req)
{    
    return bad_request(req, "Not implemented");
}

template <class Body, class Allocator>
http::message_generator handle_post(ComicsDb::ComicDb &db, Request<Body, Allocator> &&req)
{    
    return bad_request(req, "Not implemented");
}

// Return a response for the given request.
//
// The concrete type of the response message (which depends on the
// request), is type-erased in message_generator.
template <class Body, class Allocator>
http::message_generator handle_request(ComicsDb::ComicDb &db, Request<Body, Allocator> &&req)
{
    // Make sure we can handle the method
    switch (req.method())
    {
    case http::verb::get:
        return handle_get(db, std::move(req));

    case http::verb::put:
        return handle_put(db, std::move(req));

    case http::verb::delete_:
        return handle_delete(db, std::move(req));

    case http::verb::post:
        return handle_post(db, std::move(req));

    default:
        break;
    }
    return bad_request(req, "Unknown HTTP verb");
}

// Report a failure
void
fail(beast::error_code ec, char const* what)
{
    // ssl::error::stream_truncated, also known as an SSL "short read",
    // indicates the peer closed the connection without performing the
    // required closing handshake (for example, Google does this to
    // improve performance). Generally this can be a security issue,
    // but if your communication protocol is self-terminated (as
    // it is with both HTTP and WebSocket) then you may simply
    // ignore the lack of close_notify.
    //
    // https://github.com/boostorg/beast/issues/38
    //
    // https://security.stackexchange.com/questions/91435/how-to-handle-a-malicious-ssl-tls-shutdown
    //
    // When a short read would cut off the end of an HTTP message,
    // Beast returns the error beast::http::error::partial_message.
    // Therefore, if we see a short read here, it has occurred
    // after the message has been completed, so it is safe to ignore it.

    if(ec == net::ssl::error::stream_truncated)
        return;

    std::cerr << what << ": " << ec.message() << "\n";
}

// Handles an HTTP server connection.
// This uses the Curiously Recurring Template Pattern so that
// the same code works with both SSL streams and regular sockets.
template <class Derived>
class session
{
public:
    // Take ownership of the buffer
    session(State &state, beast::flat_buffer buffer) :
        buffer_(std::move(buffer)),
        state_(state)
    {
    }

    void
    do_read()
    {
        // Make the request empty before reading,
        // otherwise the operation behavior is undefined.
        req_ = {};

        // Set the timeout.
        beast::get_lowest_layer(derived().stream()).expires_after(std::chrono::seconds(30));

        // Read a request
        http::async_read(derived().stream(), buffer_, req_,
            beast::bind_front_handler(
                &session::on_read,
                derived().shared_from_this()));
    }

    void
    on_read(
        beast::error_code ec,
        std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);

        // This means they closed the connection
        if(ec == http::error::end_of_stream)
            return derived().do_eof();

        if(ec)
            return fail(ec, "read");

        // Send the response
        send_response(handle_request(state_.db, std::move(req_)));
    }

    void
    send_response(http::message_generator&& msg)
    {
        bool keep_alive = msg.keep_alive();

        // Write the response
        beast::async_write(
            derived().stream(),
            std::move(msg),
            beast::bind_front_handler(
                &session::on_write,
                derived().shared_from_this(),
                keep_alive));
    }

    void
    on_write(
        bool keep_alive,
        beast::error_code ec,
        std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);

        if(ec)
            return fail(ec, "write");

        if(! keep_alive)
        {
            // This means we should close the connection, usually because
            // the response indicated the "Connection: close" semantic.
            return derived().do_eof();
        }

        // Read another request
        do_read();
    }

protected:
    beast::flat_buffer buffer_;

private:
    Derived &derived()
    {
        return static_cast<Derived &>(*this);
    }

    State                               &state_;
    http::request<http::string_body>     req_;
};

// Handles a plain HTTP connection
class plain_session
    : public session<plain_session>
    , public std::enable_shared_from_this<plain_session>
{
public:
    // Create the session
    plain_session(State &state, tcp::socket &&socket, beast::flat_buffer buffer) :
        session<plain_session>(state, std::move(buffer)),
        stream_(std::move(socket))
    {
    }

    // Called by the base class
    beast::tcp_stream&
    stream()
    {
        return stream_;
    }

    // Start the asynchronous operation
    void
    run()
    {
        // We need to be executing within a strand to perform async operations
        // on the I/O objects in this session. Although not strictly necessary
        // for single-threaded contexts, this example code is written to be
        // thread-safe by default.
        net::dispatch(stream_.get_executor(),
                      beast::bind_front_handler(
                          &session::do_read,
                          shared_from_this()));
    }

    void
    do_eof()
    {
        // Send a TCP shutdown
        beast::error_code ec;
        stream_.socket().shutdown(tcp::socket::shutdown_send, ec);

        // At this point the connection is closed gracefully
    }

private:
    beast::tcp_stream stream_;
};

// Handles an SSL HTTP connection
class ssl_session
    : public session<ssl_session>
    , public std::enable_shared_from_this<ssl_session>
{
public:
    // Create the session
    ssl_session(State &state, tcp::socket &&socket, beast::flat_buffer buffer) :
        session<ssl_session>(state, std::move(buffer)),
        stream_(std::move(socket), state.ctx)
    {
    }

    // Called by the base class
    beast::ssl_stream<beast::tcp_stream>&
    stream()
    {
        return stream_;
    }

    // Start the asynchronous operation
    void
    run()
    {
        auto self = shared_from_this();
        // We need to be executing within a strand to perform async operations
        // on the I/O objects in this session.
        net::dispatch(stream_.get_executor(), [self]() {
            // Set the timeout.
            beast::get_lowest_layer(self->stream_).expires_after(
                std::chrono::seconds(30));

            // Perform the SSL handshake
            // Note, this is the buffered version of the handshake.
            self->stream_.async_handshake(
                ssl::stream_base::server,
                self->buffer_.data(),
                beast::bind_front_handler(
                    &ssl_session::on_handshake,
                    self));
        });
    }

    void
    on_handshake(
        beast::error_code ec,
        std::size_t bytes_used)
    {
        if(ec)
            return fail(ec, "handshake");

        // Consume the portion of the buffer used by the handshake
        this->buffer_.consume(bytes_used);

        this->do_read();
    }

    void
    do_eof()
    {
        // Set the timeout.
        beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));

        // Perform the SSL shutdown
        stream_.async_shutdown(
            beast::bind_front_handler(
                &ssl_session::on_shutdown,
                shared_from_this()));
    }

    void
    on_shutdown(beast::error_code ec)
    {
        if(ec)
            return fail(ec, "shutdown");

        // At this point the connection is closed gracefully
    }

private:
    beast::ssl_stream<beast::tcp_stream> stream_;
};

// Detects SSL handshakes
class detect_session : public std::enable_shared_from_this<detect_session>
{
public:
    detect_session(State &state, tcp::socket &&socket) :
        state_(state),
        stream_(std::move(socket))
    {
    }

    // Launch the detector
    void
    run()
    {
        // Set the timeout.
        beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));

        // Detect a TLS handshake
        async_detect_ssl(
            stream_,
            buffer_,
            beast::bind_front_handler(
                &detect_session::on_detect,
                shared_from_this()));
    }

    void
    on_detect(beast::error_code ec, bool result)
    {
        if(ec)
            return fail(ec, "detect");

        if(result)
        {
            // Launch SSL session
            std::make_shared<ssl_session>(state_, stream_.release_socket(), std::move(buffer_))->run();
            return;
        }

        // Launch plain session
        std::make_shared<plain_session>(state_, stream_.release_socket(), std::move(buffer_))->run();
    }

private:
    State             &state_;
    beast::tcp_stream  stream_;
    beast::flat_buffer buffer_;
};

// Accepts incoming connections and launches the sessions
class listener : public std::enable_shared_from_this<listener>
{
public:
    listener(State &state, tcp::endpoint endpoint) :
        state_(state),
        acceptor_(make_strand(state.ioc))
    {
        beast::error_code ec;

        // Open the acceptor
        acceptor_.open(endpoint.protocol(), ec);
        if(ec)
        {
            fail(ec, "open");
            return;
        }

        // Allow address reuse
        acceptor_.set_option(net::socket_base::reuse_address(true), ec);
        if(ec)
        {
            fail(ec, "set_option");
            return;
        }

        // Bind to the server address
        acceptor_.bind(endpoint, ec);
        if(ec)
        {
            fail(ec, "bind");
            return;
        }

        // Start listening for connections
        std::cout << "Listening for connections on endpoint " << endpoint << '\n';
        acceptor_.listen(
            net::socket_base::max_listen_connections, ec);
        if(ec)
        {
            fail(ec, "listen");
            return;
        }
    }

    // Start accepting incoming connections
    void
    run()
    {
        do_accept();
    }

private:
    void
    do_accept()
    {
        // The new connection gets its own strand
        acceptor_.async_accept(
            net::make_strand(state_.ioc),
            beast::bind_front_handler(
                &listener::on_accept,
                shared_from_this()));
    }

    void
    on_accept(beast::error_code ec, tcp::socket socket)
    {
        if(ec)
        {
            fail(ec, "accept");
            return; // To avoid infinite loop
        }
        else
        {
            // Create the session and run it
            std::make_shared<detect_session>(state_, std::move(socket))->run();
        }

        // Accept another connection
        do_accept();
    }

    State        &state_;
    tcp::acceptor acceptor_;
};

int run(const char *addressText, unsigned short port, int numThreads)
{
    ComicsDb::ComicDb db = ComicsDb::load();

    const net::ip::address address = net::ip::make_address(addressText);
    net::io_context ioc(numThreads);
    ssl::context ctx{ssl::context::tlsv12_server};
    load_server_certificate(ctx);
    ctx.set_default_verify_paths();

    // Server state: database, asio I/O context, SSL context
    State state{db, ioc, ctx};

    // Create and launch a listening port
    std::make_shared<listener>(state, tcp::endpoint{address, port})->run();

    // Run the I/O service on the requested number of threads
    std::vector<std::thread> v;
    v.reserve(numThreads - 1);
    for(auto i = numThreads - 1; i > 0; --i)
        v.emplace_back(
        [&ioc]
        {
            ioc.run();
        });
    ioc.run();

    return EXIT_SUCCESS;
}

}

int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        // clang-format off
        std::cerr <<
            "Usage: " << argv[0] << " <address> <port> <threads>\n" <<
            "Example:\n" <<
            "    " << argv[0] << " 0.0.0.0 8080 1\n";
        // clang-format on
        return EXIT_FAILURE;
    }
    const char *address = argv[1];
    const auto  port = static_cast<unsigned short>(std::atoi(argv[2]));
    const auto  threads = std::max<int>(1, std::atoi(argv[3]));
    return comicServer::run(address, port, threads);
}
