#include "server.hpp"
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread.hpp>
#include <boost/thread/mutex.hpp>
#include <iostream>
#include <regex>
#include <sstream>
#include <string>

#ifdef USE_SSL
#include <boost/asio/ssl.hpp>
#endif

#include "connection.hpp"
#include "crypto.hpp"

server::server(boost::shared_ptr<boost::asio::io_service> io_service,
               short port)
    : io_service(io_service), ecdh("secp256k1"), session_count(0),
#ifdef USE_SSL
      context(*io_service, boost::asio::ssl::context::sslv23),
#endif // USE_SSL
      acceptor(*io_service, boost::asio::ip::tcp::endpoint(
                                boost::asio::ip::tcp::v4(), port)) {
  dsa::hash hash("sha256");

  public_key = ecdh.get_public_key();
  hash.update(public_key);

  dsid = "broker-" + dsa::base64url(hash.digest_base64());

#ifdef USE_SSL
  context.set_options(boost::asio::ssl::context::default_workarounds |
                       boost::asio::ssl::context::no_sslv2);
  context.set_password_callback(boost::bind(&server::get_password, this));
  context.use_certificate_chain_file("certificate.pem");
  context.use_private_key_file("key.pem", boost::asio::ssl::context::pem);

  connection *new_connection = new connection(*this, io_service, context);
#else  // don't USE_SSL
  connection *new_connection = new connection(*this, io_service);
#endif // USE_SSL
  acceptor.async_accept(new_connection->socket(),
                        boost::bind(&server::handle_accept, this, new_connection,
                                    boost::asio::placeholders::error));
}

void server::handle_accept(connection *new_connection,
                           const boost::system::error_code &error) {
  if (!error) {
    new_connection->start();
#ifdef USE_SSL
    new_connection = new connection(*this, io_service, context);
#else // don't USE_SSL
    new_connection = new connection(*this, io_service);
#endif // USE_SSL
    acceptor.async_accept(new_connection->socket(),
                          boost::bind(&server::handle_accept, this, new_connection,
                                      boost::asio::placeholders::error));
  } else {
    std::stringstream ss;
    ss << "[" << boost::this_thread::get_id() << "] Error: " << error
              << std::endl;
    std::cout << ss.str();
    delete new_connection;
  }
}

void server::end_session(connection *s) { delete s; }

#ifdef USE_SSL
std::string server::get_password() const {
  return "";
}
#endif // USE_SSL

int server::get_session_id() {
  return session_count++;
}