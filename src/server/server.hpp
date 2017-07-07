#pragma once

#include <atomic>
#include <string>
#include <vector>
#include <boost/asio.hpp>
#include <boost/shared_ptr.hpp>
#include <openssl/hmac.h>

#include "crypto.hpp"

#ifdef USE_SSL
#include <boost/asio/ssl.hpp>

typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl_socket;
#endif // USE_SSL

#ifndef uint
typedef unsigned int uint;
#endif

class Connection;
class Session;

class Server {
private:
  boost::shared_ptr<boost::asio::io_service> io_service;
  boost::asio::ip::tcp::acceptor acceptor;
  std::string dsid;
  std::vector<byte> public_key;
  dsa::ecdh ecdh;
#ifdef USE_SSL
  boost::asio::ssl::context context;

  std::string get_password() const;
#endif // USE_SSL

  std::atomic_int session_count;

  friend Connection;

public:
  Server(boost::shared_ptr<boost::asio::io_service> io_service, short port);

  void handle_accept(Connection *new_session,
    const boost::system::error_code &error);

  void end_connection(Connection *s);
  void end_session(Session *s);

  int get_session_id();
};
