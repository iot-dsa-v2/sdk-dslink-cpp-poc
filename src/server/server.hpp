#pragma once

#include <atomic>
#include <string>
#include <vector>
#include <memory>

#include <boost/asio.hpp>
#include <boost/shared_ptr.hpp>
#include <openssl/hmac.h>

#include "crypto.h"
#include "util.h"

using namespace dsa;

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
  
  boost::asio::ip::tcp::acceptor acceptor;
  std::string dsid;
  std::shared_ptr<Buffer> public_key;
  dsa::ecdh ecdh;
#ifdef USE_SSL
  boost::asio::ssl::context context;

  std::string get_password() const;
#endif // USE_SSL

  std::atomic_int session_count;

  friend Connection;

public:
  const boost::shared_ptr<boost::asio::io_service> io_service;

  Server(boost::shared_ptr<boost::asio::io_service> io_service, short port);

  void handle_accept(Connection *new_session,
    const boost::system::error_code &error);


  int get_session_id();
};
