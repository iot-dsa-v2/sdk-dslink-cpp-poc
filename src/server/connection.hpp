#pragma once

#include <string>
#include <vector>
#include <memory>
#include <boost/asio.hpp>
#include <boost/shared_ptr.hpp>

#include "crypto.h"
#include "message.hpp"
#include "util.h"

using namespace dsa;

typedef message::message_buffer message_buffer;

class Server;
class Session;

class Connection {
private:

  boost::shared_ptr<Session> session;

  message_buffer read_buf;
  message_buffer write_buf;
  
#ifdef USE_SSL
  ssl_socket sock;
#else  // don't USE_SSL
  boost::asio::ip::tcp::socket sock;
#endif // USE_SSL

  std::shared_ptr<Buffer> shared_secret;
  std::shared_ptr<Buffer> client_dsid;
  std::shared_ptr<Buffer> client_public;
  std::shared_ptr<Buffer> client_salt;
  std::shared_ptr<Buffer> client_token;
  std::shared_ptr<Buffer> client_auth;
  std::shared_ptr<Buffer> auth;
  std::shared_ptr<Buffer> salt;

  std::string path;

  bool use_ssl;
  bool is_requester;
  bool is_responder;

  int load_f1(message_buffer* buf);
  int load_f3(message_buffer* buf);
  void compute_secret();

  void f0_received(message_buffer* buf,
    const boost::system::error_code &err,
    size_t bytes_transferred);
  void f1_sent(message_buffer* buf,
    const boost::system::error_code &err,
    size_t bytes_transferred);
  void f2_received(message_buffer* buf,
    const boost::system::error_code &err,
    size_t bytes_transferred);
  void f3_sent(message_buffer* buf,
    const boost::system::error_code &err,
    size_t bytes_transferred);
  void read_loop(message_buffer* buf,
    const boost::system::error_code &err,
    size_t bytes_transferred);

public:
  std::string session_id;

  boost::asio::io_service::strand strand;

  Server& serv;
#ifdef USE_SSL
  Connection(Server &s, boost::shared_ptr<boost::asio::io_service> io_service,
    boost::asio::ssl::context &context);

  ssl_socket::lowest_layer_type &socket();

  void handle_ssl_handshake(const boost::system::error_code &error);
#else  // don't USE_SSL
  Connection(Server &s, boost::shared_ptr<boost::asio::io_service> io_service);

  boost::asio::ip::tcp::socket &socket();
#endif // USE_SSL

  enum { max_length = 512, f0_bytes_wo_dsid = 112 };

  ~Connection();

  void start();

  void handle_read(const boost::system::error_code &error,
    size_t bytes_transferred);

  void handle_write(const boost::system::error_code &error,
    size_t bytes_transferred);
};
