#pragma once

#include <string>
#include <vector>
#include <boost/asio.hpp>
#include <boost/shared_ptr.hpp>

#include "crypto.hpp"

class Server;

class Connection {
private:
  Server &serv;
#ifdef USE_SSL
  ssl_socket sock;
#else  // don't USE_SSL
  boost::asio::ip::tcp::socket sock;
#endif // USE_SSL
  boost::asio::io_service::strand strand;

  enum { max_length = 512, f0_bytes_wo_dsid = 112 };
  byte write_buf[max_length];
  byte read_buf[max_length];

  std::vector<byte> shared_secret;
  std::vector<byte> client_dsid;
  std::vector<byte> client_public;
  std::vector<byte> client_salt;
  std::vector<byte> client_token;
  std::vector<byte> client_auth;
  std::vector<byte> auth;
  std::vector<byte> salt;

  std::string session_id;
  std::string path;

  bool use_ssl;
  bool is_requester;
  bool is_responder;

  int load_f1();
  int load_f3();
  void compute_secret();

  void f0_received(const boost::system::error_code &err,
    size_t bytes_transferred);
  void f1_sent(const boost::system::error_code &err,
    size_t bytes_transferred);
  void read_f2();
  void f2_received(const boost::system::error_code &err,
    size_t bytes_transferred);
  void f3_sent(const boost::system::error_code &err,
    size_t bytes_transferred);

  void read_loop(const boost::system::error_code &err,
    size_t bytes_transferred);

public:
#ifdef USE_SSL
  connection(Server &s, boost::shared_ptr<boost::asio::io_service> io_service,
    boost::asio::ssl::context &context);

  ssl_socket::lowest_layer_type &socket();

  void handle_ssl_handshake(const boost::system::error_code &error);
#else  // don't USE_SSL
  Connection(Server &s, boost::shared_ptr<boost::asio::io_service> io_service);

  boost::asio::ip::tcp::socket &socket();
#endif // USE_SSL

  ~Connection();

  void start();

  void handle_read(const boost::system::error_code &error,
    size_t bytes_transferred);

  void handle_write(const boost::system::error_code &error,
    size_t bytes_transferred);
};