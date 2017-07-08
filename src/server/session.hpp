#pragma once

#include <boost/asio.hpp>

class Connection;

class Session {
  Connection * connection;

public:
  Session(Connection *);
  ~Session();
  bool send(boost::asio::const_buffer);

private:
  std::vector<uint32_t> subscriptionIds;
  void receive_request(const boost::system::error_code &err, size_t bytes_transferred);
  void read_some();
  bool parse_message(size_t bytes_transferred);

  std::unique_ptr<boost::asio::deadline_timer> timer;
  void start_timer();
  bool on_timer(const boost::system::error_code &err);
};

