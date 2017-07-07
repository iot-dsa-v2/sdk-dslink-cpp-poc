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
  void receive_request(const boost::system::error_code &err,
    size_t bytes_transferred);
};

