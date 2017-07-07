#pragma once

#include <boost/asio.hpp>

class Connection;

class Session {
  Connection * connection;
public:
  Session(Connection *);
  bool send(boost::asio::const_buffer);
};

