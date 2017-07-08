#pragma once

#include <map>
#include <vector>
#include <array>
#include <boost/asio.hpp>

#include "message.hpp"

using namespace dsa::message;

class Connection;

class Session {
  Connection * connection;

public:
  Session(Connection *);
  ~Session();
  bool send(boost::asio::const_buffer);

private:
	buffer_factory buffer_factory;
  std::vector<uint32_t> subscriptionIds;
  void receive_request(message_buffer* buf,
	  const boost::system::error_code &err, size_t bytes_transferred);
  void read_some();
  bool parse_message(message_buffer* buf, size_t bytes_transferred);

  std::unique_ptr<boost::asio::deadline_timer> timer;
  void start_timer();
  bool on_timer(const boost::system::error_code &err);
};

