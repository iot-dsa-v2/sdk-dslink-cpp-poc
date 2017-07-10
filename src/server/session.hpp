#pragma once

#include <map>
#include <vector>
#include <array>
#include <atomic>
#include <boost/asio.hpp>

#include "message.hpp"

typedef uint8_t byte;

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
  bool parse_message(message_buffer* buf, size_t bytes_transferred, size_t offset);

  std::unique_ptr<boost::asio::deadline_timer> timer;
  void start_timer();
  bool on_timer(const boost::system::error_code &err);

  std::atomic_int sent_count;

  void send_response(uint32_t rid);
  void send_done(byte * buf, const boost::system::error_code & error, size_t bytes_transferred);
};

