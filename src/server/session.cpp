#include "session.hpp"
#include <boost/asio.hpp>
#include <boost/bind.hpp>

#include "connection.hpp"
#include "server.hpp"
#include "message.hpp"

using namespace dsa::message;



Session::Session(Connection * connection)
  : connection(connection), sent_count(0) {
  //async_read(connection->socket(), connection->get_read_buffer(), boost::bind(&Session::receive_request, this,
  //  boost::asio::placeholders::error,
  //  boost::asio::placeholders::bytes_transferred));
  read_some();

  static boost::posix_time::milliseconds interval(10);
  timer.reset(new boost::asio::deadline_timer(*(connection->serv.io_service), interval));

  start_timer();
}

Session::~Session() {
  timer->cancel();
  delete connection;
}
bool Session::send(boost::asio::const_buffer buffer) {
  return true;
}

void Session::read_some() {
  message_buffer& buf = buffer_factory.get_buffer();

  connection->socket().async_read_some(
    buf.asio_buffer(),
    boost::bind(
      &Session::receive_request,
      this, &buf,
      boost::asio::placeholders::error,
      boost::asio::placeholders::bytes_transferred
    )
  );
}

void Session::receive_request(message_buffer* buf,
  const boost::system::error_code &error,
  size_t bytes_transferred) {
  if (!error) {
    if (!parse_message(buf, bytes_transferred, 0)) {
      delete this;
      return;
    }
    read_some();
  } else {
    delete this;
  }
}

bool Session::parse_message(message_buffer* buf, size_t bytes_transferred, size_t offset) {
  byte *cur = buf->data() + offset;
  uint32_t size;
  uint16_t header_size;
  byte method_type;
  uint32_t rid;

  memcpy(&size, cur, sizeof(size));
  cur += sizeof(size);
  memcpy(&header_size, cur, sizeof(header_size));
  cur += sizeof(header_size);
  memcpy(&method_type, cur, sizeof(method_type));
  cur += sizeof(method_type);
  memcpy(&rid, cur, sizeof(rid));
  cur += sizeof(rid);
  // ignore dynamic headers for now

  if (bytes_transferred >= size + offset) {
    auto add_id = [&](uint32_t id) {
      subscriptionIds.push_back(id);
    };
    connection->strand.post(boost::bind<void>(add_id, rid));

    std::cout << "receive request\n";
    if (bytes_transferred > size + offset) {
      // parse the rest of the data
      // this is only safe for the poc because of small message size
      return parse_message(buf, bytes_transferred, offset + size);
    }
    return true;
  }
  return false;
}

void Session::start_timer() {
  timer->async_wait(boost::bind(
    &Session::on_timer,
    this,
    boost::asio::placeholders::error
  ));
}

void Session::send_response(uint32_t rid) {
  byte * buf = new byte[1000];
  uint32_t total = 0;

  /* total length placeholder */
  for (int i = 0; i < sizeof(total); ++i)
    buf[total++] = 0;

  /* header length */
  uint16_t header_length = 11;
  std::memcpy(&buf[total], &header_length, sizeof(header_length));
  total += sizeof(header_length);

  /* message type */
  buf[total++] = 0x81;

  /* request id */
  memcpy(&buf[total], &rid, sizeof(rid));
  total += sizeof(rid);

  char message[] = "sample message";
  memcpy(&buf[total], message, sizeof(message));
  total += sizeof(message);

  /* write total length */
  std::memcpy(buf, &total, sizeof(total));

  // ignore dynamic headers for now
  sent_count++;

  boost::asio::async_write(
    connection->socket(), boost::asio::buffer(buf, total), 
    boost::bind(&Session::send_done, this, buf,
      boost::asio::placeholders::error,
      boost::asio::placeholders::bytes_transferred));
}

void Session::send_done(byte * buf, const boost::system::error_code & error,
  size_t bytes_transferred) {
  delete[] buf;
  std::stringstream ss;
  if (!error) {
    ss << "transferred: " << bytes_transferred << " bytes" << std::endl;
    sent_count--;
  } else {
    ss << "error: " << error << std::endl;
  }
  std::cout << ss.str();
}

bool Session::on_timer(const boost::system::error_code &err) {
  if (err) {
    return false;
  }

  start_timer();

  if (sent_count < subscriptionIds.size()) {
    auto send_responses = [&]() {
      for (int id : subscriptionIds) {
        send_response(id);
      }
    };
    connection->strand.post(boost::bind<void>(send_responses));
  }

  return true;
}