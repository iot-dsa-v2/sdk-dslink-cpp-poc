#include "session.hpp"

#include "connection.hpp";
Session::Session(Connection * connection)
  :connection(connection) {

}


bool Session::send(boost::asio::const_buffer buffer) {
  return true;
}

