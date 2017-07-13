#ifndef DSA_SDK_UTIL_BUFFER_H_
#define DSA_SDK_UTIL_BUFFER_H_

#include <iostream>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>
#include <memory>

namespace dsa {
class Buffer {
 private:
  enum { default_capacity = 256 };
  uint8_t * _data;
  size_t _size;
  size_t _capacity;
 public:
  // default constructor
  Buffer();

  // set capacity constructor
  Buffer(size_t capacity);

  // shallow copy constructor
  Buffer(const Buffer& other);

  // dangerous raw pointer constructor
  // data pointer assumed to be stored on heap with correct size and capacity args
  Buffer(uint8_t* data, size_t size, size_t capacity);

  // assignment operator
  Buffer& operator=(const Buffer& other);

  // get current capacity of underlying array
  size_t capacity() const;

  // manually resize capacity of buffer, true if successful
  bool resize(size_t capacity);

  // number of elements in buffer
  size_t size() const;

  // add element to the end of the list of elements, no check on capacity
  void append(uint8_t data);

  // append with capacity check, amortized doubling used to resize buffer if needed
  void safe_append(uint8_t data);

  // copy from pointer `size` number of items
  void assign(const uint8_t * data, size_t size);

  // access underlying array
  uint8_t * data() const;

  // access operator
  uint8_t& operator[](int index);

  // const access operator
  const uint8_t& operator[](int index) const;

  // iterator
  typedef uint8_t * iterator;
  typedef const uint8_t * const_iterator;
  iterator begin() { return &_data[0]; }
  iterator end() { return &_data[_size]; }
};

}  // namespace dsa

inline std::ostream& operator<<(std::ostream& os, const dsa::Buffer& buf) {
  std::stringstream ss;
  ss << "[";
  if (buf.size() > 0) {
    for (unsigned int i = 0; i < buf.size() - 1; ++i) {
      ss << std::hex << (unsigned int)(buf[i]) << std::dec << ", ";
    }
    ss << std::hex << (unsigned int)(buf[buf.size() - 1]) << std::dec;
  }
  ss << "]";
  return os << ss.str();
}

#endif  // DSA_SDK_UTIL_BUFFER_H_