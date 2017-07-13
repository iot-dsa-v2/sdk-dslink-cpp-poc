#include "buffer.h"

#include <cstring>
#include <iostream>

namespace dsa {

Buffer::Buffer()
    : _data(new uint8_t[default_capacity]), _size(0), _capacity(default_capacity) {}

Buffer::Buffer(size_t capacity)
    : _data(new uint8_t[capacity]), _size(0), _capacity(capacity) {
  if (capacity < 1)
    throw new std::runtime_error("Invalid capacity for buffer constructor");
}

Buffer::Buffer(const Buffer &other)
    : _size(other._size), _capacity(other._capacity) {
  _data = new uint8_t[_capacity];
  std::memcpy(_data, other.data(), other.size());
}

Buffer::Buffer(uint8_t *data, size_t size, size_t capacity)
    : _data(data), _size(size), _capacity(capacity) {}

Buffer& Buffer::operator=(const Buffer &other) {
  delete[] _data;
  _data = new uint8_t[other.capacity()];
  _size = other.size();
  _capacity = other.capacity();
  std::memcpy(_data, other.data(), other.size());
  return *this;
}
 
size_t Buffer::capacity() const { return _capacity; }
 
size_t Buffer::size() const { return _size; }
 
bool Buffer::resize(size_t capacity) {
  if (capacity <= _capacity)
    return false;
  uint8_t *new_data = new uint8_t[capacity];
  std::memcpy(new_data, _data, _size);
  delete[] _data;
  _data = new_data;
  _capacity = capacity;
  return true;
}
 
void Buffer::append(uint8_t data) { _data[_size++] = data; }
 
void Buffer::safe_append(uint8_t data) {
  if (_size + 1 >= _capacity)
    resize(_capacity * 2);
  _data[_size++] = data;
}
 
uint8_t *Buffer::data() const { return _data; }
 
void Buffer::assign(const uint8_t *data, size_t size) {
  if (_capacity < size) {
    delete[] _data;
    _data = new uint8_t[size];
  }
  _size = size;
  std::memcpy(_data, data, _size);
}
 
uint8_t &Buffer::operator[](int index) {
  if (index >= _size) {
    if (index >= _capacity) {
      throw new std::runtime_error("Buffer access, index out of bounds");
    }
    _size = index + 1;
  }
  return _data[index];
}

const uint8_t &Buffer::operator[](int index) const {
  if (index >= _size) {
    throw new std::runtime_error("Buffer access, index out of bounds");
  }
  return _data[index];
}

} // namespace dsa
