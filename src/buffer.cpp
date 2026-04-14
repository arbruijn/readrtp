#include "readrtp/buffer.hpp"

#include "readrtp/error.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <limits>

namespace readrtp {

namespace {

}  // namespace

ByteBuffer read_file_bytes(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw PatchError("unable to open file for reading: " + path.string());
    }

    input.seekg(0, std::ios::end);
    std::streamsize size = input.tellg();
    input.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(size);
    if (!input.read(reinterpret_cast<char*>(buffer.data()), size)) {
        throw PatchError("unable to read file: " + path.string());
    }

    return buffer;
}

BufferReader::BufferReader(ByteBuffer data, std::size_t offset)
    : data_(std::move(data)), pos_(offset) {
    if (offset > data_.size()) {
        throw PatchError("buffer reader offset out of range");
    }
}

std::size_t BufferReader::remaining() const {
    return data_.size() - pos_;
}

bool BufferReader::eof() const {
    return pos_ >= data_.size();
}

std::size_t BufferReader::tell() const {
    return pos_;
}

void BufferReader::seek(std::size_t offset) {
    if (offset > data_.size()) {
        throw PatchError("seek out of range");
    }
    pos_ = offset;
}

std::uint8_t BufferReader::read_u8() {
    if (eof()) {
        throw PatchError("unexpected EOF reading u8");
    }
    return data_[pos_++];
}

ByteBuffer BufferReader::read_bytes(std::size_t count) {
    if (pos_ + count > data_.size()) {
        throw PatchError("unexpected EOF reading bytes");
    }

    const auto begin = data_.begin() + static_cast<std::ptrdiff_t>(pos_);
    const auto end = begin + static_cast<std::ptrdiff_t>(count);
    pos_ += count;
    return ByteBuffer(begin, end);
}

std::uint16_t BufferReader::read_u16le() {
    const auto bytes = read_bytes(2);
    return static_cast<std::uint16_t>(bytes[0])
        | (static_cast<std::uint16_t>(bytes[1]) << 8U);
}

std::uint32_t BufferReader::read_u32le() {
    const auto bytes = read_bytes(4);
    return static_cast<std::uint32_t>(bytes[0])
        | (static_cast<std::uint32_t>(bytes[1]) << 8U)
        | (static_cast<std::uint32_t>(bytes[2]) << 16U)
        | (static_cast<std::uint32_t>(bytes[3]) << 24U);
}

std::int32_t BufferReader::read_i32le() {
    return static_cast<std::int32_t>(read_u32le());
}

std::string BufferReader::read_cstring() {
    const auto begin = data_.begin() + static_cast<std::ptrdiff_t>(pos_);
    const auto end = std::find(begin, data_.end(), static_cast<std::uint8_t>(0));
    if (end == data_.end()) {
        throw PatchError("unterminated string");
    }

    std::string value(begin, end);
    pos_ += static_cast<std::size_t>(std::distance(begin, end)) + 1;
    return value;
}

std::string BufferReader::read_len_prefixed_utf8() {
    std::size_t length = read_u8();
    if (length == 0xFFU) {
        length = read_u16le();
    }
    if (length == 0) {
        return {};
    }

    const auto bytes = read_bytes(length);
    return std::string(bytes.begin(), bytes.end());
}

ByteBuffer BufferReader::read_len_prefixed_bytes() {
    std::size_t length = read_u8();
    if (length == 0xFFU) {
        length = read_u16le();
    }
    if (length == 0) {
        return {};
    }
    return read_bytes(length);
}

const ByteBuffer& BufferReader::data() const noexcept {
    return data_;
}

MutableFile::MutableFile(
    std::filesystem::path path,
    std::optional<ByteBuffer> initial_data
) : path_(std::move(path)) {
    if (initial_data.has_value()) {
        data_ = std::move(*initial_data);
    } else if (!path_.empty() && std::filesystem::exists(path_)) {
        data_ = read_file_bytes(path_);
    }
}

void MutableFile::ensure_size(std::size_t size) {
    if (size > data_.size()) {
        data_.resize(size, 0);
    }
}

void MutableFile::write_at(std::size_t offset, ByteView chunk) {
    ensure_size(offset + chunk.size());
    std::copy(chunk.begin(), chunk.end(), data_.begin() + static_cast<std::ptrdiff_t>(offset));
}

void MutableFile::fill_at(std::size_t offset, std::size_t length, std::uint8_t value) {
    ensure_size(offset + length);
    std::fill_n(
        data_.begin() + static_cast<std::ptrdiff_t>(offset),
        static_cast<std::ptrdiff_t>(length),
        value
    );
}

ByteBuffer MutableFile::read_at(std::size_t offset, std::size_t length) {
    ensure_size(offset + length);
    const auto begin = data_.begin() + static_cast<std::ptrdiff_t>(offset);
    const auto end = begin + static_cast<std::ptrdiff_t>(length);
    return ByteBuffer(begin, end);
}

void MutableFile::add_at(std::size_t offset, std::size_t width, std::int64_t delta) {
    if (width == 0 || width > sizeof(std::uint64_t)) {
        throw PatchError("unsupported add_at width");
    }

    ensure_size(offset + width);
    std::uint64_t current = 0;
    for (std::size_t index = 0; index < width; ++index) {
        current |= static_cast<std::uint64_t>(data_[offset + index]) << (index * 8U);
    }

    const auto mask = width == sizeof(std::uint64_t)
        ? std::numeric_limits<std::uint64_t>::max()
        : ((static_cast<std::uint64_t>(1) << (width * 8U)) - 1U);
    const auto updated = (current + static_cast<std::uint64_t>(delta)) & mask;

    for (std::size_t index = 0; index < width; ++index) {
        data_[offset + index] = static_cast<std::uint8_t>(
            (updated >> (index * 8U)) & 0xFFU
        );
    }
}

void MutableFile::truncate(std::size_t size) {
    if (size < data_.size()) {
        data_.resize(size);
    }
}

void MutableFile::save() const {
    if (path_.empty()) {
        throw PatchError("cannot save mutable file without a path");
    }

    if (!path_.parent_path().empty()) {
        std::filesystem::create_directories(path_.parent_path());
    }

    std::ofstream output(path_, std::ios::binary);
    if (!output) {
        throw PatchError("unable to open file for writing: " + path_.string());
    }

    output.write(
        reinterpret_cast<const char*>(data_.data()),
        static_cast<std::streamsize>(data_.size())
    );
    if (!output) {
        throw PatchError("failed while writing file: " + path_.string());
    }
}

const std::filesystem::path& MutableFile::path() const noexcept {
    return path_;
}

}  // namespace readrtp
