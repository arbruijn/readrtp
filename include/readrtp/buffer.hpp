#pragma once

#include "readrtp/common.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

namespace readrtp {

[[nodiscard]] ByteBuffer read_file_bytes(const std::filesystem::path& path);

class BufferReader {
public:
    explicit BufferReader(ByteBuffer data = {}, std::size_t offset = 0);

    [[nodiscard]] std::size_t remaining() const;
    [[nodiscard]] bool eof() const;
    [[nodiscard]] std::size_t tell() const;
    void seek(std::size_t offset);
    std::uint8_t read_u8();
    ByteBuffer read_bytes(std::size_t count);
    std::uint16_t read_u16le();
    std::uint32_t read_u32le();
    std::int32_t read_i32le();
    std::string read_cstring();
    std::string read_len_prefixed_utf8();
    ByteBuffer read_len_prefixed_bytes();

    [[nodiscard]] const ByteBuffer& data() const noexcept;

private:
    ByteBuffer data_;
    std::size_t pos_{0};
};

class MutableFile {
public:
    explicit MutableFile(
        std::filesystem::path path = {},
        std::optional<ByteBuffer> initial_data = std::nullopt
    );

    void ensure_size(std::size_t size);
    void write_at(std::size_t offset, ByteView chunk);
    void fill_at(std::size_t offset, std::size_t length, std::uint8_t value);
    [[nodiscard]] ByteBuffer read_at(std::size_t offset, std::size_t length);
    void add_at(std::size_t offset, std::size_t width, std::int64_t delta);
    void truncate(std::size_t size);
    void save() const;

    [[nodiscard]] const std::filesystem::path& path() const noexcept;

private:
    std::filesystem::path path_;
    ByteBuffer data_;
};

}  // namespace readrtp
