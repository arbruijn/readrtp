#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace readrtp {

using ByteBuffer = std::vector<std::uint8_t>;
using ByteView = std::span<const std::uint8_t>;
using ChecksumBytes = std::array<std::uint8_t, 10>;

[[nodiscard]] inline ByteView as_bytes(const ByteBuffer& buffer) {
    return ByteView(buffer.data(), buffer.size());
}

[[nodiscard]] inline ByteBuffer make_byte_buffer(ByteView view) {
    return ByteBuffer(view.begin(), view.end());
}

}  // namespace readrtp
