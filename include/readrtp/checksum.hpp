#pragma once

#include "readrtp/common.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace readrtp {

inline constexpr std::uint32_t kChecksumWord31Mask = 0x7FFFFFFFU;
inline constexpr std::uint32_t kChecksumWord30Mask = 0x3FFFFFFFU;
inline constexpr std::size_t kChecksumStateSize = 10;

struct UnpackedChecksumState {
    std::uint8_t counter31{0};
    std::uint8_t counter30{0};
    std::uint32_t state31{0};
    std::uint32_t state30{0};
};

[[nodiscard]] UnpackedChecksumState unpack_checksum_state(
    std::optional<ChecksumBytes> state = std::nullopt
);

[[nodiscard]] ChecksumBytes pack_checksum_state(
    const UnpackedChecksumState& state
);

[[nodiscard]] ChecksumBytes update_checksum_state_bytes(
    ByteView data,
    std::optional<ChecksumBytes> state = std::nullopt
);

[[nodiscard]] ChecksumBytes update_cyclic_checksum_state_bytes(
    ByteView data,
    std::optional<ChecksumBytes> state = std::nullopt
);

[[nodiscard]] ChecksumBytes update_checksum_with_rotation_bytes(
    ByteView data,
    std::size_t offset,
    std::optional<ChecksumBytes> state = std::nullopt
);

[[nodiscard]] ChecksumBytes update_bitstream_state_with_modulo_rotation_bytes(
    ByteView data,
    std::size_t offset,
    std::optional<ChecksumBytes> state = std::nullopt
);

[[nodiscard]] std::string verify_checksum(
    ByteView data,
    const ChecksumBytes& expected,
    std::string_view context
);

}  // namespace readrtp
