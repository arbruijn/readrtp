#include "readrtp/checksum.hpp"

#include "readrtp/error.hpp"

#include <iomanip>
#include <sstream>

namespace readrtp {

namespace {

[[nodiscard]] std::string to_hex(const ChecksumBytes& bytes) {
    std::ostringstream stream;
    stream << std::hex << std::setfill('0');
    for (const auto byte : bytes) {
        stream << std::setw(2) << static_cast<unsigned int>(byte);
    }
    return stream.str();
}

}  // namespace

constexpr std::uint32_t rotate_left_masked(
    std::uint32_t value,
    std::uint32_t shift,
    std::uint32_t width
) {
    const auto mask = ((static_cast<std::uint32_t>(1) << width) - 1U);
    shift %= width;
    value &= mask;
    if (shift == 0) {
        return value;
    }
    return ((value << shift) & mask) | (value >> (width - shift));
}

UnpackedChecksumState unpack_checksum_state(std::optional<ChecksumBytes> state) {
    if (!state.has_value()) {
        return {};
    }

    const auto& raw = *state;
    return {
        raw[0],
        raw[1],
        static_cast<std::uint32_t>(raw[2])
            | (static_cast<std::uint32_t>(raw[3]) << 8U)
            | (static_cast<std::uint32_t>(raw[4]) << 16U)
            | (static_cast<std::uint32_t>(raw[5]) << 24U),
        static_cast<std::uint32_t>(raw[6])
            | (static_cast<std::uint32_t>(raw[7]) << 8U)
            | (static_cast<std::uint32_t>(raw[8]) << 16U)
            | (static_cast<std::uint32_t>(raw[9]) << 24U),
    };
}

ChecksumBytes pack_checksum_state(const UnpackedChecksumState& state) {
    ChecksumBytes packed{};
    const auto state31 = state.state31 & kChecksumWord31Mask;
    const auto state30 = state.state30 & kChecksumWord30Mask;

    packed[0] = static_cast<std::uint8_t>(state.counter31 % 0x1FU);
    packed[1] = static_cast<std::uint8_t>(state.counter30 % 0x1EU);
    packed[2] = static_cast<std::uint8_t>(state31 & 0xFFU);
    packed[3] = static_cast<std::uint8_t>((state31 >> 8U) & 0xFFU);
    packed[4] = static_cast<std::uint8_t>((state31 >> 16U) & 0xFFU);
    packed[5] = static_cast<std::uint8_t>((state31 >> 24U) & 0xFFU);
    packed[6] = static_cast<std::uint8_t>(state30 & 0xFFU);
    packed[7] = static_cast<std::uint8_t>((state30 >> 8U) & 0xFFU);
    packed[8] = static_cast<std::uint8_t>((state30 >> 16U) & 0xFFU);
    packed[9] = static_cast<std::uint8_t>((state30 >> 24U) & 0xFFU);
    return packed;
}

ChecksumBytes update_checksum_state_bytes(
    ByteView data,
    std::optional<ChecksumBytes> state
) {
    auto unpacked = unpack_checksum_state(state);
    if (data.empty()) {
        return pack_checksum_state(unpacked);
    }

    unpacked.counter31 = static_cast<std::uint8_t>(
        (unpacked.counter31 + data.size()) % 0x1FU
    );
    unpacked.counter30 = static_cast<std::uint8_t>(
        (unpacked.counter30 + data.size()) % 0x1EU
    );

    for (const auto byte : data) {
        unpacked.state31 = rotate_left_masked(unpacked.state31 ^ byte, 1, 31);
        unpacked.state30 = rotate_left_masked(unpacked.state30 ^ byte, 1, 30);
    }

    return pack_checksum_state(unpacked);
}

ChecksumBytes update_cyclic_checksum_state_bytes(
    ByteView data,
    std::optional<ChecksumBytes> state
) {
    auto unpacked = unpack_checksum_state(state);
    if (data.empty()) {
        return pack_checksum_state(unpacked);
    }

    unpacked.counter31 = static_cast<std::uint8_t>(
        (unpacked.counter31 + data.size()) % 0x1FU
    );
    unpacked.counter30 = static_cast<std::uint8_t>(
        (unpacked.counter30 + data.size()) % 0x1EU
    );

    for (const auto byte : data) {
        unpacked.state31 = rotate_left_masked(unpacked.state31 ^ byte, 8, 31);
        unpacked.state30 = rotate_left_masked(unpacked.state30 ^ byte, 8, 30);
    }

    return pack_checksum_state(unpacked);
}

ChecksumBytes update_checksum_with_rotation_bytes(
    ByteView data,
    std::size_t offset,
    std::optional<ChecksumBytes> state
) {
    auto original = unpack_checksum_state(state);
    auto rotated = original;

    rotated.counter31 = static_cast<std::uint8_t>(offset % 0x1FU);
    rotated.counter30 = static_cast<std::uint8_t>(offset % 0x1EU);
    rotated.state31 = rotate_left_masked(
        original.state31,
        (rotated.counter31 + 0x1FU - original.counter31) % 0x1FU,
        31
    );
    rotated.state30 = rotate_left_masked(
        original.state30,
        (rotated.counter30 + 0x1EU - original.counter30) % 0x1EU,
        30
    );

    auto updated = unpack_checksum_state(
        update_checksum_state_bytes(data, pack_checksum_state(rotated))
    );
    updated.state30 = rotate_left_masked(
        updated.state30,
        (original.counter30 + 0x1EU - updated.counter30) % 0x1EU,
        30
    );
    updated.state31 = rotate_left_masked(
        updated.state31,
        (original.counter31 + 0x1FU - updated.counter31) % 0x1FU,
        31
    );
    updated.counter31 = original.counter31;
    updated.counter30 = original.counter30;
    return pack_checksum_state(updated);
}

ChecksumBytes update_bitstream_state_with_modulo_rotation_bytes(
    ByteView data,
    std::size_t offset,
    std::optional<ChecksumBytes> state
) {
    auto original = unpack_checksum_state(state);
    auto rotated = original;

    rotated.counter31 = static_cast<std::uint8_t>(offset % 0x1FU);
    rotated.counter30 = static_cast<std::uint8_t>(offset % 0x1EU);
    rotated.state31 = rotate_left_masked(
        original.state31,
        ((rotated.counter31 + 0x1FU - original.counter31) % 0x1FU) * 8U,
        31
    );
    rotated.state30 = rotate_left_masked(
        original.state30,
        ((rotated.counter30 + 0x1EU - original.counter30) % 0x1EU) * 8U,
        30
    );

    auto updated = unpack_checksum_state(
        update_cyclic_checksum_state_bytes(data, pack_checksum_state(rotated))
    );
    updated.state30 = rotate_left_masked(
        updated.state30,
        ((original.counter30 + 0x1EU - updated.counter30) % 0x1EU) * 8U,
        30
    );
    updated.state31 = rotate_left_masked(
        updated.state31,
        ((original.counter31 + 0x1FU - updated.counter31) % 0x1FU) * 8U,
        31
    );
    updated.counter31 = original.counter31;
    updated.counter30 = original.counter30;
    return pack_checksum_state(updated);
}

std::string verify_checksum(
    ByteView data,
    const ChecksumBytes& expected,
    std::string_view context
) {
    const auto classic = update_checksum_state_bytes(data);
    if (classic == expected) {
        return "classic";
    }

    const auto cyclic = update_cyclic_checksum_state_bytes(data);
    if (cyclic == expected) {
        return "cyclic";
    }

    throw PatchError(
        std::string(context)
        + " checksum mismatch: expected "
        + to_hex(expected)
        + ", classic "
        + to_hex(classic)
        + ", cyclic "
        + to_hex(cyclic)
    );
}

}  // namespace readrtp
