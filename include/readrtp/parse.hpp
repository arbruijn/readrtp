#pragma once

#include "readrtp/buffer.hpp"
#include "readrtp/common.hpp"
#include "readrtp/types.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace readrtp {

inline constexpr std::size_t kType2000ShortNameSize = 14;
inline constexpr std::uint16_t kType5000DirectHeaderKind = 0x02C2;
inline constexpr std::uint16_t kType5000PatchHeaderKind = 0x02C4;
inline constexpr std::uint16_t kType5000DirectInlineKind = 0x0001;
inline constexpr std::uint16_t kType5000PatchInlineKind = 0x0101;
inline constexpr std::uint16_t kType5000PatchVariantFlags = 0x0009;
inline constexpr std::uint16_t kType4000PatchHeaderKind = 0x4000;
inline constexpr std::uint16_t kType4000PatchInlineKind = 0x0101;
inline constexpr std::uint16_t kType4000PatchVariantFlags = 0x0009;
inline constexpr std::size_t kLegacyBannerLineSize = 37;


[[nodiscard]] std::string read_package_string(
    BufferReader& reader,
    std::uint32_t string_flags
);

[[nodiscard]] bool engine_reads_second_delta(std::uint32_t engine_flags);

[[nodiscard]] std::string decode_latin1_cstring(ByteView raw);

[[nodiscard]] std::string read_len_prefixed_cstring(BufferReader& reader);

[[nodiscard]] std::string expected_record_name(std::string_view path);

[[nodiscard]] std::size_t type_5000_max_size_hint(
    const std::optional<Type5000RecordMetadata>& metadata
);

[[nodiscard]] bool looks_like_record_flags(std::uint32_t flags);

[[nodiscard]] std::vector<std::string> read_legacy_banner_lines(
    BufferReader& reader
);

[[nodiscard]] Type5000EntryMetadata read_type_5000_entry_metadata(
    BufferReader& reader,
    std::size_t start_offset,
    std::string_view expected_name,
    std::size_t entry_index
);

[[nodiscard]] Type5000EntryMetadata read_legacy_type_5000_entry_metadata(
    BufferReader& reader
);

[[nodiscard]] Record parse_type_5000_record(
    BufferReader& reader,
    std::size_t start_offset,
    std::uint32_t flags,
    std::optional<std::uint32_t> subflags,
    std::string_view path
);

[[nodiscard]] Record parse_legacy_type_4000_record(
    BufferReader& reader,
    std::size_t start_offset,
    std::uint32_t flags,
    std::optional<std::uint32_t> subflags,
    std::string_view path
);

[[nodiscard]] Record parse_type_2000_record(
    BufferReader& reader,
    std::size_t start_offset,
    std::uint32_t flags,
    std::optional<std::uint32_t> subflags,
    std::string_view path,
    bool legacy
);

[[nodiscard]] std::optional<Record> parse_record(
    BufferReader& reader,
    std::uint32_t package_flags,
    std::uint32_t engine_flags,
    std::uint32_t string_flags,
    bool has_legacy_records
);


[[nodiscard]] Package parse_package(ByteView data);

}  // namespace readrtp
