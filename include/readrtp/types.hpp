#pragma once

#include "readrtp/common.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace readrtp {

struct DeferredBlock {
    std::int32_t file_id{0};
    std::size_t offset{0};
    std::size_t length{0};
};

struct PendingLiteralBlock {
    std::size_t offset{0};
    std::size_t length{0};
    std::optional<std::size_t> output_offset;
};

struct Type2000RecordMetadata {
    ByteBuffer path_selector;
    std::uint32_t inline_kind{0};
    bool is_instruction_stream{false};
    std::string short_name;
    std::uint32_t file_attributes{0};
    ChecksumBytes checksum{};
    std::string name;
};

struct Type5000EntryMetadata {
    std::string short_name;
    std::uint32_t file_attributes{0};
    std::size_t size_hint{0};
    ChecksumBytes checksum{};
    std::string name;
};

struct Type5000RecordMetadata {
    std::uint32_t header_kind{0};
    std::uint32_t inline_kind{0};
    bool is_instruction_stream{false};
    std::optional<std::uint32_t> variant_flags;
    Type5000EntryMetadata primary_entry;
    std::optional<Type5000EntryMetadata> secondary_entry;
    std::vector<Type5000EntryMetadata> entries;
};

struct Record {
    std::size_t offset{0};
    std::uint32_t flags{0};
    std::optional<std::uint32_t> subflags;
    std::string path;
    std::size_t next_record_offset{0};
    std::size_t history_version_count{1};
    std::optional<std::size_t> body_offset;
    std::optional<std::size_t> stream_offset;
    std::optional<std::size_t> compressed_offset;
    std::optional<std::size_t> compressed_size;
    std::optional<ChecksumBytes> checksum;
    std::optional<std::size_t> decompressed_size;
    std::optional<Type2000RecordMetadata> type_2000;
    std::optional<Type5000RecordMetadata> type_5000;

    [[nodiscard]] bool is_instruction_stream() const;
};

struct Package {
    std::uint32_t version{0};
    std::uint32_t flags{0};
    std::uint32_t engine_flags{0};
    std::uint32_t package_flags{0};
    std::uint32_t string_flags{0};
    std::vector<std::string> roots;
    std::vector<Record> records;
    std::vector<std::string> banner_lines;
};

struct CompressedStream {
    std::size_t offset{0};
    std::size_t bytes_consumed{0};
    ByteBuffer payload;
};

struct RecordVersion {
    Record record;
    std::size_t version_index{0};
    std::size_t stream_offset{0};
    std::size_t stream_end{0};
};

struct RecordFileVersions {
    Record record;
    std::vector<RecordVersion> versions;
};

}  // namespace readrtp
