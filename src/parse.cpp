#include "readrtp/parse.hpp"

#include "readrtp/error.hpp"
#include "readrtp/patch_applier.hpp"

#include <algorithm>
#include <cctype>

using namespace readrtp;

namespace {

[[nodiscard]] bool case_insensitive_equal(
    std::string_view lhs,
    std::string_view rhs
) {
    if (lhs.size() != rhs.size()) {
        return false;
    }

    for (std::size_t index = 0; index < lhs.size(); ++index) {
        const auto l = static_cast<unsigned char>(lhs[index]);
        const auto r = static_cast<unsigned char>(rhs[index]);
        if (std::tolower(l) != std::tolower(r)) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] ChecksumBytes to_checksum_bytes(ByteView raw) {
    if (raw.size() != 10U) {
        throw PatchError("unexpected checksum length");
    }

    ChecksumBytes checksum{};
    std::copy(raw.begin(), raw.end(), checksum.begin());
    return checksum;
}

}  // namespace

namespace readrtp {

std::string read_package_string(BufferReader& reader, std::uint32_t string_flags) {
    if ((string_flags & 0x8U) != 0U) {
        throw PatchError("wide package strings are not yet supported");
    }

    const auto length = reader.read_u8();
    if (length == 0U) {
        return {};
    }

    const auto bytes = reader.read_bytes(length);
    return normalize_rel_path(std::string(bytes.begin(), bytes.end()));
}

bool engine_reads_second_delta(std::uint32_t engine_flags) {
    return (engine_flags & 0x7U) == 0U && ((engine_flags >> 16U) & 0x1U) != 0U;
}

std::string decode_latin1_cstring(ByteView raw) {
    auto end = std::find(raw.begin(), raw.end(), static_cast<std::uint8_t>(0));
    return normalize_rel_path(std::string(raw.begin(), end));
}

std::string read_len_prefixed_cstring(BufferReader& reader) {
    const auto raw = reader.read_len_prefixed_bytes();
    if (raw.empty()) {
        return {};
    }
    if (raw.back() != 0U) {
        throw PatchError("expected counted string to include a trailing NUL");
    }
    return decode_latin1_cstring(as_bytes(raw));
}

std::string expected_record_name(std::string_view path) {
    const auto normalized = normalize_rel_path(path);
    const auto slash = normalized.find_last_of('/');
    return slash == std::string::npos ? normalized : normalized.substr(slash + 1U);
}

std::size_t type_5000_max_size_hint(
    const std::optional<Type5000RecordMetadata>& metadata
) {
    if (!metadata.has_value() || metadata->entries.empty()) {
        return 0;
    }

    std::size_t max_hint = 0;
    for (const auto& entry : metadata->entries) {
        max_hint = std::max(max_hint, entry.size_hint);
    }
    return max_hint;
}

bool looks_like_record_flags(std::uint32_t flags) {
    const auto record_type = flags & 0xF000U;
    return record_type == 0x1000U
        || record_type == 0x2000U
        || record_type == 0x4000U
        || record_type == 0x5000U;
}

std::vector<std::string> read_legacy_banner_lines(BufferReader& reader) {
    const auto start_offset = reader.tell();
    const auto& data = reader.data();
    if (data.size() - start_offset < 2U) {
        return {};
    }

    const auto first_flags = static_cast<std::uint16_t>(data[start_offset])
        | (static_cast<std::uint16_t>(data[start_offset + 1U]) << 8U);
    if (looks_like_record_flags(first_flags)) {
        return {};
    }

    const auto line_count = reader.read_u16le();
    if (line_count == 0U) {
        reader.seek(start_offset);
        return {};
    }

    const auto candidate_offset = reader.tell()
        + static_cast<std::size_t>(line_count) * kLegacyBannerLineSize;
    if (candidate_offset > data.size() || data.size() - candidate_offset < 2U) {
        reader.seek(start_offset);
        return {};
    }

    const auto candidate_flags = static_cast<std::uint16_t>(data[candidate_offset])
        | (static_cast<std::uint16_t>(data[candidate_offset + 1U]) << 8U);
    if (!looks_like_record_flags(candidate_flags)) {
        reader.seek(start_offset);
        return {};
    }

    std::vector<std::string> lines;
    lines.reserve(line_count);
    for (std::size_t index = 0; index < line_count; ++index) {
        const auto raw = reader.read_bytes(kLegacyBannerLineSize);
        const auto nul = std::find(raw.begin(), raw.end(), static_cast<std::uint8_t>(0));
        auto line = std::string(raw.begin(), nul);
        while (!line.empty() && line.back() == ' ') {
            line.pop_back();
        }
        lines.push_back(normalize_rel_path(line));
    }
    return lines;
}

Type5000EntryMetadata read_type_5000_entry_metadata(
    BufferReader& reader,
    std::size_t start_offset,
    std::string_view expected_name,
    std::size_t entry_index
) {
    Type5000EntryMetadata metadata;
    metadata.short_name = decode_latin1_cstring(
        reader.read_bytes(kType2000ShortNameSize)
    );
    metadata.file_attributes = reader.read_u16le();
    metadata.size_hint = reader.read_u32le();
    reader.read_bytes(4);
    metadata.checksum = to_checksum_bytes(reader.read_bytes(10));
    reader.read_bytes(8);
    metadata.name = read_len_prefixed_cstring(reader);

    if (!case_insensitive_equal(metadata.name, expected_name)) {
        throw PatchError(
            "type-0x5000 record at offset " + std::to_string(start_offset)
            + " entry " + std::to_string(entry_index) + " embeds name "
            + metadata.name
        );
    }

    return metadata;
}

Type5000EntryMetadata read_legacy_type_5000_entry_metadata(BufferReader& reader) {
    Type5000EntryMetadata metadata;
    metadata.short_name = decode_latin1_cstring(
        reader.read_bytes(kType2000ShortNameSize)
    );
    metadata.file_attributes = reader.read_u16le();
    metadata.size_hint = reader.read_u32le();
    reader.read_bytes(4);
    metadata.checksum = to_checksum_bytes(reader.read_bytes(10));
    metadata.name = metadata.short_name;
    return metadata;
}

Record parse_type_5000_record(
    BufferReader& reader,
    std::size_t start_offset,
    std::uint32_t flags,
    std::optional<std::uint32_t> subflags,
    std::string_view path
) {
    const auto rel_next = reader.read_u32le();
    const auto history_version_count = reader.read_u16le();
    reader.read_bytes(10);
    const auto body_start = reader.tell();
    const auto next_record_offset = body_start + static_cast<std::size_t>(rel_next);
    if (next_record_offset < body_start || next_record_offset > reader.data().size()) {
        throw PatchError("record at offset " + std::to_string(start_offset)
            + " jumps outside package");
    }

    const auto expected_name = expected_record_name(path);
    const auto header_kind = reader.read_u16le();
    std::uint32_t inline_kind = 0;
    std::optional<std::uint32_t> variant_flags;
    if (header_kind == kType5000DirectHeaderKind) {
        inline_kind = reader.read_u8();
        if (inline_kind != kType5000DirectInlineKind) {
            throw PatchError("unsupported type-0x5000 inline kind");
        }
    } else if (header_kind == kType5000PatchHeaderKind) {
        variant_flags = reader.read_u16le();
        inline_kind = reader.read_u16le();
        if (*variant_flags != kType5000PatchVariantFlags) {
            throw PatchError("unsupported type-0x5000 variant flags");
        }
        if (inline_kind != kType5000PatchInlineKind) {
            throw PatchError("unsupported type-0x5000 inline kind");
        }
    } else {
        throw PatchError("unsupported type-0x5000 header kind");
    }

    const auto output_size = reader.read_u32le();
    const auto compressed_size = reader.read_u32le();
    auto primary_entry = read_type_5000_entry_metadata(
        reader, start_offset, expected_name, 1
    );
    std::optional<Type5000EntryMetadata> secondary_entry;
    if (header_kind == kType5000DirectHeaderKind) {
        if (primary_entry.size_hint != output_size) {
            throw PatchError(
                "type-0x5000 record at offset " + std::to_string(start_offset)
                + " repeats output size"
            );
        }
    } else {
        secondary_entry = read_type_5000_entry_metadata(
            reader, start_offset, expected_name, 2
        );
    }

    const auto stream_offset = reader.tell();
    const auto stream_end_offset = stream_offset
        + static_cast<std::size_t>(compressed_size);
    if (stream_end_offset < stream_offset
        || stream_end_offset > next_record_offset) {
        throw PatchError("record at offset " + std::to_string(start_offset)
            + " overruns package payload");
    }

    Type5000RecordMetadata metadata;
    metadata.header_kind = header_kind;
    metadata.inline_kind = inline_kind;
    metadata.is_instruction_stream = header_kind == kType5000PatchHeaderKind;
    metadata.variant_flags = variant_flags;
    metadata.primary_entry = std::move(primary_entry);
    metadata.secondary_entry = std::move(secondary_entry);
    metadata.entries.push_back(metadata.primary_entry);
    if (metadata.secondary_entry.has_value()) {
        metadata.entries.push_back(*metadata.secondary_entry);
    }

    Record record;
    record.offset = start_offset;
    record.flags = flags;
    record.subflags = subflags;
    record.path = std::string(path);
    record.next_record_offset = next_record_offset;
    record.history_version_count = history_version_count;
    record.body_offset = body_start;
    record.stream_offset = stream_offset;
    record.compressed_size = compressed_size;
    record.decompressed_size = output_size;
    record.type_5000 = std::move(metadata);
    return record;
}

Record parse_legacy_type_4000_record(
    BufferReader& reader,
    std::size_t start_offset,
    std::uint32_t flags,
    std::optional<std::uint32_t> subflags,
    std::string_view path
) {
    const auto body_start = reader.tell();
    reader.read_bytes(10);
    const auto variant_flags = reader.read_u16le();
    const auto inline_kind = reader.read_u16le();
    if (variant_flags != kType4000PatchVariantFlags) {
        throw PatchError("unsupported type-0x4000 variant flags");
    }
    if (inline_kind != kType4000PatchInlineKind) {
        throw PatchError("unsupported type-0x4000 inline kind");
    }

    const auto output_size = reader.read_u32le();
    const auto compressed_size = reader.read_u32le();
    auto primary_entry = read_legacy_type_5000_entry_metadata(reader);
    auto secondary_entry = read_legacy_type_5000_entry_metadata(reader);
    const auto stream_offset = reader.tell();
    const auto next_record_offset = stream_offset
        + static_cast<std::size_t>(compressed_size);
    if (next_record_offset < stream_offset
        || next_record_offset > reader.data().size()) {
        throw PatchError("record at offset " + std::to_string(start_offset)
            + " overruns package payload");
    }

    const auto resolved_path = !path.empty()
        ? std::string(path)
        : (!secondary_entry.name.empty() ? secondary_entry.name : primary_entry.name);

    Type5000RecordMetadata metadata;
    metadata.header_kind = kType4000PatchHeaderKind;
    metadata.inline_kind = inline_kind;
    metadata.is_instruction_stream = true;
    metadata.variant_flags = variant_flags;
    metadata.primary_entry = std::move(primary_entry);
    metadata.secondary_entry = std::move(secondary_entry);
    metadata.entries.push_back(metadata.primary_entry);
    metadata.entries.push_back(*metadata.secondary_entry);

    Record record;
    record.offset = start_offset;
    record.flags = flags;
    record.subflags = subflags;
    record.path = resolved_path;
    record.next_record_offset = next_record_offset;
    record.body_offset = body_start;
    record.stream_offset = stream_offset;
    record.compressed_size = compressed_size;
    record.decompressed_size = output_size;
    record.type_5000 = std::move(metadata);
    return record;
}

Record parse_type_2000_record(
    BufferReader& reader,
    std::size_t start_offset,
    std::uint32_t flags,
    std::optional<std::uint32_t> subflags,
    std::string_view path,
    bool legacy
) {
    const auto body_start = reader.tell();
    const auto path_selector = reader.read_bytes(10);
    const auto inline_kind_value = read_varint_from_reader(reader);
    if (inline_kind_value != 1) {
        throw PatchError("unsupported type-0x2000 inline kind");
    }

    const auto output_size = reader.read_u32le();
    const auto compressed_size = reader.read_u32le();
    auto short_name = decode_latin1_cstring(
        reader.read_bytes(kType2000ShortNameSize)
    );
    const auto file_attributes = reader.read_u16le();
    const auto repeated_output_size = reader.read_u32le();
    if (repeated_output_size != output_size) {
        throw PatchError("type-0x2000 record repeats output size");
    }

    std::string name;
    std::string resolved_path;
    ChecksumBytes checksum{};
    if (legacy) {
        reader.read_bytes(4);
        checksum = to_checksum_bytes(reader.read_bytes(10));
        name = short_name;
        resolved_path = !path.empty() ? std::string(path) : short_name;
    } else {
        reader.read_bytes(4);
        checksum = to_checksum_bytes(reader.read_bytes(10));
        reader.read_bytes(8);
        name = read_len_prefixed_cstring(reader);
        const auto expected_name = expected_record_name(path);
        if (!case_insensitive_equal(name, expected_name)) {
            throw PatchError("type-0x2000 record embeds mismatched name");
        }
        resolved_path = std::string(path);
    }

    const auto compressed_offset = reader.tell();
    const auto next_record_offset = compressed_offset
        + static_cast<std::size_t>(compressed_size);
    if (next_record_offset < compressed_offset
        || next_record_offset > reader.data().size()) {
        throw PatchError("record at offset " + std::to_string(start_offset)
            + " overruns package payload");
    }

    Type2000RecordMetadata metadata;
    metadata.path_selector = std::move(path_selector);
    metadata.inline_kind = static_cast<std::uint32_t>(inline_kind_value);
    metadata.is_instruction_stream = false;
    metadata.short_name = std::move(short_name);
    metadata.file_attributes = file_attributes;
    metadata.checksum = checksum;
    metadata.name = std::move(name);

    Record record;
    record.offset = start_offset;
    record.flags = flags;
    record.subflags = subflags;
    record.path = std::move(resolved_path);
    record.next_record_offset = next_record_offset;
    record.body_offset = body_start;
    record.compressed_offset = compressed_offset;
    record.compressed_size = compressed_size;
    record.decompressed_size = output_size;
    record.type_2000 = std::move(metadata);
    return record;
}

std::optional<Record> parse_record(
    BufferReader& reader,
    std::uint32_t package_flags,
    std::uint32_t engine_flags,
    std::uint32_t string_flags,
    bool has_legacy_records
) {
    const auto start_offset = reader.tell();
    const auto flags = reader.read_u16le();
    const auto record_type = flags & 0xF000U;
    if (record_type == 0x1000U) {
        return std::nullopt;
    }

    std::optional<std::uint32_t> subflags;
    auto effective_subflags = package_flags;
    if ((flags & 0x2U) != 0U) {
        subflags = reader.read_u16le();
        effective_subflags = *subflags;
    }

    std::string path;
    if ((flags & 0x4U) != 0U) {
        path = read_package_string(reader, string_flags);
    }

    if ((effective_subflags & 0xC0U) != 0U) {
        (void) read_varint_from_reader(reader);
        if (engine_reads_second_delta(engine_flags)) {
            (void) read_varint_from_reader(reader);
        }
    }

    if ((flags & 0x80U) != 0U) {
        (void) read_varint_from_reader(reader);
    }

    if ((flags & 0x100U) != 0U) {
        reader.read_u16le();
    }

    if ((flags & 0x200U) != 0U && record_type != 0x5000U) {
        (void) read_package_string(reader, string_flags);
        (void) read_package_string(reader, string_flags);
    }

    if (record_type == 0x5000U) {
        return parse_type_5000_record(reader, start_offset, flags, subflags, path);
    }
    if (record_type == 0x2000U) {
        return parse_type_2000_record(
            reader, start_offset, flags, subflags, path, has_legacy_records
        );
    }
    if (record_type == 0x4000U && has_legacy_records) {
        return parse_legacy_type_4000_record(
            reader, start_offset, flags, subflags, path
        );
    }

    throw PatchError(
        "unsupported record type " + std::to_string(record_type)
        + " at offset " + std::to_string(start_offset)
    );
}

Package parse_package(ByteView data) {
    BufferReader reader(make_byte_buffer(data));
    const auto magic = reader.read_u16le();
    if (magic != 0x2A4BU) {
        throw PatchError("unexpected package magic");
    }

    const auto version = reader.read_u16le();
    const auto flags = reader.read_u16le();
    const auto engine_flags = (flags & 0x8000U) != 0U ? reader.read_u32le() : 0U;
    const auto package_flags = reader.read_u16le();
    reader.read_u32le();
    reader.read_u32le();
    reader.read_u16le();
    reader.read_u16le();
    const auto string_flags = reader.read_u16le();
    if ((string_flags & 0x4U) != 0U) {
        reader.read_u32le();
    }
    reader.read_u32le();

    std::vector<std::string> roots;
    if ((flags & 0x0200U) != 0U) {
        const auto root_count = reader.read_u16le();
        roots.reserve(root_count);
        for (std::size_t index = 0; index < root_count; ++index) {
            roots.push_back(read_package_string(reader, string_flags));
        }
    }

    const auto banner_lines = read_legacy_banner_lines(reader);

    std::vector<Record> records;
    while (!reader.eof()) {
        const auto record = parse_record(
            reader,
            package_flags,
            engine_flags,
            string_flags,
            !banner_lines.empty()
        );
        if (!record.has_value()) {
            break;
        }
        records.push_back(*record);
        reader.seek(record->next_record_offset);
    }

    if (records.empty()) {
        throw PatchError("did not recover any records from package");
    }

    Package package;
    package.version = version;
    package.flags = flags;
    package.engine_flags = engine_flags;
    package.package_flags = package_flags;
    package.string_flags = string_flags;
    package.roots = std::move(roots);
    package.records = std::move(records);
    package.banner_lines = std::move(banner_lines);
    return package;
}

}  // namespace readrtp
