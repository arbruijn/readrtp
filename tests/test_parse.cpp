#include "readrtp/buffer.hpp"
#include "readrtp/parse.hpp"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <filesystem>
#include <string>
#include <utility>
#include <vector>

namespace {

constexpr std::size_t kType5000EntryTrailingMetadataSize = 22;

void append_u8(readrtp::ByteBuffer& out, std::uint8_t value) {
    out.push_back(value);
}

void append_u16le(readrtp::ByteBuffer& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>(value & 0xFFU));
    out.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
}

void append_u32le(readrtp::ByteBuffer& out, std::uint32_t value) {
    out.push_back(static_cast<std::uint8_t>(value & 0xFFU));
    out.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
    out.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xFFU));
    out.push_back(static_cast<std::uint8_t>((value >> 24U) & 0xFFU));
}

void append_bytes(readrtp::ByteBuffer& out, readrtp::ByteView bytes) {
    out.insert(out.end(), bytes.begin(), bytes.end());
}

void append_string(readrtp::ByteBuffer& out, std::string_view value) {
    out.insert(out.end(), value.begin(), value.end());
}

readrtp::ByteBuffer encode_short_name(std::string_view name) {
    readrtp::ByteBuffer out(readrtp::kType2000ShortNameSize, 0);
    const auto count = std::min(name.size(), out.size());
    std::copy_n(name.begin(), static_cast<std::ptrdiff_t>(count), out.begin());
    return out;
}

readrtp::ByteBuffer encode_counted_cstring(std::string_view name) {
    readrtp::ByteBuffer out;
    const auto raw_size = name.size() + 1U;
    assert(raw_size < 0xFFU);
    append_u8(out, static_cast<std::uint8_t>(raw_size));
    append_string(out, name);
    append_u8(out, 0);
    return out;
}

readrtp::ByteBuffer build_type_5000_entry(
    std::string_view short_name,
    std::uint16_t file_attributes,
    std::uint32_t size_hint,
    std::string_view name,
    std::uint8_t checksum_seed
) {
    readrtp::ByteBuffer out;
    append_bytes(out, encode_short_name(short_name));
    append_u16le(out, file_attributes);
    append_u32le(out, size_hint);
    out.insert(out.end(), kType5000EntryTrailingMetadataSize, checksum_seed);
    append_bytes(out, encode_counted_cstring(name));
    return out;
}

readrtp::ByteBuffer build_type_5000_record(
    std::string_view payload,
    std::uint16_t header_kind,
    std::uint32_t decompressed_size,
    std::vector<readrtp::ByteBuffer> entries,
    std::uint16_t variant_flags = 0,
    std::uint16_t inline_kind = 1,
    std::uint16_t history_version_count = 1,
    std::string_view trailer = {}
) {
    readrtp::ByteBuffer body;
    if (header_kind == readrtp::kType5000DirectHeaderKind) {
        append_u16le(body, header_kind);
        append_u8(body, static_cast<std::uint8_t>(inline_kind));
    } else {
        append_u16le(body, header_kind);
        append_u16le(body, variant_flags);
        append_u16le(body, inline_kind);
    }
    append_u32le(body, decompressed_size);
    append_u32le(body, static_cast<std::uint32_t>(payload.size()));
    for (const auto& entry : entries) {
        append_bytes(body, entry);
    }

    readrtp::ByteBuffer out;
    append_u32le(
        out,
        static_cast<std::uint32_t>(body.size() + payload.size() + trailer.size())
    );
    append_u16le(out, history_version_count);
    out.insert(out.end(), 10, 0);
    append_bytes(out, body);
    append_string(out, payload);
    append_string(out, trailer);
    return out;
}

readrtp::ByteBuffer build_type_2000_record(
    std::string_view path,
    std::string_view payload,
    std::string_view short_name,
    std::uint16_t file_attributes,
    std::uint32_t output_size,
    bool legacy
) {
    readrtp::ByteBuffer out;
    out.insert(out.end(), 10, 0);
    append_u8(out, 1);
    append_u32le(out, output_size);
    append_u32le(out, static_cast<std::uint32_t>(payload.size()));
    append_bytes(out, encode_short_name(short_name));
    append_u16le(out, file_attributes);
    append_u32le(out, output_size);
    out.insert(out.end(), 4, 0);
    out.insert(out.end(), 10, 0xAA);
    if (!legacy) {
        out.insert(out.end(), 8, 0);
        append_bytes(out, encode_counted_cstring(path.substr(path.find_last_of('/') + 1U)));
    }
    append_string(out, payload);
    return out;
}

readrtp::ByteBuffer build_legacy_4000_record_body(
    std::string_view short_name,
    std::uint32_t output_size,
    std::string_view payload
) {
    readrtp::ByteBuffer out;
    out.insert(out.end(), 10, 0);
    append_u16le(out, readrtp::kType4000PatchVariantFlags);
    append_u16le(out, readrtp::kType4000PatchInlineKind);
    append_u32le(out, output_size);
    append_u32le(out, static_cast<std::uint32_t>(payload.size()));
    append_bytes(out, encode_short_name(short_name));
    append_u16le(out, 0x0020);
    append_u32le(out, output_size);
    out.insert(out.end(), 4, 0);
    out.insert(out.end(), 10, 0x55);
    append_bytes(out, encode_short_name(short_name));
    append_u16le(out, 0x0020);
    append_u32le(out, output_size);
    out.insert(out.end(), 4, 0);
    out.insert(out.end(), 10, 0x66);
    append_string(out, payload);
    return out;
}

readrtp::ByteBuffer build_legacy_package() {
    readrtp::ByteBuffer out;
    append_u16le(out, 0x2A4B);
    append_u16le(out, 0x0001);
    append_u16le(out, 0x0000);
    append_u16le(out, 0x0030);
    append_u32le(out, 0);
    append_u32le(out, 0);
    append_u16le(out, 0);
    append_u16le(out, 0);
    append_u16le(out, 0);
    append_u32le(out, 0);

    append_u16le(out, 2);
    auto line1 = readrtp::ByteBuffer(37, 0x20);
    const std::string line1_text = "Legacy banner line 1";
    std::copy(line1_text.begin(), line1_text.end(), line1.begin());
    line1[line1_text.size()] = 0;
    append_bytes(out, line1);

    auto line2 = readrtp::ByteBuffer(37, 0x20);
    const std::string line2_text = "Second banner line";
    std::copy(line2_text.begin(), line2_text.end(), line2.begin());
    line2[line2_text.size()] = 0;
    append_bytes(out, line2);

    append_u16le(out, 0x4000);
    append_bytes(
        out,
        build_legacy_4000_record_body("DESCENTR.EXE", 0x10, "abcde")
    );
    append_u16le(out, 0x1000);
    return out;
}

}  // namespace

int main() {
    {
        const auto data = readrtp::read_file_bytes("data.bin");
        const auto package = readrtp::parse_package(readrtp::as_bytes(data));

        assert(package.version == 0x019A);
        assert(package.flags == 0x93E4);
        assert(package.engine_flags == 0x00010000);
        assert(package.package_flags == 0x0030);
        assert(package.string_flags == 0x0004);
        assert(package.roots.size() == 4);
        assert(package.banner_lines.empty());
        assert(package.records.size() == 33);
        assert(package.records.front().path == "netgames/Anarchy.d3m");
        assert(package.records.back().path == "LANGUAGE/readmes/ONLINERES.txt");

        const auto& by_path = package.records;
        const auto find_record = [&by_path](std::string_view path) -> const readrtp::Record& {
            for (const auto& record : by_path) {
                if (record.path == path) {
                    return record;
                }
            }
            assert(false && "missing expected record");
            return by_path.front();
        };

        const auto& anarchy = find_record("netgames/Anarchy.d3m");
        assert(anarchy.body_offset == 0x83);
        assert(anarchy.stream_offset == 0xFF);
        assert(anarchy.compressed_size == 0x29AD);
        assert(anarchy.decompressed_size == 0x3384);
        assert(anarchy.history_version_count == 3);
        assert(anarchy.type_5000.has_value());
        assert(anarchy.type_5000->header_kind == 0x02C4);
        assert(anarchy.type_5000->variant_flags == 0x0009);
        assert(anarchy.type_5000->inline_kind == 0x0101);
        assert(anarchy.type_5000->is_instruction_stream);
        assert(anarchy.type_5000->entries.size() == 2);

        const auto& version_new = find_record("version.new");
        assert(version_new.body_offset == 0x176D53);
        assert(version_new.stream_offset == 0x176D95);
        assert(version_new.compressed_size == 0x5A);
        assert(version_new.decompressed_size == 0x44);
        assert(version_new.history_version_count == 1);
        assert(version_new.type_5000.has_value());
        assert(version_new.type_5000->header_kind == 0x02C2);
        assert(!version_new.type_5000->is_instruction_stream);

        const auto& panther = find_record("panther.ctl");
        assert(panther.type_2000.has_value());
        assert(panther.type_2000->path_selector == readrtp::ByteBuffer(10, 0));
        assert(panther.type_2000->inline_kind == 1);
        assert(panther.type_2000->short_name == "panther.ctl");
        assert(panther.type_2000->name == "panther.ctl");
        assert(!panther.type_2000->is_instruction_stream);
    }

    {
        const auto record_bytes = build_type_5000_record(
            "plain replacement payload",
            readrtp::kType5000DirectHeaderKind,
            0x44,
            {
                build_type_5000_entry(
                    "version.new",
                    0x0020,
                    0x44,
                    "version.new",
                    0x41
                ),
            }
        );
        readrtp::BufferReader reader(record_bytes);
        const auto record = readrtp::parse_type_5000_record(
            reader,
            0,
            0x5000,
            std::nullopt,
            "docs/version.new"
        );

        assert(record.body_offset == 0x10);
        assert(record.history_version_count == 1);
        assert(record.stream_offset == record_bytes.size() - 25U);
        assert(record.compressed_size == 25U);
        assert(record.decompressed_size == 0x44);
        assert(record.type_5000.has_value());
        assert(record.type_5000->header_kind == readrtp::kType5000DirectHeaderKind);
        assert(record.type_5000->inline_kind == 1U);
        assert(!record.type_5000->is_instruction_stream);
        assert(record.type_5000->secondary_entry.has_value() == false);
    }

    {
        const auto payload = std::string_view("patch payload without marker");
        const auto trailer = std::string_view("\xb5\x9ctrailing-marker", 17);
        const auto record_bytes = build_type_5000_record(
            payload,
            readrtp::kType5000PatchHeaderKind,
            0x3384,
            {
                build_type_5000_entry(
                    "Anarchy.d3m",
                    0x0080,
                    0x26E02,
                    "Anarchy.d3m",
                    0x42
                ),
                build_type_5000_entry(
                    "Anarchy.d3m",
                    0x0080,
                    0x26E16,
                    "Anarchy.d3m",
                    0x43
                ),
            },
            0x0009,
            0x0101,
            1,
            trailer
        );
        readrtp::BufferReader reader(record_bytes);
        const auto record = readrtp::parse_type_5000_record(
            reader,
            0,
            0x5000,
            std::nullopt,
            "netgames/Anarchy.d3m"
        );

        assert(record.history_version_count == 1);
        assert(record.stream_offset == record_bytes.size() - payload.size() - trailer.size());
        assert(record.compressed_size == payload.size());
        assert(record.type_5000.has_value());
        assert(record.type_5000->secondary_entry.has_value());
        assert(record.type_5000->is_instruction_stream);
    }

    {
        const auto record_bytes = build_type_2000_record(
            "docs/version.new",
            "output payload",
            "version.new",
            0x0020,
            0x44,
            false
        );
        readrtp::BufferReader reader(record_bytes);
        const auto record = readrtp::parse_type_2000_record(
            reader,
            0,
            0x2000,
            std::nullopt,
            "docs/version.new",
            false
        );

        assert(record.body_offset == 0);
        assert(record.compressed_offset == record_bytes.size() - 14U);
        assert(record.compressed_size == 14U);
        assert(record.decompressed_size == 0x44);
        assert(record.type_2000.has_value());
        assert(record.type_2000->short_name == "version.new");
        assert(record.type_2000->name == "version.new");
        assert(record.path == "docs/version.new");
    }

    {
        const auto record_bytes = build_type_2000_record(
            "README.TXT",
            "legacy payload",
            "README.TXT",
            0x0020,
            0x44,
            true
        );
        readrtp::BufferReader reader(record_bytes);
        const auto record = readrtp::parse_type_2000_record(
            reader,
            0,
            0x2000,
            std::nullopt,
            "",
            true
        );

        assert(record.path == "README.TXT");
        assert(record.type_2000.has_value());
        assert(record.type_2000->name == "README.TXT");
        assert(record.type_2000->short_name == "README.TXT");
    }

    {
        const auto data = build_legacy_package();
        const auto package = readrtp::parse_package(readrtp::as_bytes(data));

        assert(package.banner_lines.size() == 2);
        assert(package.banner_lines[0] == "Legacy banner line 1");
        assert(package.banner_lines[1] == "Second banner line");
        assert(package.records.size() == 1);

        const auto& record = package.records.front();
        assert(record.path == "DESCENTR.EXE");
        assert(record.flags == 0x4000);
        assert(record.history_version_count == 1);
        assert(record.type_5000.has_value());
        assert(record.type_5000->header_kind == 0x4000);
        assert(record.type_5000->is_instruction_stream);
        assert(record.type_5000->entries.size() == 2);
        assert(record.type_5000->primary_entry.name == "DESCENTR.EXE");
        assert(record.type_5000->secondary_entry.has_value());
    }

    {
        readrtp::BufferReader reader(readrtp::ByteBuffer{0x00, 0x10});
        const auto record = readrtp::parse_record(reader, 0, 0, 0, false);
        assert(!record.has_value());
    }

    return 0;
}
