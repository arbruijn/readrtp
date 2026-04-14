#include "readrtp/patch_applier.hpp"

#include "readrtp/buffer.hpp"
#include "readrtp/checksum.hpp"
#include "readrtp/error.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

namespace readrtp {

namespace {

[[nodiscard]] std::string to_lower_copy(std::string value) {
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); }
    );
    return value;
}

[[nodiscard]] std::string format_hex(std::size_t value) {
    std::ostringstream stream;
    stream << "0x" << std::hex << value;
    return stream.str();
}

[[nodiscard]] std::string format_optional_size(
    const std::optional<std::size_t>& value
) {
    if (!value.has_value()) {
        return "None";
    }
    return std::to_string(*value);
}

}  // namespace


std::string normalize_rel_path(std::string_view path) {
    std::string normalized(path);
    while (!normalized.empty() && normalized.back() == '\0') {
        normalized.pop_back();
    }
    std::replace(normalized.begin(), normalized.end(), '\\', '/');
    return normalized;
}

std::filesystem::path resolve_casefold_path(
    const std::filesystem::path& base_dir,
    std::string_view rel_path
) {
    auto current = base_dir;
    const std::filesystem::path normalized(normalize_rel_path(rel_path));

    for (const auto& part : normalized) {
        if (part.empty() || part == ".") {
            continue;
        }

        const auto candidate = current / part;
        if (std::filesystem::exists(candidate)) {
            current = candidate;
            continue;
        }

        if (!std::filesystem::is_directory(current)) {
            current = candidate;
            continue;
        }

        const auto wanted = part.string();
        const auto folded = to_lower_copy(wanted);
        auto matched = false;
        for (const auto& entry : std::filesystem::directory_iterator(current)) {
            if (to_lower_copy(entry.path().filename().string()) == folded) {
                current = entry.path();
                matched = true;
                break;
            }
        }

        if (!matched) {
            current = candidate;
        }
    }

    return current;
}

std::pair<std::int64_t, std::size_t> read_varint(ByteView data, std::size_t pos) {
    if (pos >= data.size()) {
        throw PatchError("unexpected EOF in variable-length integer");
    }

    const auto first = data[pos++];
    std::uint8_t prefix_mask = 0x40;
    std::uint8_t value_mask = 0x3F;
    std::size_t extra = 0;
    while ((first & prefix_mask) != 0U) {
        ++extra;
        prefix_mask >>= 1U;
        value_mask >>= 1U;
    }

    std::int64_t value = first & value_mask;
    ByteBuffer extra_bytes;
    extra_bytes.reserve(extra);
    for (std::size_t index = 0; index < extra; ++index) {
        if (pos >= data.size()) {
            throw PatchError("truncated variable-length integer");
        }
        extra_bytes.push_back(data[pos++]);
    }

    for (auto it = extra_bytes.rbegin(); it != extra_bytes.rend(); ++it) {
        value = (value << 8U) | *it;
    }
    if ((first & 0x80U) != 0U) {
        value = -value;
    }
    return {value, pos};
}

std::int64_t read_varint_from_reader(BufferReader& reader) {
    const auto [value, next_pos] = read_varint(as_bytes(reader.data()), reader.tell());
    reader.seek(next_pos);
    return value;
}


PatchApplier::PatchApplier(
    ByteBuffer patch_bytes,
    std::filesystem::path target_dir,
    const Record& record,
    std::size_t output_size,
    std::size_t stream_offset,
    std::optional<ChecksumBytes> expected_input_checksum,
    std::optional<ChecksumBytes> expected_output_checksum,
    bool trace
) : patch_bytes_(std::move(patch_bytes)),
    reader_(patch_bytes_, stream_offset),
    target_dir_(std::move(target_dir)),
    record_(record),
    output_rel_path_(normalize_rel_path(record.path)),
    out_path_(resolve_casefold_path(target_dir_, output_rel_path_)),
    output_size_(output_size),
    expected_input_checksum_(expected_input_checksum),
    expected_output_checksum_(expected_output_checksum),
    trace_(trace) {
    reset_version_state();
}

std::size_t PatchApplier::apply_one_version() {
    while (!reader_.eof()) {
        const auto opcode = reader_.read_u8();
        if (trace_) {
            std::cout << "op:" << static_cast<unsigned int>(opcode)
                      << " @" << output_cursor_ << '\n';
        }

        if (opcode == 1U) {
            if (!pending_literal_blocks_.empty()) {
                throw PatchError(
                    "instruction stream reached end-of-version with pending literal blocks"
                );
            }
            output_image_->save();
            return reader_.tell();
        }

        if (opcode == 2U) {
            select_source_file(static_cast<std::int32_t>(
                read_nonnegative_varint("file id")
            ));
            continue;
        }

        if (opcode == 3U || opcode == 4U) {
            const auto literal_prefix = opcode == 4U
                ? read_nonnegative_varint("literal prefix")
                : 0U;
            write_output_block(
                read_inline_output_block(),
                literal_prefix
            );
            continue;
        }

        if (opcode == 5U) {
            process_pending_literals();
            continue;
        }

        if (opcode == 6U) {
            apply_single_byte_delta();
            continue;
        }

        if (opcode == 7U) {
            apply_uniform_add_queue(1U);
            continue;
        }

        if (opcode == 8U) {
            deferred_output_blocks_.push_back(read_inline_output_block());
            continue;
        }

        if (opcode == 9U || opcode == 10U) {
            const auto literal_prefix = opcode == 10U
                ? read_nonnegative_varint("literal prefix")
                : 0U;
            const auto block_index = read_nonnegative_varint("output block index");
            if (block_index >= deferred_output_blocks_.size()) {
                throw PatchError(
                    "output block index " + std::to_string(block_index)
                    + " is out of range at " + format_hex(reader_.tell() - 1U)
                );
            }
            write_output_block(
                deferred_output_blocks_[block_index],
                literal_prefix
            );
            continue;
        }

        if (opcode == 11U || opcode == 12U) {
            if (opcode == 12U) {
                const auto literal_prefix = read_nonnegative_varint("literal prefix");
                queue_pending_literal(literal_prefix, output_cursor_);
            }
            const auto length = read_nonnegative_varint("fill length");
            const ByteBuffer zero_pattern{0U};
            fill_output_with_pattern(as_bytes(zero_pattern), length);
            continue;
        }

        if (opcode == 13U) {
            apply_queue_type_d();
            continue;
        }

        if (opcode == 14U) {
            apply_uniform_add_queue(1U);
            continue;
        }

        if (opcode == 15U) {
            apply_uniform_add_queue(2U);
            continue;
        }

        if (opcode == 16U) {
            apply_uniform_add_queue(4U);
            continue;
        }

        if (opcode >= 17U && opcode <= 22U) {
            if (opcode >= 20U) {
                const auto literal_prefix = read_nonnegative_varint("literal prefix");
                queue_pending_literal(literal_prefix, output_cursor_);
            }

            const auto pattern_width = std::size_t{
                opcode == 17U ? 1U
                : opcode == 18U ? 2U
                : opcode == 19U ? 4U
                : opcode == 20U ? 1U
                : opcode == 21U ? 2U
                : 4U
            };
            const auto pattern = reader_.read_bytes(pattern_width);
            if (trace_) {
                std::cout << "b*" << pattern_width << '\n';
            }
            const auto length = read_nonnegative_varint("fill length");
            fill_output_with_pattern(as_bytes(pattern), length);
            continue;
        }

        throw PatchError(
            "unsupported opcode " + format_hex(opcode)
            + " at offset " + format_hex(reader_.tell() - 1U)
        );
    }

    throw PatchError(
        "instruction stream ended without an opcode 0x01 version terminator"
    );
}

void PatchApplier::apply() {
    if (expected_input_checksum_.has_value()) {
        const auto current_bytes = std::filesystem::exists(out_path_)
            ? read_file_bytes(out_path_)
            : ByteBuffer{};
        const auto verification_kind = verify_checksum(
            as_bytes(current_bytes),
            *expected_input_checksum_,
            "source file for '" + record_.path + "'"
        );
        (void) verification_kind;
    }

    const auto version_end = apply_one_version();
    (void) version_end;
    if (!reader_.eof()) {
        throw PatchError(
            "instruction stream for '" + record_.path + "' has "
            + std::to_string(reader_.remaining())
            + " trailing bytes after one version payload"
        );
    }

    if (expected_output_checksum_.has_value()) {
        const auto output_bytes = read_file_bytes(out_path_);
        const auto verification_kind = verify_checksum(
            as_bytes(output_bytes),
            *expected_output_checksum_,
            "output file for '" + record_.path + "'"
        );
        (void) verification_kind;
    }
}

void PatchApplier::reset_version_state() {
    source_image_.emplace(out_path_);
    output_image_.emplace(out_path_, ByteBuffer{});
    output_image_->ensure_size(output_size_);
    selected_file_id_.reset();
    output_cursor_ = 0;
    delta_cursor_ = 0;
    deferred_output_blocks_.clear();
    pending_literal_blocks_.clear();
}

std::int64_t PatchApplier::read_patch_varint() {
    return read_varint_from_reader(reader_);
}

std::size_t PatchApplier::read_nonnegative_varint(std::string_view what) {
    const auto value = read_patch_varint();
    if (value < 0) {
        throw PatchError(
            std::string(what) + " must be non-negative, got "
            + std::to_string(value)
        );
    }
    if (trace_) {
        std::cout << "vli:" << value << '\n';
    }
    return static_cast<std::size_t>(value);
}

std::int64_t PatchApplier::read_signed_value(std::size_t width) {
    if (width == 0U || width > sizeof(std::int64_t)) {
        throw PatchError("unsupported signed value width");
    }

    const auto bytes = reader_.read_bytes(width);
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < width; ++index) {
        value |= static_cast<std::uint64_t>(bytes[index]) << (index * 8U);
    }

    const auto sign_bit = static_cast<std::uint64_t>(1) << ((width * 8U) - 1U);
    if ((value & sign_bit) != 0U && width < sizeof(std::int64_t)) {
        value |= (~static_cast<std::uint64_t>(0)) << (width * 8U);
    }
    return static_cast<std::int64_t>(value);
}

void PatchApplier::select_source_file(std::int32_t file_id) {
    if (file_id != 0) {
        throw PatchError(
            "unsupported file id " + std::to_string(file_id)
            + " for '" + record_.path + "'"
        );
    }
    selected_file_id_ = file_id;
    output_cursor_ = 0;
    delta_cursor_ = 0;
}

MutableFile& PatchApplier::require_source_image() {
    if (!selected_file_id_.has_value()) {
        throw PatchError("instruction stream used file data before opcode 0x02");
    }
    return *source_image_;
}

void PatchApplier::queue_pending_literal(
    std::size_t length,
    std::optional<std::size_t> output_offset
) {
    if (length == 0U) {
        return;
    }

    (void) require_source_image();
    if (trace_) {
        std::cout << "queued " << length << " @"
                  << format_optional_size(output_offset) << '\n';
    }

    pending_literal_blocks_.push_back(PendingLiteralBlock{
        .offset = output_cursor_,
        .length = length,
        .output_offset = output_offset,
    });
    output_image_->fill_at(output_cursor_, length, 0);
    output_cursor_ += length;
}

void PatchApplier::write_output_block(
    const DeferredBlock& block,
    std::size_t literal_prefix
) {
    if (block.file_id != 0) {
        throw PatchError(
            "unsupported output file id " + std::to_string(block.file_id)
            + " for '" + record_.path + "'"
        );
    }

    if (literal_prefix != 0U) {
        queue_pending_literal(literal_prefix, output_cursor_);
    }

    auto& source_image = require_source_image();
    const auto chunk = source_image.read_at(block.offset, block.length);
    output_image_->write_at(output_cursor_, as_bytes(chunk));
    output_cursor_ += block.length;
}

DeferredBlock PatchApplier::read_inline_output_block() {
    DeferredBlock block;
    block.file_id = 0;
    block.offset = read_nonnegative_varint("output offset");
    block.length = read_nonnegative_varint("output length");
    return block;
}

void PatchApplier::fill_output_with_pattern(ByteView pattern, std::size_t length) {
    (void) require_source_image();
    if (length == 0U) {
        return;
    }
    if (pattern.empty()) {
        throw PatchError("fill pattern cannot be empty");
    }

    ByteBuffer repeated(length);
    for (std::size_t index = 0; index < length; ++index) {
        repeated[index] = pattern[index % pattern.size()];
    }
    output_image_->write_at(output_cursor_, as_bytes(repeated));
    output_cursor_ += length;
}

void PatchApplier::process_pending_literals() {
    if (trace_) {
        std::cout << "pos=" << output_cursor_
                  << " output_size=" << output_size_ << '\n';
    }
    if (output_cursor_ < output_size_) {
        pending_literal_blocks_.push_back(PendingLiteralBlock{
            .offset = output_cursor_,
            .length = output_size_ - output_cursor_,
            .output_offset = output_cursor_,
        });
    }

    (void) require_source_image();
    for (const auto& block : pending_literal_blocks_) {
        if (trace_) {
            std::cout << "b*" << block.length << '\n';
        }
        const auto literal = reader_.read_bytes(block.length);
        const auto dest_offset = block.output_offset.has_value()
            ? *block.output_offset
            : block.offset;
        output_image_->write_at(dest_offset, as_bytes(literal));
    }
    pending_literal_blocks_.clear();
}

void PatchApplier::apply_uniform_add_queue(std::size_t width) {
    const auto value = read_signed_value(width);
    const auto count = read_nonnegative_varint("queue count");
    delta_cursor_ = 0;
    (void) require_source_image();

    for (std::size_t index = 0; index < count; ++index) {
        delta_cursor_ += read_nonnegative_varint("queue delta");
        output_image_->add_at(delta_cursor_, width, value);
    }
}

void PatchApplier::apply_queue_type_d() {
    const auto count = read_nonnegative_varint("queue count");
    delta_cursor_ = 0;
    (void) require_source_image();

    for (std::size_t index = 0; index < count; ++index) {
        delta_cursor_ += read_nonnegative_varint("queue delta");
        const auto value = read_signed_value(1U);
        output_image_->add_at(delta_cursor_, 1U, value);
    }
}

void PatchApplier::apply_single_byte_delta() {
    delta_cursor_ = read_nonnegative_varint("queue delta");
    const auto value = read_signed_value(1U);
    (void) require_source_image();
    output_image_->add_at(delta_cursor_, 1U, value);
}

}  // namespace readrtp
