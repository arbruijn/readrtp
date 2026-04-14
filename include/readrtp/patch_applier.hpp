#pragma once

#include "readrtp/buffer.hpp"
#include "readrtp/common.hpp"
#include "readrtp/types.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace readrtp {


[[nodiscard]] std::string normalize_rel_path(std::string_view path);

[[nodiscard]] std::filesystem::path resolve_casefold_path(
    const std::filesystem::path& base_dir,
    std::string_view rel_path
);

[[nodiscard]] std::pair<std::int64_t, std::size_t> read_varint(
    ByteView data,
    std::size_t pos
);

[[nodiscard]] std::int64_t read_varint_from_reader(BufferReader& reader);


class PatchApplier {
public:
    PatchApplier(
        ByteBuffer patch_bytes,
        std::filesystem::path target_dir,
        const Record& record,
        std::size_t output_size,
        std::size_t stream_offset = 0,
        std::optional<ChecksumBytes> expected_input_checksum = std::nullopt,
        std::optional<ChecksumBytes> expected_output_checksum = std::nullopt,
        bool trace = false
    );

    [[nodiscard]] std::size_t apply_one_version();
    void apply();

private:
    void reset_version_state();
    [[nodiscard]] std::int64_t read_patch_varint();
    [[nodiscard]] std::size_t read_nonnegative_varint(std::string_view what);
    [[nodiscard]] std::int64_t read_signed_value(std::size_t width);
    void select_source_file(std::int32_t file_id);
    [[nodiscard]] MutableFile& require_source_image();
    void queue_pending_literal(
        std::size_t length,
        std::optional<std::size_t> output_offset = std::nullopt
    );
    void write_output_block(
        const DeferredBlock& block,
        std::size_t literal_prefix = 0
    );
    [[nodiscard]] DeferredBlock read_inline_output_block();
    void fill_output_with_pattern(ByteView pattern, std::size_t length);
    void process_pending_literals();
    void apply_uniform_add_queue(std::size_t width);
    void apply_queue_type_d();
    void apply_single_byte_delta();

    ByteBuffer patch_bytes_;
    BufferReader reader_;
    std::filesystem::path target_dir_;
    Record record_;
    std::string output_rel_path_;
    std::filesystem::path out_path_;
    std::size_t output_size_{0};
    std::optional<ChecksumBytes> expected_input_checksum_;
    std::optional<ChecksumBytes> expected_output_checksum_;
    bool trace_{false};

    std::optional<MutableFile> source_image_;
    std::optional<MutableFile> output_image_;
    std::optional<std::int32_t> selected_file_id_;
    std::size_t output_cursor_{0};
    std::size_t delta_cursor_{0};
    std::vector<DeferredBlock> deferred_output_blocks_;
    std::vector<PendingLiteralBlock> pending_literal_blocks_;
};

}  // namespace readrtp
