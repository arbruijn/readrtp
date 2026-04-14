#pragma once

#include "readrtp/common.hpp"
#include "readrtp/types.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iosfwd>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace readrtp {

inline constexpr std::size_t kInputTrailerSize = 8;
inline constexpr std::size_t kInputTrailerOffsetSize = 4;
inline constexpr std::array<std::uint8_t, 4> kInputTrailerSignature = {
    'D',
    'K',
    'N',
    'J',
};

struct ApplyOptions {
    std::filesystem::path input_path;
    std::optional<std::filesystem::path> source_dir;
    std::optional<std::filesystem::path> target_dir;
    std::optional<std::string> file;
    bool verbose{false};
    bool trace{false};
    bool list_only{false};
    bool check_only{false};
    bool quiet{false};
    std::optional<std::filesystem::path> reference_dir;
};


[[nodiscard]] std::optional<std::pair<std::size_t, std::size_t>>
record_stream_bounds(const Record& record);

[[nodiscard]] std::optional<std::size_t> record_version_output_size(
    const RecordVersion& version
);

[[nodiscard]] ByteBuffer load_input_package_bytes(
    const std::filesystem::path& input_path
);

[[nodiscard]] bool trees_match(
    const std::filesystem::path& reference_dir,
    const std::filesystem::path& target_dir
);

[[nodiscard]] CompressedStream decompress_record_stream(
    ByteView data,
    std::size_t stream_offset,
    std::size_t stream_end_offset,
    std::optional<std::size_t> expected_compressed_size = std::nullopt
);

[[nodiscard]] std::pair<Record, std::size_t> parse_type_5000_history_chunk(
    ByteView data,
    std::size_t start_offset,
    const std::string& path
);

void seed_work_tree(
    const std::optional<std::filesystem::path>& source_dir,
    const std::filesystem::path& target_dir,
    const std::filesystem::path& work_tree
);

void write_record_payload(
    const std::filesystem::path& target_dir,
    const std::string& record_path,
    ByteView payload
);

[[nodiscard]] std::optional<ChecksumBytes> expected_input_checksum(
    const RecordVersion& version
);

[[nodiscard]] std::optional<ChecksumBytes> expected_output_checksum(
    const RecordVersion& version
);

[[nodiscard]] std::pair<std::string, std::optional<std::size_t>>
detect_file_version_state(
    const RecordFileVersions& file_versions,
    const std::optional<std::filesystem::path>& file_path
);

struct ApplyResult {
    bool success{false};
    std::size_t files_patched{0};
    std::vector<std::pair<std::string, std::string>> file_statuses;
};

[[nodiscard]] ApplyResult apply_patches(
    const Package& package,
    ByteView data,
    const std::optional<std::filesystem::path>& source_dir,
    const std::filesystem::path& target_dir,
    const std::optional<std::string>& file,
    bool trace
);

[[nodiscard]] std::unordered_map<std::string, std::filesystem::path>
build_target_file_lookup(const std::filesystem::path& target_dir);

[[nodiscard]] std::pair<ChecksumBytes, ChecksumBytes> compute_file_checksums(
    const std::filesystem::path& file_path
);


void copy_tree(
    const std::filesystem::path& source,
    const std::filesystem::path& destination
);

void sync_tree(
    const std::filesystem::path& source,
    const std::filesystem::path& target
);

[[nodiscard]] std::vector<RecordFileVersions> iter_record_payloads(
    const Package& package,
    ByteView data
);

[[nodiscard]] std::vector<RecordVersion> iter_record_version_payloads(
    const Record& record,
    ByteView data
);

void apply_package(
    const Package& package,
    ByteView package_bytes,
    const std::optional<std::filesystem::path>& source_dir,
    const std::filesystem::path& target_dir,
    const std::optional<std::string>& file = std::nullopt,
    bool trace = false,
    const std::optional<std::filesystem::path>& reference_dir = std::nullopt
);

[[nodiscard]] std::string calculate_status(
    const RecordFileVersions& file_versions,
    const std::filesystem::path& target_dir,
    const std::unordered_map<std::string, std::filesystem::path>& target_files
);

[[nodiscard]] std::unordered_map<std::string, int> check_package(
    const Package& package,
    ByteView data,
    const std::filesystem::path& target_dir,
    bool verbose = false
);

[[nodiscard]] std::vector<std::string> list_package(
    const Package& package,
    ByteView data,
    bool verbose = false
);

[[nodiscard]] int run_apply(
    const ApplyOptions& options,
    std::ostream& out,
    std::ostream& err
);

[[nodiscard]] int apply_main(int argc, char** argv);

}  // namespace readrtp
