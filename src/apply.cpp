#include "readrtp/apply.hpp"

#include "readrtp/buffer.hpp"
#include "readrtp/checksum.hpp"
#include "readrtp/decompression.hpp"
#include "readrtp/error.hpp"
#include "readrtp/parse.hpp"
#include "readrtp/patch_applier.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <ostream>
#include <sstream>
#include <string_view>
#include <system_error>
#include <unordered_map>

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

[[nodiscard]] std::string normalize_lookup_key(std::string_view path) {
    return to_lower_copy(normalize_rel_path(path));
}

[[nodiscard]] std::string format_commas(std::size_t value) {
    auto digits = std::to_string(value);
    std::string formatted;
    formatted.reserve(digits.size() + digits.size() / 3U);

    std::size_t count = 0;
    for (auto it = digits.rbegin(); it != digits.rend(); ++it) {
        if (count == 3U) {
            formatted.push_back(',');
            count = 0;
        }
        formatted.push_back(*it);
        ++count;
    }

    std::reverse(formatted.begin(), formatted.end());
    return formatted;
}

[[nodiscard]] std::string format_size_field(std::optional<std::size_t> size) {
    if (!size.has_value()) {
        return "0";
    }
    return format_commas(*size);
}

[[nodiscard]] std::string format_hex(std::size_t value) {
    std::ostringstream stream;
    stream << "0x" << std::hex << value;
    return stream.str();
}

[[nodiscard]] std::filesystem::path make_temp_work_tree() {
    auto base = std::filesystem::temp_directory_path()
        / ("rtpatch-apply-"
            + std::to_string(
                std::chrono::steady_clock::now().time_since_epoch().count()
            ));
    std::filesystem::create_directories(base);
    return base;
}

struct TempDirGuard {
    std::filesystem::path path;

    ~TempDirGuard() {
        if (path.empty()) {
            return;
        }
        std::error_code error;
        std::filesystem::remove_all(path, error);
    }
};

[[nodiscard]] bool path_matches_filter(
    const std::optional<std::string>& filter,
    const std::string& path
) {
    if (!filter.has_value()) {
        return true;
    }
    return to_lower_copy(*filter) == to_lower_copy(path);
}

}  // namespace

void copy_tree(
    const std::filesystem::path& source,
    const std::filesystem::path& destination
) {
    if (!std::filesystem::is_directory(source)) {
        throw PatchError("source directory does not exist: " + source.string());
    }

    std::filesystem::create_directories(destination);
    for (const auto& entry : std::filesystem::recursive_directory_iterator(source)) {
        const auto relative = std::filesystem::relative(entry.path(), source);
        const auto out = destination / relative;
        if (entry.is_directory()) {
            std::filesystem::create_directories(out);
        } else if (entry.is_regular_file()) {
            std::filesystem::create_directories(out.parent_path());
            std::filesystem::copy_file(
                entry.path(),
                out,
                std::filesystem::copy_options::overwrite_existing
            );
        }
    }
}

void sync_tree(
    const std::filesystem::path& source,
    const std::filesystem::path& target
) {
    if (!std::filesystem::is_directory(source)) {
        throw PatchError("source directory does not exist: " + source.string());
    }

    copy_tree(source, target);

    std::vector<std::filesystem::path> paths_to_remove;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(target)) {
        const auto relative = std::filesystem::relative(entry.path(), target);
        const auto mirrored = source / relative;
        if (!std::filesystem::exists(mirrored)) {
            paths_to_remove.push_back(entry.path());
        }
    }

    std::sort(paths_to_remove.rbegin(), paths_to_remove.rend());
    for (const auto& path : paths_to_remove) {
        std::error_code error;
        std::filesystem::remove(path, error);
    }
}

std::vector<RecordFileVersions> iter_record_payloads(
    const Package& package,
    ByteView data
) {
    std::vector<RecordFileVersions> files;
    files.reserve(package.records.size());
    for (const auto& record : package.records) {
        auto versions = iter_record_version_payloads(record, data);
        if (versions.empty()) {
            continue;
        }
        files.push_back(RecordFileVersions{
            .record = record,
            .versions = std::move(versions),
        });
    }
    return files;
}

std::vector<RecordVersion> iter_record_version_payloads(
    const Record& record,
    ByteView data
) {
    const auto bounds = record_stream_bounds(record);
    if (!bounds.has_value()) {
        return {};
    }

    const auto [base_stream_offset, base_stream_end] = *bounds;
    std::vector<RecordVersion> versions;
    versions.push_back(RecordVersion{
        .record = record,
        .version_index = 0,
        .stream_offset = base_stream_offset,
        .stream_end = base_stream_end,
    });

    if (!record.type_5000.has_value() || record.history_version_count <= 1U) {
        return versions;
    }

    std::size_t expanded_count = 1;
    auto next_offset = base_stream_end;
    while (next_offset < record.next_record_offset) {
        auto [chunk_record, chunk_next_offset] = parse_type_5000_history_chunk(
            data,
            next_offset,
            record.path
        );
        const auto chunk_bounds = record_stream_bounds(chunk_record);
        if (!chunk_bounds.has_value()) {
            throw PatchError(
                "type-0x5000 history chunk at " + std::to_string(chunk_record.offset)
                + " has no payload stream"
            );
        }
        versions.push_back(RecordVersion{
            .record = std::move(chunk_record),
            .version_index = expanded_count,
            .stream_offset = chunk_bounds->first,
            .stream_end = chunk_bounds->second,
        });
        ++expanded_count;
        next_offset = chunk_next_offset;
    }

    if (expanded_count != record.history_version_count) {
        throw PatchError(
            "record at " + std::to_string(record.offset) + " expanded to "
            + std::to_string(expanded_count) + " version payload(s), expected "
            + std::to_string(record.history_version_count)
        );
    }

    return versions;
}

void apply_package(
    const Package& package,
    ByteView package_bytes,
    const std::optional<std::filesystem::path>& source_dir,
    const std::filesystem::path& target_dir,
    const std::optional<std::string>& file,
    bool trace,
    const std::optional<std::filesystem::path>& reference_dir
) {
    const auto result = apply_patches(
        package,
        package_bytes,
        source_dir,
        target_dir,
        file,
        trace
    );

    auto match = true;
    if (reference_dir.has_value() && !file.has_value()) {
        match = trees_match(*reference_dir, target_dir);
    }

    if (result.success && match) {
        return;
    }

    std::cerr << "failed to apply patch\n";
}

std::string calculate_status(
    const RecordFileVersions& file_versions,
    const std::filesystem::path& target_dir,
    const std::unordered_map<std::string, std::filesystem::path>& target_files
) {
    (void) target_dir;
    const auto key = normalize_lookup_key(file_versions.record.path);
    const auto file_it = target_files.find(key);
    const std::optional<std::filesystem::path> file_path = file_it == target_files.end()
        ? std::nullopt
        : std::optional<std::filesystem::path>(file_it->second);
    return detect_file_version_state(file_versions, file_path).first;
}

std::unordered_map<std::string, int> check_package(
    const Package& package,
    ByteView data,
    const std::filesystem::path& target_dir,
    bool verbose
) {
    std::unordered_map<std::string, int> statuses{
        {"missing", 0},
        {"already_updated", 0},
        {"ok", 0},
        {"unknown", 0},
    };

    const auto target_files = build_target_file_lookup(target_dir);
    for (const auto& file_versions : iter_record_payloads(package, data)) {
        auto status = calculate_status(file_versions, target_dir, target_files);
        if (verbose) {
            std::replace(status.begin(), status.end(), '_', ' ');
            std::cout << file_versions.record.path << ": " << status << '\n';
        }
        ++statuses[status];
    }

    return statuses;
}

std::vector<std::string> list_package(
    const Package& package,
    ByteView data,
    bool verbose
) {
    const auto files = iter_record_payloads(package, data);

    std::size_t max_size = 0;
    for (const auto& file_versions : files) {
        const auto size = record_version_output_size(file_versions.versions[0]);
        if (size.has_value() && *size > max_size) {
            max_size = *size;
        }
        if (!verbose) {
            continue;
        }
        for (const auto& version : file_versions.versions) {
            const auto vsize = record_version_output_size(version);
            if (vsize.has_value() && *vsize > max_size) {
                max_size = *vsize;
            }
        }
    }

    const auto size_width = max_size > 0U ? format_commas(max_size).size() : 1U;
    std::vector<std::string> lines;
    lines.reserve(verbose ? files.size() * 2U : files.size());

    for (const auto& file_versions : files) {
        const auto& path = file_versions.record.path;
        const auto size = format_size_field(record_version_output_size(
            file_versions.versions[0]
        ));
        lines.push_back(
            std::string(size_width > size.size()
                ? size_width - size.size()
                : 0U,
                ' ')
            + size + " " + path
        );

        if (!verbose) {
            continue;
        }
        for (const auto& version : file_versions.versions) {
            const auto vsize = format_size_field(record_version_output_size(version));
            lines.push_back(
                std::string(size_width > vsize.size()
                    ? size_width - vsize.size()
                    : 0U,
                    ' ')
                + vsize + " " + path + "@" + std::to_string(version.version_index)
            );
        }
    }

    return lines;
}

int run_apply(
    const ApplyOptions& options,
    std::ostream& out,
    std::ostream& err
) {
    try {
        if (options.input_path.empty()) {
            err << "apply: --input is required\n";
            return 1;
        }

        const auto data = load_input_package_bytes(options.input_path);
        const auto package = parse_package(data);

        if (options.list_only) {
            for (const auto& line : list_package(package, data, options.verbose)) {
                out << line << '\n';
            }
            return 0;
        }

        if (options.check_only) {
            if (!options.target_dir.has_value()) {
                err << "apply: --target-dir is required when using --check\n";
                return 1;
            }

            std::unordered_map<std::string, int> statuses{
                {"missing", 0},
                {"already_updated", 0},
                {"ok", 0},
                {"unknown", 0},
            };
            const auto target_files = build_target_file_lookup(*options.target_dir);
            for (const auto& file_versions : iter_record_payloads(package, data)) {
                auto status = calculate_status(file_versions, *options.target_dir, target_files);
                if (options.verbose) {
                    std::string pretty = status;
                    std::replace(pretty.begin(), pretty.end(), '_', ' ');
                    out << file_versions.record.path << ": " << pretty << '\n';
                }
                ++statuses[status];
            }

            out << "\nSummary:\n";
            out << "  missing: " << statuses["missing"] << '\n';
            out << "  already updated: " << statuses["already_updated"] << '\n';
            out << "  ok: " << statuses["ok"] << '\n';
            out << "  unknown: " << statuses["unknown"] << '\n';
            return 0;
        }

        if (!options.target_dir.has_value()) {
            err << "apply: --target-dir is required unless using --list or --check\n";
            return 1;
        }

        const auto result = apply_patches(
            package,
            data,
            options.source_dir,
            *options.target_dir,
            options.file,
            options.trace
        );

        auto match = true;
        if (options.reference_dir.has_value() && !options.file.has_value()) {
            match = trees_match(*options.reference_dir, *options.target_dir);
        }
        if (!result.success || !match) {
            err << "failed to apply patch\n";
        }
        if (!options.quiet) {
            std::unordered_map<std::string, int> statuses{
                {"missing", 0},
                {"already_updated", 0},
                {"ok", 0},
                {"unknown", 0},
            };
            for (const auto& file_status : result.file_statuses) {
                auto status = file_status.second;
                if (options.verbose) {
                    std::string pretty = status;
                    std::replace(pretty.begin(), pretty.end(), '_', ' ');
                    out << file_status.first << ": " << pretty << '\n';
                }
                ++statuses[status];
            }

            out << "\nSummary:\n";
            out << "  missing: " << statuses["missing"] << '\n';
            out << "  already updated: " << statuses["already_updated"] << '\n';
            out << "  updated: " << statuses["ok"] << '\n';
            out << "  unknown: " << statuses["unknown"] << '\n';
        }
        return 0;
    } catch (const PatchError& error) {
        err << "apply: " << error.what() << '\n';
        return 1;
    }
}

void print_help(std::ostream& out) {
    out << "Standalone -style patch applier\n";
    out << "\n";
    out << "Options:\n";
    out << "  --input <file>         Patch/package file, e.g. D3_US_1.4_Patch.exe\n";
    out << "  --source-dir <dir>     Optional tree to copy into the output directory before patching\n";
    out << "  --target-dir <dir>     Directory to write patched files into\n";
    out << "  --file <file>          Optional file selection\n";
    out << "  -v, --verbose          Enable logging\n";
    out << "  -t, --trace            Enable tracing\n";
    out << "  -l, --list             List all recordfile entries\n";
    out << "  -c, --check            Check if files in target directory match package versions\n";
    out << "  --reference-dir <dir>  Directory containing the expected sample output tree\n";
    out << "  -q, --quiet            Suppress status output\n";
    out << "  -h, --help, -?         Show this help message and exit\n";
}

int apply_main(int argc, char** argv) {
    ApplyOptions options;
    bool parse_error = false;
    for (int index = 1; index < argc; ++index) {
        std::string_view arg(argv[index]);

        if (arg == "-h" || arg == "--help" || arg == "-?") {
            print_help(std::cout);
            return 0;
        }

        const auto next_value = [&](std::string_view name) -> std::optional<std::string_view> {
            if (arg == name) {
                if (index + 1 >= argc) {
                    std::cerr << "apply: missing value for " << name << '\n';
                    parse_error = true;
                    return std::nullopt;
                }
                return std::string_view(argv[++index]);
            }
            const auto prefix = std::string(name) + "=";
            if (arg.rfind(prefix, 0) == 0U) {
                return arg.substr(prefix.size());
            }
            return std::nullopt;
        };

        if (arg == "-v" || arg == "--verbose") {
            options.verbose = true;
            continue;
        }
        if (arg == "-t" || arg == "--trace") {
            options.trace = true;
            continue;
        }
        if (arg == "-l" || arg == "--list") {
            options.list_only = true;
            continue;
        }
        if (arg == "-c" || arg == "--check") {
            options.check_only = true;
            continue;
        }
        if (arg == "-q" || arg == "--quiet") {
            options.quiet = true;
            continue;
        }
        if (const auto value = next_value("--input")) {
            options.input_path = std::filesystem::path(std::string(*value));
            continue;
        }
        if (const auto value = next_value("--source-dir")) {
            options.source_dir = std::filesystem::path(std::string(*value));
            continue;
        }
        if (const auto value = next_value("--target-dir")) {
            options.target_dir = std::filesystem::path(std::string(*value));
            continue;
        }
        if (const auto value = next_value("--file")) {
            options.file = std::string(*value);
            continue;
        }
        if (const auto value = next_value("--reference-dir")) {
            options.reference_dir = std::filesystem::path(std::string(*value));
            continue;
        }

        std::cerr << "apply: unknown argument: " << arg << '\n';
        return 1;
    }

    if (parse_error) {
        return 1;
    }

    return run_apply(options, std::cout, std::cerr);
}


std::optional<std::pair<std::size_t, std::size_t>>
record_stream_bounds(const Record& record) {
    std::optional<std::size_t> stream_offset = record.compressed_offset;
    if (!stream_offset.has_value()) {
        stream_offset = record.stream_offset;
    }
    if (!stream_offset.has_value()) {
        return std::nullopt;
    }

    auto stream_end = record.next_record_offset;
    if (record.compressed_size.has_value()) {
        stream_end = *stream_offset + *record.compressed_size;
        if (stream_end < *stream_offset || stream_end > record.next_record_offset) {
            throw PatchError(
                "record at " + std::to_string(record.offset)
                + " declares compressed payload ending at " + std::to_string(stream_end)
                + " outside record boundary "
                + std::to_string(record.next_record_offset)
            );
        }
    }

    return std::pair{*stream_offset, stream_end};
}

std::optional<std::size_t> record_version_output_size(
    const RecordVersion& version
) {
    if (version.record.type_2000.has_value()) {
        return version.record.decompressed_size;
    }

    if (!version.record.type_5000.has_value()) {
        return version.record.decompressed_size;
    }

    const auto& metadata = *version.record.type_5000;
    if (version.version_index == 0 && metadata.secondary_entry.has_value()) {
        return metadata.secondary_entry->size_hint;
    }
    return metadata.primary_entry.size_hint;
}

ByteBuffer load_input_package_bytes(const std::filesystem::path& input_path) {
    auto raw = read_file_bytes(input_path);
    if (raw.size() < kInputTrailerSize) {
        throw PatchError("input file is too small to contain the expected trailer");
    }

    const auto trailer_offset = raw.size() - kInputTrailerSize;
    const auto signature_begin = raw.begin()
        + static_cast<std::ptrdiff_t>(trailer_offset + kInputTrailerOffsetSize);
    if (!std::equal(
            signature_begin,
            signature_begin + static_cast<std::ptrdiff_t>(kInputTrailerSignature.size()),
            kInputTrailerSignature.begin()
        )) {
        return raw;
    }

    const auto start_offset =
        static_cast<std::size_t>(raw[trailer_offset])
        | (static_cast<std::size_t>(raw[trailer_offset + 1U]) << 8U)
        | (static_cast<std::size_t>(raw[trailer_offset + 2U]) << 16U)
        | (static_cast<std::size_t>(raw[trailer_offset + 3U]) << 24U);
    if (start_offset >= raw.size() - kInputTrailerSize) {
        throw PatchError("input package trailer offset does not point to package data");
    }

    ByteBuffer data(
        raw.begin() + static_cast<std::ptrdiff_t>(start_offset),
        raw.end()
    );
    for (std::size_t index = 0; index < kInputTrailerOffsetSize; ++index) {
        data[data.size() - kInputTrailerSize + index] = 0;
    }
    return data;
}

bool trees_match(
    const std::filesystem::path& reference_dir,
    const std::filesystem::path& target_dir
) {
    if (!std::filesystem::is_directory(reference_dir)
        || !std::filesystem::is_directory(target_dir)) {
        return false;
    }

    const auto build_index = [](const std::filesystem::path& root) {
        std::unordered_map<std::string, std::filesystem::path> index;
        for (const auto& entry : std::filesystem::recursive_directory_iterator(root)) {
            if (!entry.is_regular_file()) {
                continue;
            }
            const auto relative = std::filesystem::relative(entry.path(), root);
            index.emplace(
                normalize_lookup_key(relative.generic_string()),
                entry.path()
            );
        }
        return index;
    };

    const auto reference_files = build_index(reference_dir);
    const auto target_files = build_index(target_dir);
    if (reference_files.size() != target_files.size()) {
        return false;
    }

    for (const auto& [relative, reference_path] : reference_files) {
        const auto target_it = target_files.find(relative);
        if (target_it == target_files.end()) {
            return false;
        }
        if (read_file_bytes(reference_path) != read_file_bytes(target_it->second)) {
            return false;
        }
    }

    return true;
}

CompressedStream decompress_record_stream(
    ByteView data,
    std::size_t stream_offset,
    std::size_t stream_end_offset,
    std::optional<std::size_t> expected_compressed_size
) {
    if (stream_offset > stream_end_offset || stream_end_offset > data.size()) {
        throw PatchError("compressed stream bounds are outside the package");
    }

    const auto slice = data.subspan(stream_offset, stream_end_offset - stream_offset);
    auto [payload, bytes_consumed] = decompress_stream(slice);
    if (expected_compressed_size.has_value()
        && bytes_consumed != *expected_compressed_size) {
        throw PatchError(
            "compressed payload at " + format_hex(stream_offset)
            + " consumed " + format_hex(bytes_consumed)
            + ", expected " + format_hex(*expected_compressed_size)
        );
    }
    if (stream_offset + bytes_consumed > stream_end_offset) {
        throw PatchError(
            "compressed payload at " + format_hex(stream_offset)
            + " overruns bounded stream ending at "
            + format_hex(stream_end_offset)
        );
    }

    return CompressedStream{
        .offset = stream_offset,
        .bytes_consumed = bytes_consumed,
        .payload = std::move(payload),
    };
}

std::pair<Record, std::size_t> parse_type_5000_history_chunk(
    ByteView data,
    std::size_t start_offset,
    const std::string& path
) {
    BufferReader reader(ByteBuffer(data.begin(), data.end()), start_offset);
    const auto header_kind = reader.read_u16le();
    const auto variant_flags = reader.read_u16le();
    const auto inline_kind = reader.read_u8();
    const auto output_size = reader.read_u32le();
    const auto compressed_size = reader.read_u32le();
    const auto checksum_raw = reader.read_bytes(10);
    ChecksumBytes checksum{};
    std::copy(checksum_raw.begin(), checksum_raw.end(), checksum.begin());

    const auto expected_name = expected_record_name(path);
    auto primary_entry = read_type_5000_entry_metadata(
        reader,
        start_offset,
        expected_name,
        1
    );
    const auto stream_offset = reader.tell();
    const auto next_offset = stream_offset + static_cast<std::size_t>(compressed_size);
    if (next_offset < stream_offset || next_offset > data.size()) {
        throw PatchError(
            "type-0x5000 history chunk at " + format_hex(start_offset)
            + " overruns package payload"
        );
    }

    Record record;
    record.offset = start_offset;
    record.flags = 0x5000U;
    record.subflags = std::nullopt;
    record.path = path;
    record.next_record_offset = next_offset;
    record.history_version_count = 1U;
    record.body_offset = start_offset;
    record.stream_offset = stream_offset;
    record.compressed_size = compressed_size;
    record.checksum = checksum;
    record.decompressed_size = output_size;

    Type5000RecordMetadata metadata;
    metadata.header_kind = header_kind;
    metadata.inline_kind = inline_kind;
    metadata.is_instruction_stream = header_kind == kType5000PatchHeaderKind;
    metadata.variant_flags = variant_flags;
    metadata.primary_entry = std::move(primary_entry);
    metadata.secondary_entry = std::nullopt;
    metadata.entries = {metadata.primary_entry};
    record.type_5000 = std::move(metadata);

    return {std::move(record), next_offset};
}

void seed_work_tree(
    const std::optional<std::filesystem::path>& source_dir,
    const std::filesystem::path& target_dir,
    const std::filesystem::path& work_tree
) {
    if (source_dir.has_value()) {
        copy_tree(*source_dir, work_tree);
        return;
    }
    if (std::filesystem::is_directory(target_dir)) {
        copy_tree(target_dir, work_tree);
        return;
    }
    if (!work_tree.empty()) {
        std::filesystem::create_directories(work_tree);
    }
}

void write_record_payload(
    const std::filesystem::path& target_dir,
    const std::string& record_path,
    ByteView payload
) {
    const auto out_path = resolve_casefold_path(target_dir, record_path);
    if (!out_path.parent_path().empty()) {
        std::filesystem::create_directories(out_path.parent_path());
    }
    std::ofstream output(out_path, std::ios::binary);
    if (!output) {
        throw PatchError("unable to open output file: " + out_path.string());
    }
    output.write(
        reinterpret_cast<const char*>(payload.data()),
        static_cast<std::streamsize>(payload.size())
    );
}

std::optional<ChecksumBytes> expected_input_checksum(const RecordVersion& version) {
    const auto& metadata = version.record.type_5000;
    if (!metadata.has_value()
        || !metadata->secondary_entry.has_value()
        || version.version_index != 0U) {
        return std::nullopt;
    }
    return metadata->primary_entry.checksum;
}

std::optional<ChecksumBytes> expected_output_checksum(const RecordVersion& version) {
    if (version.record.type_2000.has_value()) {
        return version.record.type_2000->checksum;
    }

    const auto& metadata = version.record.type_5000;
    if (!metadata.has_value()) {
        return std::nullopt;
    }
    if (version.version_index == 0U && metadata->secondary_entry.has_value()) {
        return metadata->secondary_entry->checksum;
    }
    return metadata->primary_entry.checksum;
}

std::pair<std::string, std::optional<std::size_t>>
detect_file_version_state(
    const RecordFileVersions& file_versions,
    const std::optional<std::filesystem::path>& file_path
) {
    const auto& versions = file_versions.versions;
    if (file_path.has_value() && std::filesystem::exists(*file_path)) {
        const auto file_checksums = compute_file_checksums(*file_path);

        const auto final_checksum = expected_output_checksum(versions.back());
        if (final_checksum.has_value()
            && (file_checksums.first == *final_checksum
                || file_checksums.second == *final_checksum)) {
            return {"already_updated", versions.size()};
        }

        const auto initial_checksum = expected_input_checksum(versions.front());
        if (initial_checksum.has_value()
            && (file_checksums.first == *initial_checksum
                || file_checksums.second == *initial_checksum)) {
            return {"ok", 0};
        }

        for (std::size_t version_index = versions.size(); version_index-- > 1U;) {
            const auto checksum = expected_output_checksum(versions[version_index - 1U]);
            if (checksum.has_value()
                && (file_checksums.first == *checksum
                    || file_checksums.second == *checksum)) {
                return {"ok", version_index};
            }
        }

        if (versions.front().record.is_instruction_stream()) {
            return {"unknown", 0};
        }
        return {"ok", 0};
    }

    if (versions.front().record.is_instruction_stream()) {
        return {"missing", 0};
    }
    return {"ok", 0};
}

ApplyResult apply_patches(
    const Package& package,
    ByteView data,
    const std::optional<std::filesystem::path>& source_dir,
    const std::filesystem::path& target_dir,
    const std::optional<std::string>& file,
    bool trace
) {
    const auto files = iter_record_payloads(package, data);
    const auto work_tree = make_temp_work_tree();
    TempDirGuard guard{work_tree};
    seed_work_tree(source_dir, target_dir, work_tree);

    ApplyResult result;
    std::vector<std::string> failed_patch_records;
    for (const auto& file_versions : files) {
        const auto& path = file_versions.record.path;
        if (!path_matches_filter(file, path)) {
            continue;
        }

        bool file_patched = false;
        const auto [status, start_index_opt] = detect_file_version_state(
            file_versions,
            resolve_casefold_path(work_tree, path)
        );
        result.file_statuses.push_back({path, status});
        const auto start_index = start_index_opt.value_or(0U);
        for (const auto& version : file_versions.versions) {
            if (version.version_index < start_index) {
                continue;
            }

            const auto stream = decompress_record_stream(
                data,
                version.stream_offset,
                version.stream_end,
                version.record.compressed_size
            );
            if (!version.record.is_instruction_stream()) {
                write_record_payload(work_tree, version.record.path, as_bytes(stream.payload));
                const auto checksum = expected_output_checksum(version);
                if (checksum.has_value()) {
                    const auto verification_kind = verify_checksum(
                        as_bytes(stream.payload),
                        *checksum,
                        "output file for '" + version.record.path + "'"
                    );
                    (void) verification_kind;
                }
                file_patched = true;
                continue;
            }

            const auto& metadata = *version.record.type_5000;
            const auto& entry = version.version_index == 0U && metadata.secondary_entry.has_value()
                ? metadata.secondary_entry.value()
                : metadata.primary_entry;
            try {
                PatchApplier(
                    std::move(stream.payload),
                    work_tree,
                    version.record,
                    entry.size_hint,
                    0U,
                    expected_input_checksum(version),
                    expected_output_checksum(version),
                    trace
                ).apply();
                file_patched = true;
            } catch (const std::exception&) {
                failed_patch_records.push_back(version.record.path);
                break;
            }
        }
        if (file_patched && std::find(failed_patch_records.begin(), failed_patch_records.end(), path) == failed_patch_records.end()) {
            ++result.files_patched;
        }
    }

    sync_tree(work_tree, target_dir);
    result.success = failed_patch_records.empty();
    return result;
}

std::unordered_map<std::string, std::filesystem::path>
build_target_file_lookup(const std::filesystem::path& target_dir) {
    std::unordered_map<std::string, std::filesystem::path> lookup;
    if (!std::filesystem::is_directory(target_dir)) {
        return lookup;
    }

    for (const auto& entry : std::filesystem::recursive_directory_iterator(target_dir)) {
        if (!entry.is_regular_file()) {
            continue;
        }
        const auto relative = std::filesystem::relative(entry.path(), target_dir);
        lookup.emplace(
            normalize_lookup_key(relative.generic_string()),
            entry.path()
        );
    }
    return lookup;
}

std::pair<ChecksumBytes, ChecksumBytes> compute_file_checksums(
    const std::filesystem::path& file_path
) {
    const auto data = read_file_bytes(file_path);
    return {
        update_checksum_state_bytes(as_bytes(data)),
        update_cyclic_checksum_state_bytes(as_bytes(data)),
    };
}


}  // namespace readrtp
