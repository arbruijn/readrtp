#include "readrtp/apply.hpp"
#include "readrtp/buffer.hpp"
#include "readrtp/patch_applier.hpp"
#include "readrtp/parse.hpp"
#include "readrtp/types.hpp"

#include <cassert>
#include <chrono>
#include <cctype>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unordered_map>

namespace {

[[nodiscard]] std::filesystem::path make_temp_dir() {
    const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto path = std::filesystem::temp_directory_path()
        / ("readrtp-cpp-e2e-" + std::to_string(stamp));
    std::filesystem::remove_all(path);
    std::filesystem::create_directories(path);
    return path;
}

[[nodiscard]] std::unordered_map<std::string, std::filesystem::path> build_file_index(
    const std::filesystem::path& root
) {
    std::unordered_map<std::string, std::filesystem::path> index;
    if (!std::filesystem::is_directory(root)) {
        return index;
    }

    for (const auto& entry : std::filesystem::recursive_directory_iterator(root)) {
        if (!entry.is_regular_file()) {
            continue;
        }
        const auto relative = std::filesystem::relative(entry.path(), root);
        auto key = readrtp::normalize_rel_path(relative.generic_string());
        std::transform(
            key.begin(),
            key.end(),
            key.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); }
        );
        index.emplace(
            std::move(key),
            entry.path()
        );
    }
    return index;
}

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void assert_tree_matches(
    const std::filesystem::path& reference_dir,
    const std::filesystem::path& target_dir
) {
    const auto reference_files = build_file_index(reference_dir);
    const auto target_files = build_file_index(target_dir);

    require(
        reference_files.size() == target_files.size(),
        "file count mismatch between reference and target trees"
    );

    for (const auto& [rel_path, reference_path] : reference_files) {
        const auto target_it = target_files.find(rel_path);
        require(
            target_it != target_files.end(),
            "missing file in target tree: " + rel_path
        );

        const auto ref_bytes = readrtp::read_file_bytes(reference_path);
        const auto tgt_bytes = readrtp::read_file_bytes(target_it->second);
        require(
            ref_bytes == tgt_bytes,
            "file contents differ for: " + rel_path
        );
    }
}

void run_smoke_tests() {
    const auto normalized = readrtp::normalize_rel_path("foo\\bar");
    assert(normalized == "foo/bar");

    const readrtp::ByteBuffer encoded{0x05};
    const auto [value, next_pos] =
        readrtp::read_varint(readrtp::as_bytes(encoded), 0);
    assert(value == 5);
    assert(next_pos == 1);

    readrtp::Record record;
    assert(!record.is_instruction_stream());
}

void run_end_to_end_test() {
    const auto package_blob = readrtp::load_input_package_bytes("data.bin");
    const auto package = readrtp::parse_package(package_blob);

    const auto source_dir = std::filesystem::path("test/d3old");
    const auto reference_dir = std::filesystem::path("test/d3new");
    const auto target_dir = make_temp_dir() / "patched";
    std::filesystem::create_directories(target_dir);

    readrtp::apply_package(package, package_blob, source_dir, target_dir);
    assert_tree_matches(reference_dir, target_dir);

    std::filesystem::remove_all(target_dir.parent_path());
}

}  // namespace

int main() {
    try {
        run_smoke_tests();
        run_end_to_end_test();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
