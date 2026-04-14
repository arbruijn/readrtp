#pragma once

#include "readrtp/common.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace readrtp {

inline constexpr std::uint16_t kCompressionMagic = 0xB59C;
inline constexpr std::size_t kTokenBlockSize = 0x200;
inline constexpr std::size_t kRangeTableSlots = 24;

class CompressionError : public std::runtime_error {
public:
    explicit CompressionError(const std::string& message);
};


struct HuffmanTable {
    std::uint32_t raw_bits{0};
    std::uint32_t max_code_len{0};
    std::uint32_t counter_reset{0};
    std::uint32_t cooldown_reset{0};
    std::uint32_t active_symbols{1};
    std::uint32_t active_levels{1};
    std::uint32_t counter{0};
    std::uint32_t cooldown{0};
    std::uint32_t cooldown_base{0};
    std::uint32_t cooldown_orig{0};
    std::uint32_t counter_orig{0};
    std::uint32_t escape_symbol{0};
    std::uint32_t dummy_symbol{0};
    std::vector<std::uint32_t> symbol_order;
    std::vector<std::uint32_t> freqs;
    std::vector<std::uint32_t> level_counts;
    std::vector<std::uint32_t> row_ptrs;
    std::vector<std::array<std::uint32_t, 4>> range_table;

    HuffmanTable(
        std::uint32_t raw_bits,
        std::uint32_t max_code_len,
        std::uint32_t counter_reset,
        std::uint32_t cooldown_reset
    );

    void rebuild_row_ptrs();
    [[nodiscard]] bool decrement_counter_and_update_array(std::uint32_t symbol);
    void update_huffman_table_offsets(std::uint32_t start_level);
    [[nodiscard]] std::uint32_t update_huffman_tree_structure(std::uint32_t symbol);
    void optimize_huffman_table();
};

struct Token {
    bool is_copy{false};
    std::uint32_t value{0};
    std::uint32_t length{0};
};


class Decompressor {
public:
    explicit Decompressor(ByteBuffer data);

    [[nodiscard]] std::uint8_t require_byte(std::size_t pos) const;
    [[nodiscard]] std::uint32_t current_unread_bits() const;
    [[nodiscard]] std::uint32_t read_bitstream_variable_length_uint(
        std::uint32_t width
    );
    [[nodiscard]] std::uint32_t get_next_bit_from_compressed_stream();
    void initialize_compression_context();
    [[nodiscard]] std::uint32_t decode_huffman_symbol_with_length(
        HuffmanTable& table
    );
    [[nodiscard]] std::optional<Token> decode_next_token();
    [[nodiscard]] std::vector<Token> decode_compressed_integer_stream();
    [[nodiscard]] std::vector<Token> decode_tokens(std::size_t count);
    [[nodiscard]] ByteBuffer inflate_compressed_stream_with_dictionary(
        const std::vector<Token>& tokens
    );
    [[nodiscard]] ByteBuffer decompress();
    [[nodiscard]] std::size_t bytes_consumed() const;

private:
    void ensure_initialized();
    [[nodiscard]] std::uint32_t read_bitstream_variable_length_uint_impl(
        std::uint32_t width
    );

    ByteBuffer data_;
    std::size_t byte_pos_{0};
    std::uint32_t bits_left_{8};
    std::optional<std::uint32_t> literal_mode_;
    std::optional<std::uint32_t> window_selector_;
    std::size_t window_size_{0};
    std::size_t window_mask_{0};
    std::size_t window_low_bits_{0};
    bool end_seen_{false};
    std::optional<HuffmanTable> literal_table_;
    std::optional<HuffmanTable> length_table_;
    std::optional<HuffmanTable> distance_table_;
    ByteBuffer dictionary_;
    std::size_t dict_pos_{0};
    bool context_initialized_{false};
};

[[nodiscard]] std::pair<ByteBuffer, std::size_t> decompress_stream(ByteView blob);

}  // namespace readrtp
