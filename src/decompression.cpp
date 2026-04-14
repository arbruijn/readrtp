#include "readrtp/decompression.hpp"

#include "readrtp/error.hpp"

namespace readrtp {

CompressionError::CompressionError(const std::string& message)
    : std::runtime_error(message) {}


HuffmanTable::HuffmanTable(
    std::uint32_t raw_bits_value,
    std::uint32_t max_code_len_value,
    std::uint32_t counter_reset_value,
    std::uint32_t cooldown_reset_value
) : raw_bits(raw_bits_value),
    max_code_len(max_code_len_value),
    counter_reset(counter_reset_value),
    cooldown_reset(cooldown_reset_value),
    counter(counter_reset_value),
    cooldown(cooldown_reset_value),
    cooldown_base(cooldown_reset_value),
    cooldown_orig(cooldown_reset_value),
    counter_orig(counter_reset_value) {
    const auto raw_symbol_count = static_cast<std::uint32_t>(1U << raw_bits);
    escape_symbol = raw_symbol_count;
    dummy_symbol = raw_symbol_count + 1U;

    symbol_order.assign(raw_symbol_count + 2U, dummy_symbol);
    if (!symbol_order.empty()) {
        symbol_order[0] = escape_symbol;
    }

    freqs.assign(raw_symbol_count + 2U, 0x8000U);
    if (freqs.size() >= 2U) {
        freqs[raw_symbol_count] = 0;
        freqs[raw_symbol_count + 1U] = 0;
    }

    level_counts.assign(max_code_len, 0);
    if (!level_counts.empty()) {
        level_counts[0] = 2;
    }

    row_ptrs.assign(max_code_len + 1U, 2U);
    if (!row_ptrs.empty()) {
        row_ptrs[0] = 0;
    }

    range_table.assign(kRangeTableSlots, {0, 0, 0, 0});
}

void HuffmanTable::rebuild_row_ptrs() {
    std::uint32_t total = 0;
    if (row_ptrs.empty()) {
        return;
    }

    row_ptrs[0] = 0;
    for (std::size_t index = 0; index < level_counts.size(); ++index) {
        total += level_counts[index];
        row_ptrs[index + 1U] = total;
    }
}

bool HuffmanTable::decrement_counter_and_update_array(std::uint32_t symbol) {
    if (symbol >= freqs.size()) {
        throw PatchError("invalid Huffman symbol index");
    }
    ++freqs[symbol];
    --counter;
    return counter == 0;
}

void HuffmanTable::update_huffman_table_offsets(std::uint32_t start_level) {
    std::uint32_t base = start_level == 0
        ? 2U
        : range_table[start_level - 1U][0] * 2U;
    for (std::uint32_t level = start_level; level < max_code_len; ++level) {
        const auto start = base - level_counts[level];
        range_table[level][0] = start;
        base = start * 2U;
        range_table[level][1] = base;
        range_table[level][2] = start * 4U;
        range_table[level][3] = start * 16U;
    }
}

std::uint32_t HuffmanTable::update_huffman_tree_structure(std::uint32_t symbol) {
    if (symbol >= freqs.size()) {
        throw CompressionError("invalid Huffman symbol index");
    }

    freqs[symbol] = 1;
    symbol_order[active_symbols] = symbol;
    active_symbols += 1;

    if (active_symbols == 2U) {
        return 0;
    }

    int level;
    if (active_levels < max_code_len) {
        level = static_cast<int>(active_levels) - 1;
        active_levels += 1;
    } else {
        level = static_cast<int>(active_levels) - 2;
        while (level >= 0
            && level_counts[static_cast<std::size_t>(level)] == 0U) {
            level -= 1;
        }
        if (level < 0) {
            throw CompressionError("invalid Huffman tree state");
        }
    }

    level_counts[static_cast<std::size_t>(level)] -= 1U;
    level_counts[static_cast<std::size_t>(level) + 1U] += 2U;
    rebuild_row_ptrs();
    return static_cast<std::uint32_t>(level);
}

void HuffmanTable::optimize_huffman_table() {
    --cooldown;

    std::uint32_t max_freq = 0;
    for (std::uint32_t index = 0; index < active_symbols; ++index) {
        const auto symbol = symbol_order[index];
        if (symbol >= freqs.size()) {
            throw CompressionError("invalid Huffman symbol index");
        }

        std::uint32_t freq = freqs[symbol];
        if (cooldown == 0U) {
            freq >>= 1U;
            freqs[symbol] = freq;
        }
        if (max_freq < freq) {
            max_freq = freq;
        }
    }

    if (max_freq != 0U) {
        std::uint32_t mask = 0x8000U;
        while ((max_freq & mask) == 0U) {
            mask = ((mask >> 1U) | 0x8000U) & 0xFFFFU;
        }

        std::uint32_t index = 0;
        while (index < active_symbols) {
            auto symbol = symbol_order[index];
            if ((freqs[symbol] & mask) != 0U) {
                index += 1U;
                continue;
            }

            std::uint32_t scan = index + 1U;
            std::uint32_t last = index;
            if (active_symbols <= scan) {
                break;
            }

            while (scan < active_symbols) {
                const auto scan_symbol = symbol_order[scan];
                if ((freqs[scan_symbol] & mask) != 0U) {
                    last += 1U;
                    symbol_order[last - 1U] = scan_symbol;
                    symbol_order[scan] = symbol;
                    symbol = symbol_order[last];
                }
                scan += 1U;
            }

            if (last != index) {
                index = last - 1U;
            }

            mask = ((mask >> 1U) | 0x8000U) & 0xFFFFU;
            if ((mask & 1U) != 0U) {
                break;
            }
        }
    }

    std::int32_t adjustments = 0;
    std::int32_t last_level = static_cast<std::int32_t>(active_levels) - 1;
    rebuild_row_ptrs();

    std::int32_t level = 0;
    while (level < static_cast<std::int32_t>(active_levels)) {
        const auto count = static_cast<std::int32_t>(
            level_counts[static_cast<std::size_t>(level)]
        );
        if (count == 0) {
            level += 1;
            continue;
        }

        const auto start = static_cast<std::int32_t>(
            row_ptrs[static_cast<std::size_t>(level)]
        );
        const auto end = static_cast<std::int32_t>(
            row_ptrs[static_cast<std::size_t>(level) + 1U]
        );
        const auto first_freq = freqs[symbol_order[static_cast<std::size_t>(start)]];

        bool branch_a = false;
        if (count < 3 || level == static_cast<std::int32_t>(max_code_len) - 1) {
            branch_a = true;
        } else {
            const auto tail_1 = freqs[symbol_order[static_cast<std::size_t>(end) - 1U]];
            const auto tail_2 = freqs[symbol_order[static_cast<std::size_t>(end) - 2U]];
            if (first_freq < tail_1 + tail_2) {
                branch_a = true;
            }
        }

        if (branch_a) {
            std::int32_t found_level = -1;
            if (level + 1 < static_cast<std::int32_t>(active_levels)) {
                std::int32_t candidate = static_cast<std::int32_t>(
                    freqs[symbol_order[
                        row_ptrs[static_cast<std::size_t>(level) + 1U] - 1U
                    ]]
                );
                for (std::int32_t deeper = level + 2;
                    deeper < static_cast<std::int32_t>(active_levels);
                    ++deeper) {
                    candidate -= static_cast<std::int32_t>(
                        freqs[symbol_order[row_ptrs[static_cast<std::size_t>(deeper)]]]
                    );
                    if (level_counts[static_cast<std::size_t>(deeper)] > 1U) {
                        const auto next_freq = freqs[symbol_order[
                            row_ptrs[static_cast<std::size_t>(deeper)] + 1U
                        ]];
                        if (candidate < 0
                            || static_cast<std::uint32_t>(candidate) < next_freq) {
                            found_level = deeper;
                            break;
                        }
                    }
                }
            }

            if (found_level == -1) {
                level += 1;
                continue;
            }

            level_counts[static_cast<std::size_t>(level)] -= 1U;
            level_counts[static_cast<std::size_t>(level) + 1U] += 2U;
            level_counts[static_cast<std::size_t>(found_level) - 1U] += 1U;
            level_counts[static_cast<std::size_t>(found_level)] -= 2U;
            adjustments += 1;
            if (level_counts[static_cast<std::size_t>(last_level)] == 0U
                && active_levels > 1U) {
                active_levels -= 1U;
                last_level -= 1;
            }
            rebuild_row_ptrs();
            level = 0;
            continue;
        }

        level_counts[static_cast<std::size_t>(level) - 1U] += 1U;
        level_counts[static_cast<std::size_t>(level)] -= 3U;
        level_counts[static_cast<std::size_t>(level) + 1U] += 2U;
        adjustments += 1;
        if (last_level == level) {
            active_levels += 1U;
            last_level += 1;
        }
        rebuild_row_ptrs();
        level = 0;
    }

    if (adjustments < 0x10) {
        if (adjustments < 8 && cooldown_base != 1U) {
            counter_reset <<= 1U;
            cooldown >>= 1U;
            cooldown_base >>= 1U;
        }
    } else {
        counter_reset = counter_orig;
        cooldown_base = cooldown_orig;
    }

    counter = counter_reset;
    if (cooldown == 0U) {
        cooldown = cooldown_base;
    }
}


Decompressor::Decompressor(ByteBuffer data)
    : data_(std::move(data)) {}

void Decompressor::ensure_initialized() {
    if (!context_initialized_) {
        initialize_compression_context();
    }
}

std::uint32_t Decompressor::read_bitstream_variable_length_uint_impl(
    std::uint32_t width
) {
    if (width == 0U) {
        return 0U;
    }

    std::uint32_t value = 0;
    std::uint32_t remaining = width;
    while (remaining > 0U) {
        const auto current = current_unread_bits();
        const auto take = remaining < bits_left_ ? remaining : bits_left_;
        const auto shift = bits_left_ - take;
        value = (value << take) | (current >> shift);
        bits_left_ -= take;
        remaining -= take;

        if (bits_left_ == 0U) {
            byte_pos_ += 1U;
            bits_left_ = 8U;
        }
    }

    return value;
}

std::uint8_t Decompressor::require_byte(std::size_t pos) const {
    if (pos >= data_.size()) {
        throw CompressionError("unexpected EOF in compressed stream");
    }
    return data_[pos];
}

std::uint32_t Decompressor::current_unread_bits() const {
    return require_byte(byte_pos_) & ((1U << bits_left_) - 1U);
}

std::uint32_t Decompressor::read_bitstream_variable_length_uint(
    std::uint32_t width
) {
    ensure_initialized();
    return read_bitstream_variable_length_uint_impl(width);
}

std::uint32_t Decompressor::get_next_bit_from_compressed_stream() {
    return read_bitstream_variable_length_uint(1U);
}

void Decompressor::initialize_compression_context() {
    context_initialized_ = false;
    byte_pos_ = 0U;
    bits_left_ = 8U;
    literal_mode_.reset();
    window_selector_.reset();
    window_size_ = 0U;
    window_mask_ = 0U;
    window_low_bits_ = 0U;
    end_seen_ = false;
    literal_table_.reset();
    length_table_.reset();
    distance_table_.reset();
    dictionary_.clear();
    dict_pos_ = 0U;

    const auto magic = read_bitstream_variable_length_uint_impl(16U);
    if (magic != kCompressionMagic) {
        throw CompressionError("unexpected  stream magic");
    }

    literal_mode_ = read_bitstream_variable_length_uint_impl(8U);
    static_cast<void>(read_bitstream_variable_length_uint_impl(8U));

    const auto table_reset = read_bitstream_variable_length_uint_impl(12U);
    const auto table_cooldown = read_bitstream_variable_length_uint_impl(12U);
    window_selector_ = read_bitstream_variable_length_uint_impl(4U);

    if (*window_selector_ == 8U) {
        window_size_ = 0x2000U;
        window_mask_ = 0x1FFFU;
        window_low_bits_ = 7U;
    } else {
        window_size_ = 0x1000U;
        window_mask_ = 0x0FFFU;
        window_low_bits_ = 6U;
    }

    if (*literal_mode_ == 0U) {
        literal_table_.emplace(8U, 0x10U, table_reset, table_cooldown);
        literal_table_->update_huffman_table_offsets(0U);
    }

    length_table_.emplace(6U, 0x0CU, table_reset, table_cooldown);
    length_table_->update_huffman_table_offsets(0U);

    distance_table_.emplace(6U, 0x0CU, table_reset, table_cooldown);
    distance_table_->update_huffman_table_offsets(0U);

    dictionary_.assign(window_size_, 0U);
    dict_pos_ = 0U;
    context_initialized_ = true;
}

std::uint32_t Decompressor::decode_huffman_symbol_with_length(
    HuffmanTable& table
) {
    ensure_initialized();

    if (bits_left_ == 0U) {
        throw CompressionError("no bits left for Huffman decode");
    }

    auto value = current_unread_bits();
    int range_index = static_cast<int>(bits_left_) - 1;
    auto available_bits = bits_left_;
    std::size_t local_byte_pos = byte_pos_;

    while (true) {
        if (range_index < 0
            || range_index >= static_cast<int>(table.range_table.size())) {
            throw CompressionError("invalid Huffman range index");
        }
        if (value >= table.range_table[static_cast<std::size_t>(range_index)][0]) {
            break;
        }

        local_byte_pos += 1U;
        const auto next_byte = require_byte(local_byte_pos);
        range_index += 8;
        available_bits += 8U;
        value = (value << 8U) | next_byte;
    }

    range_index -= 1;
    std::uint32_t remaining_bits = 0U;
    auto extra_bits = available_bits - 1U;

    while (extra_bits > 0U) {
        const auto threshold = range_index < 0
            ? 0U
            : table.range_table[static_cast<std::size_t>(range_index)][1];
        if (value < threshold) {
            break;
        }
        range_index -= 1;
        extra_bits -= 1U;
        value >>= 1U;
        remaining_bits += 1U;
    }

    const auto level = range_index + 1;
    if (level < 0
        || level >= static_cast<int>(table.row_ptrs.size()) - 1) {
        throw CompressionError("invalid Huffman level index");
    }

    const auto row_start = table.row_ptrs[static_cast<std::size_t>(level)];
    const auto symbol_slot = static_cast<std::int64_t>(row_start)
        + static_cast<std::int64_t>(value)
        - static_cast<std::int64_t>(table.range_table[static_cast<std::size_t>(level)][0]);
    if (symbol_slot < 0
        || symbol_slot >= static_cast<std::int64_t>(table.symbol_order.size())) {
        throw CompressionError("invalid Huffman symbol index");
    }

    const auto symbol = table.symbol_order[static_cast<std::size_t>(symbol_slot)];
    if (symbol == table.dummy_symbol) {
        throw CompressionError("decoded an uninitialized Huffman symbol");
    }

    byte_pos_ = local_byte_pos;
    if (remaining_bits == 0U) {
        byte_pos_ += 1U;
        bits_left_ = byte_pos_ >= data_.size() ? 0U : 8U;
    } else {
        bits_left_ = remaining_bits;
    }

    if (table.decrement_counter_and_update_array(symbol)) {
        table.optimize_huffman_table();
        table.update_huffman_table_offsets(0U);
    }

    if (symbol == table.escape_symbol) {
        const auto raw_symbol = read_bitstream_variable_length_uint(table.raw_bits);
        const auto start_level = table.update_huffman_tree_structure(raw_symbol);
        table.update_huffman_table_offsets(start_level);
        return raw_symbol;
    }

    return symbol;
}

std::optional<Token> Decompressor::decode_next_token() {
    ensure_initialized();
    if (end_seen_) {
        throw CompressionError("attempted to decode past end-of-stream marker");
    }
    if (!length_table_.has_value() || !distance_table_.has_value()) {
        throw CompressionError("compression tables were not initialized");
    }

    const auto decision = get_next_bit_from_compressed_stream();
    if (decision == 0U) {
        std::uint32_t literal = 0U;
        if (*literal_mode_ == 0U) {
            if (!literal_table_.has_value()) {
                throw CompressionError("literal table missing");
            }
            literal = decode_huffman_symbol_with_length(*literal_table_);
        } else {
            literal = read_bitstream_variable_length_uint(8U);
        }
        return Token{false, literal, 1U};
    }

    const auto distance_low = read_bitstream_variable_length_uint(window_low_bits_);
    const auto distance_high = decode_huffman_symbol_with_length(*distance_table_);
    const std::uint32_t distance =
        (distance_high << static_cast<std::uint32_t>(window_low_bits_)) | distance_low;
    if (distance == 0U) {
        end_seen_ = true;
        return std::nullopt;
    }

    const auto length = decode_huffman_symbol_with_length(*length_table_);
    return Token{true, distance + 1U, length};
}

std::vector<Token> Decompressor::decode_compressed_integer_stream() {
    ensure_initialized();

    std::vector<Token> tokens;
    if (end_seen_) {
        return tokens;
    }

    tokens.reserve(kTokenBlockSize);
    for (std::size_t index = 0; index < kTokenBlockSize && !end_seen_; ++index) {
        const auto token = decode_next_token();
        if (!token.has_value()) {
            break;
        }
        tokens.push_back(*token);
    }
    return tokens;
}

std::vector<Token> Decompressor::decode_tokens(std::size_t count) {
    ensure_initialized();

    std::vector<Token> tokens;
    tokens.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        const auto token = decode_next_token();
        if (!token.has_value()) {
            break;
        }
        tokens.push_back(*token);
    }
    return tokens;
}

ByteBuffer Decompressor::inflate_compressed_stream_with_dictionary(
    const std::vector<Token>& tokens
) {
    ensure_initialized();

    ByteBuffer output;
    for (const auto& token : tokens) {
        if (!token.is_copy) {
            const auto byte = static_cast<std::uint8_t>(token.value & 0xFFU);
            output.push_back(byte);
            dictionary_[dict_pos_] = byte;
            dict_pos_ = (dict_pos_ + 1U) & window_mask_;
            continue;
        }

        if (token.value == 0U) {
            throw CompressionError("invalid back-reference distance");
        }

        for (std::uint32_t repeat = 0; repeat < token.length; ++repeat) {
            const auto src_pos = (dict_pos_ - static_cast<std::size_t>(token.value))
                & window_mask_;
            const auto byte = dictionary_[src_pos];
            output.push_back(byte);
            dictionary_[dict_pos_] = byte;
            dict_pos_ = (dict_pos_ + 1U) & window_mask_;
        }
    }

    return output;
}

ByteBuffer Decompressor::decompress() {
    ensure_initialized();

    ByteBuffer output;
    std::size_t max_output = data_.size() * 16U;
    if (max_output < 65536U) {
        max_output = 65536U;
    }
    output.reserve(max_output);

    while (!end_seen_) {
        const auto tokens = decode_compressed_integer_stream();
        const auto block = inflate_compressed_stream_with_dictionary(tokens);
        output.insert(output.end(), block.begin(), block.end());
    }

    return output;
}

std::size_t Decompressor::bytes_consumed() const {
    if (bits_left_ == 0 || bits_left_ == 8) {
        return byte_pos_;
    }
    return byte_pos_ + 1U;
}

std::pair<ByteBuffer, std::size_t> decompress_stream(ByteView blob) {
    Decompressor decompressor(make_byte_buffer(blob));
    return {decompressor.decompress(), decompressor.bytes_consumed()};
}

}  // namespace readrtp
