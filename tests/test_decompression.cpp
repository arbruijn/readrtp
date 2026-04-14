#include "readrtp/buffer.hpp"
#include "readrtp/decompression.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <filesystem>
#include <iostream>
#include <utility>

int main() {
    readrtp::HuffmanTable table(8, 16, 1, 1);
    assert(table.escape_symbol == 256);

    const auto package_blob = readrtp::read_file_bytes("data.bin");

    {
        const std::array<std::uint8_t, 16> expected_prefix{
            0x02, 0x00, 0x08, 0x60, 0x07, 0x2A, 0x0F, 0x08,
            0x60, 0x35, 0x2C, 0x1A, 0x08, 0x60, 0x51, 0x2C,
        };
        readrtp::Decompressor decompressor(
            readrtp::ByteBuffer(package_blob.begin() + 0xFF, package_blob.end())
        );
        const auto output = decompressor.decompress();
        assert(output.size() == 13188U);
        assert(decompressor.bytes_consumed() == 10669U);
        assert(std::equal(output.begin(), output.begin() + 16, expected_prefix.begin()));
    }

    {
        const auto expected = readrtp::read_file_bytes("test/d3new/version.new");
        readrtp::Decompressor decompressor(
            readrtp::ByteBuffer(
                package_blob.begin() + 0x176D95,
                package_blob.end()
            )
        );
        const auto output = decompressor.decompress();
        assert(output == expected);
    }

    {
        const auto stream = readrtp::ByteBuffer(
            package_blob.begin() + 0x1308E9,
            package_blob.begin() + 0x1308E9 + 0x24B
        );
        readrtp::Decompressor decompressor(std::move(stream));
        const auto tokens = decompressor.decode_tokens(65);
        assert(tokens.size() == 65U);
        assert(!tokens[64].is_copy);
        assert(tokens[64].value == static_cast<std::uint32_t>('E'));
    }

    return 0;
}
