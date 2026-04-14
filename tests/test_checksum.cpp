#include "readrtp/common.hpp"
#include "readrtp/checksum.hpp"

#include <cassert>

int main() {
    const auto empty = readrtp::update_checksum_state_bytes({});
    const auto unpacked = readrtp::unpack_checksum_state(empty);
    assert(unpacked.counter31 == 0);
    assert(unpacked.counter30 == 0);
    assert(unpacked.state31 == 0);
    assert(unpacked.state30 == 0);

    const readrtp::ByteBuffer data{0x41U};
    const auto classic = readrtp::update_checksum_state_bytes(readrtp::as_bytes(data));
    assert(
        readrtp::verify_checksum(readrtp::as_bytes(data), classic, "unit test")
        == "classic"
    );
    return 0;
}
