#include "readrtp/types.hpp"

namespace readrtp {

bool Record::is_instruction_stream() const {
    if (type_2000.has_value()) {
        return type_2000->is_instruction_stream;
    }
    if (type_5000.has_value()) {
        return type_5000->is_instruction_stream;
    }
    return false;
}

}  // namespace readrtp
