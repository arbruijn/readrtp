#include "readrtp/error.hpp"

#include <string>

namespace readrtp {

PatchError::PatchError(const std::string& message) : std::runtime_error(message) {}

NotImplementedError::NotImplementedError(const std::string& message)
    : std::logic_error(message) {}

[[noreturn]] void throw_not_implemented(std::string_view feature) {
    throw NotImplementedError(
        "C++ translation stub not implemented yet: " + std::string(feature)
    );
}

}  // namespace readrtp
