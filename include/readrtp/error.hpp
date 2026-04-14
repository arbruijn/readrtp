#pragma once

#include <stdexcept>
#include <string>
#include <string_view>

namespace readrtp {

class PatchError : public std::runtime_error {
public:
    explicit PatchError(const std::string& message);
};

class NotImplementedError : public std::logic_error {
public:
    explicit NotImplementedError(const std::string& message);
};

[[noreturn]] void throw_not_implemented(std::string_view feature);

}  // namespace readrtp
