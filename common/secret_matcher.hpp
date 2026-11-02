#pragma once
#include <array>
#include <cstddef>
#include <string_view>

namespace guard {
class SecretMatcher {
 public:
    SecretMatcher() { Reset(); }
    void Reset() { matched_.fill(0); found_ = false; }
    bool Feed(const unsigned char* bytes, size_t size) {
        for (size_t i = 0; i < size && !found_; ++i) {
            const auto c = Lower(bytes[i]);
            for (size_t encoding = 0; encoding < patterns_.size(); ++encoding) {
                const auto pattern = patterns_[encoding];
                auto& matched = matched_[encoding];
                while (matched != 0 && c != static_cast<unsigned char>(pattern[matched])) { matched = Prefix(pattern, matched); }
                if (c == static_cast<unsigned char>(pattern[matched])) { ++matched; }
                if (matched == pattern.size()) { found_ = true; break; }
            }
        }
        return found_;
    }
    bool Found() const { return found_; }
 private:
    inline static constexpr std::array<std::string_view, 3> patterns_{
        std::string_view{"secret", 6}, std::string_view{"s\0e\0c\0r\0e\0t\0", 12}, std::string_view{"\0s\0e\0c\0r\0e\0t", 12}};
    std::array<size_t, 3> matched_{};
    bool found_{};
    static unsigned char Lower(unsigned char c) { return c >= 'A' && c <= 'Z' ? static_cast<unsigned char>(c + ('a' - 'A')) : c; }
    static size_t Prefix(std::string_view pattern, size_t length) {
        for (size_t candidate = length - 1; candidate != 0; --candidate) {
            if (pattern.substr(0, candidate) == pattern.substr(length - candidate, candidate)) { return candidate; }
        }
        return 0;
    }
};
}  // namespace guard
