#pragma once
#include <array>
#include <bit>
#include <cstddef>
#include <string_view>
#if defined(_M_X64) || defined(__SSE2__)
#include <emmintrin.h>
#endif

namespace guard {
class SecretMatcher {
 public:
    SecretMatcher() { Reset(); }
    void Reset() { matched_.fill(0); found_ = false; }
    bool Feed(const unsigned char* bytes, size_t size) {
        size_t i = 0;
        while (i < size && !found_) {
            if (matched_[0] == 0 && matched_[1] == 0 && matched_[2] <= 1) {
                const size_t skip = NextStart(bytes + i, size - i);
                if (skip != 0) { matched_[2] = bytes[i + skip - 1] == 0 ? 1 : 0; i += skip; }
                if (i == size) { break; }
            }
            Match(Lower(bytes[i]));
            ++i;
        }
        return found_;
    }
    bool Found() const { return found_; }
 private:
    inline static constexpr std::array<std::string_view, 3> patterns_{
        std::string_view{"secret", 6}, std::string_view{"s\0e\0c\0r\0e\0t\0", 12}, std::string_view{"\0s\0e\0c\0r\0e\0t", 12}};
    std::array<size_t, 3> matched_{};
    bool found_{};
    static size_t NextStart(const unsigned char* bytes, size_t size) {
        size_t next = 0;
#if defined(_M_X64) || defined(__SSE2__)
        // Sixteen possible starts, with enough lookahead for the S-centered
        // UTF-16 prefix. The scalar tail preserves partial cross-buffer matches.
        for (; size - next >= 26; next += 16) {
            const auto first = _mm_or_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(bytes + next)), _mm_set1_epi8(0x20));
            if (_mm_movemask_epi8(_mm_cmpeq_epi8(first, _mm_set1_epi8('s'))) == 0) { continue; }
            const auto mask = WindowMask(bytes + next, patterns_[0]) |
                WindowMask(bytes + next, patterns_[1].substr(0, 11));
            if (mask != 0) { return next + static_cast<size_t>(std::countr_zero(mask)); }
        }
#endif
        while (next < size && Lower(bytes[next]) != 's') { ++next; }
        return next;
    }
#if defined(_M_X64) || defined(__SSE2__)
    static unsigned WindowMask(const unsigned char* bytes, std::string_view pattern) {
        auto matches = _mm_set1_epi8(-1);
        for (size_t i = 0; i < pattern.size(); ++i) {
            auto value = _mm_loadu_si128(reinterpret_cast<const __m128i*>(bytes + i));
            if (pattern[i] != 0) { value = _mm_or_si128(value, _mm_set1_epi8(0x20)); }
            matches = _mm_and_si128(matches, _mm_cmpeq_epi8(value, _mm_set1_epi8(pattern[i])));
            if (_mm_movemask_epi8(matches) == 0) { return 0; }
        }
        return static_cast<unsigned>(_mm_movemask_epi8(matches));
    }
#endif
    void Match(unsigned char c) {
        for (size_t encoding = 0; encoding < patterns_.size(); ++encoding) {
            const auto pattern = patterns_[encoding];
            auto& matched = matched_[encoding];
            while (matched != 0 && c != static_cast<unsigned char>(pattern[matched])) { matched = Prefix(pattern, matched); }
            if (c == static_cast<unsigned char>(pattern[matched])) { ++matched; }
            if (matched == pattern.size()) { found_ = true; return; }
        }
    }
    static unsigned char Lower(unsigned char c) { return c >= 'A' && c <= 'Z' ? static_cast<unsigned char>(c + ('a' - 'A')) : c; }
    static size_t Prefix(std::string_view pattern, size_t length) {
        for (size_t candidate = length - 1; candidate != 0; --candidate) {
            if (pattern.substr(0, candidate) == pattern.substr(length - candidate, candidate)) { return candidate; }
        }
        return 0;
    }
};
}  // namespace guard
