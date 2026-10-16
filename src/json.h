#pragma once
#include <charconv>
#include <cmath>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>

// A bounded JSON reader. Views borrow the input; no DOM or third-party runtime.
namespace json {
[[noreturn]] inline void invalid() { throw std::runtime_error("Invalid JSON"); }
inline unsigned hex(char c) {
    if (c >= '0' && c <= '9') return static_cast<unsigned>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<unsigned>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<unsigned>(c - 'A' + 10);
    invalid();
}
class Reader {
public:
    std::string_view text;
    size_t pos = 0;
    explicit Reader(std::string_view input) : text(input) {}
    char peek() const { return pos < text.size() ? text[pos] : '\0'; }
    void whitespace() { while (peek() == ' ' || peek() == '\t' || peek() == '\r' || peek() == '\n') ++pos; }
    void require(char c) { if (peek() != c) invalid(); ++pos; }
    unsigned codepoint() {
        if (text.size() - pos < 4) invalid();
        unsigned value = 0;
        for (int n = 0; n < 4; ++n) value = value * 16 + hex(text[pos++]);
        return value;
    }
    static void utf8(std::string& out, unsigned cp) {
        if (cp <= 0x7f) out += static_cast<char>(cp);
        else if (cp <= 0x7ff) { out += static_cast<char>(0xc0 | (cp >> 6)); out += static_cast<char>(0x80 | (cp & 63)); }
        else if (cp <= 0xffff) {
            out += static_cast<char>(0xe0 | (cp >> 12)); out += static_cast<char>(0x80 | ((cp >> 6) & 63)); out += static_cast<char>(0x80 | (cp & 63));
        } else {
            out += static_cast<char>(0xf0 | (cp >> 18)); out += static_cast<char>(0x80 | ((cp >> 12) & 63));
            out += static_cast<char>(0x80 | ((cp >> 6) & 63)); out += static_cast<char>(0x80 | (cp & 63));
        }
    }
    void string(std::string* out = nullptr) {
        require('"');
        while (pos < text.size()) {
            const auto c = static_cast<unsigned char>(text[pos++]);
            if (c == '"') return;
            if (c < 0x20) invalid();
            if (c != '\\') { if (out) *out += static_cast<char>(c); continue; }
            if (pos >= text.size()) invalid();
            const char escaped = text[pos++];
            char decoded = 0;
            switch (escaped) {
            case '"': case '\\': case '/': decoded = escaped; break;
            case 'b': decoded = '\b'; break;
            case 'f': decoded = '\f'; break;
            case 'n': decoded = '\n'; break;
            case 'r': decoded = '\r'; break;
            case 't': decoded = '\t'; break;
            case 'u': {
                unsigned cp = codepoint();
                if (cp >= 0xd800 && cp <= 0xdbff) {
                    require('\\'); require('u'); const unsigned low = codepoint();
                    if (low < 0xdc00 || low > 0xdfff) invalid();
                    cp = 0x10000 + ((cp - 0xd800) << 10) + low - 0xdc00;
                } else if (cp >= 0xdc00 && cp <= 0xdfff) invalid();
                if (out) utf8(*out, cp);
                continue;
            }
            default: invalid();
            }
            if (out) *out += decoded;
        }
        invalid();
    }
    void digits() { if (peek() < '0' || peek() > '9') invalid(); do { ++pos; } while (peek() >= '0' && peek() <= '9'); }
    void value(unsigned depth = 0) {
        if (depth > 48) invalid();
        whitespace();
        const char c = peek();
        if (c == '"') { string(); return; }
        if (c == '{' || c == '[') {
            ++pos; whitespace(); const char end = c == '{' ? '}' : ']';
            if (peek() == end) { ++pos; return; }
            for (;;) {
                if (c == '{') { string(); whitespace(); require(':'); }
                value(depth + 1); whitespace();
                if (peek() == end) { ++pos; return; }
                require(','); whitespace();
            }
        }
        for (const auto literal : {std::string_view("true"), std::string_view("false"), std::string_view("null")}) {
            if (text.substr(pos, literal.size()) == literal) { pos += literal.size(); return; }
        }
        if (peek() == '-') ++pos;
        if (peek() == '0') ++pos; else digits();
        if (peek() == '.') { ++pos; digits(); }
        if (peek() == 'e' || peek() == 'E') { ++pos; if (peek() == '+' || peek() == '-') ++pos; digits(); }
    }
};
class Value {
    std::string_view raw_;
public:
    Value() = default;
    explicit Value(std::string_view raw) : raw_(raw) {}
    bool object() const { return !raw_.empty() && raw_.front() == '{'; }
    bool missing() const { return raw_.empty() || raw_ == "null"; }
    Value get(std::string_view key) const {
        if (!object()) return {};
        Reader reader(raw_); reader.require('{'); reader.whitespace();
        while (reader.peek() != '}') {
            std::string name; reader.string(&name); reader.whitespace(); reader.require(':'); reader.whitespace();
            const size_t begin = reader.pos; reader.value(); const size_t end = reader.pos;
            if (name == key) return Value(raw_.substr(begin, end - begin));
            reader.whitespace(); if (reader.peek() == '}') break; reader.require(','); reader.whitespace();
        }
        return {};
    }
    std::string string() const {
        if (raw_.empty() || raw_.front() != '"') return {};
        Reader reader(raw_); std::string out; reader.string(&out); return out;
    }
    bool number(double& out) const {
        if (raw_.empty()) return false;
        const auto parsed = std::from_chars(raw_.data(), raw_.data() + raw_.size(), out);
        return parsed.ec == std::errc() && parsed.ptr == raw_.data() + raw_.size() && std::isfinite(out);
    }
};
inline Value parse(std::string_view input) {
    if (input.size() > 1024 * 1024) invalid();
    Reader reader(input); reader.whitespace(); const size_t begin = reader.pos; reader.value(); const size_t end = reader.pos;
    reader.whitespace(); if (reader.pos != input.size()) invalid();
    return Value(input.substr(begin, end - begin));
}
}
