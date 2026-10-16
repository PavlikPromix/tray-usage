#include "../src/usage.h"
#include <iostream>
#include <string>

namespace {
int failures = 0;
void expect(bool condition, const char* description) {
    if (!condition) { ++failures; std::cerr << "FAIL: " << description << '\n'; }
}
template<class F> void rejects(F action, const char* description) {
    try { action(); expect(false, description); } catch (const std::exception&) {}
}
}
int main() {
    const auto normal = usage::parse(R"({"email":"ignored@example.test","rate_limit":{"primary_window":{"used_percent":60,"limit_window_seconds":18000,"reset_at":1792128826},"secondary_window":{"used_percent":41,"limit_window_seconds":604800,"reset_at":1792671473}},"code_review_rate_limit":{"primary_window":{"used_percent":99,"limit_window_seconds":18000}}})");
    expect(normal.shortWindow && normal.shortWindow->remaining() == 40, "5h remaining, not used or code-review quota");
    expect(normal.weeklyWindow && normal.weeklyWindow->remaining() == 59, "weekly remaining");
    expect(normal.weeklyWindow && normal.weeklyWindow->reset == 1792671473, "Unix seconds preserved");
    const auto swapped = usage::parse(R"({"rate_limit":{"secondary_window":{"used_percent":0,"limit_window_seconds":18000},"primary_window":{"used_percent":100,"limit_window_seconds":604800}}})");
    expect(swapped.shortWindow && swapped.shortWindow->remaining() == 100, "identify 5h by duration");
    expect(swapped.weeklyWindow && swapped.weeklyWindow->remaining() == 0, "identify weekly by duration");
    const auto missing = usage::parse(R"({"rate_limit":{"primary_window":null,"secondary_window":null}})");
    expect(!missing.shortWindow && !missing.weeklyWindow, "missing data must not turn into 100 percent");
    const auto other = usage::parse(R"({"rate_limit":{"primary_window":{"used_percent":10,"limit_window_seconds":900}}})");
    expect(!other.shortWindow, "15m quota is not a 5h quota");
    expect(usage::Window{99.8, 0}.remaining() == 0, "remaining percent rounds down");
    rejects([] { usage::parse(R"({"rate_limit":{"primary_window":{"used_percent":-1,"limit_window_seconds":18000}}})"); }, "negative percent");
    rejects([] { usage::parse(R"({"rate_limit":{"primary_window":{"used_percent":101,"limit_window_seconds":18000}}})"); }, "percent over 100");
    rejects([] { usage::parse(R"({"rate_limit":{"primary_window":{"used_percent":"60","limit_window_seconds":18000}}})"); }, "wrong type");
    rejects([] { usage::parse(R"({"rate_limit":{"primary_window":{"used_percent":10,"limit_window_seconds":18000,"reset_at":1e99}}})"); }, "overflow timestamp");
    rejects([] { usage::parse(R"({"error":"unauthorized"})"); }, "unexpected server schema");
    const std::string auth = R"({"tokens":{"access_token":"a\"b\\c","account_id":"\u0061"},"emoji":"\ud83d\ude00"})";
    const auto parsed = json::parse(auth);
    expect(parsed.get("tokens").get("access_token").string() == "a\"b\\c", "escaped credentials");
    expect(parsed.get("tokens").get("account_id").string() == "a", "unicode escapes");
    expect(parsed.get("emoji").string() == "\xf0\x9f\x98\x80", "surrogate pairs");
    for (const char* bad : {"", "{", "[1,]", "{\"a\":1,}", "01", "1.", "1e", "true false", "\"\\x\"", "\"\\ud800\"", "\"\\udc00\""})
        rejects([bad] { json::parse(bad); }, "malformed JSON");
    const std::string deep = std::string(60, '[') + "0" + std::string(60, ']');
    rejects([&] { json::parse(deep); }, "bounded nesting");
    expect(json::parse(" \r\n{\"ignored\":[true,false,null,-1.25e+2,{}]} \t").object(), "nested unknown fields");
    if (!failures) std::cout << "All usage and JSON tests passed\n";
    return failures ? 1 : 0;
}
