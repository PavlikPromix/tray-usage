#pragma once
#include "json.h"
#include <algorithm>
#include <optional>

namespace usage {
constexpr int fiveHours = 18000;
constexpr int oneWeek = 604800;
struct Window {
    double used = 0;
    std::int64_t reset = 0;
    int remaining() const { return static_cast<int>(std::floor(std::clamp(100.0 - used, 0.0, 100.0))); }
};
struct Snapshot {
    std::optional<Window> shortWindow;
    std::optional<Window> weeklyWindow;
};
inline Snapshot parse(std::string_view input) {
    const auto root = json::parse(input);
    const auto limits = root.get("rate_limit");
    if (!root.object() || !limits.object()) throw std::runtime_error("Missing rate_limit");
    Snapshot result;
    for (const auto key : {"primary_window", "secondary_window"}) {
        const auto item = limits.get(key);
        if (item.missing()) continue;
        double percent = 0, seconds = 0, reset = 0;
        if (!item.object() || !item.get("used_percent").number(percent) ||
            !item.get("limit_window_seconds").number(seconds) || percent < 0 || percent > 100)
            throw std::runtime_error("Invalid rate window");
        if (!item.get("reset_at").missing()) {
            if (!item.get("reset_at").number(reset) || reset < 0 || reset > 253402300799.0 || std::floor(reset) != reset)
                throw std::runtime_error("Invalid reset time");
        }
        Window window{percent, static_cast<std::int64_t>(reset)};
        // Match duration, never assume primary means 5h or secondary means weekly.
        if (seconds == fiveHours) result.shortWindow = window;
        if (seconds == oneWeek) result.weeklyWindow = window;
    }
    return result;
}
}
