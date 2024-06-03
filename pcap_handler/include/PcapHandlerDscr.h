#pragma once

#include <nlohmann/json.hpp>
#include <string>

namespace capture::utility::json {
template <typename ValueType>
static inline void tryGetValue(const nlohmann::json &j, const std::string &name,
                               ValueType &value) noexcept {
  value = j.contains(name) ? j.at(name).get_to(value) : value;
}
} // namespace utility::json

namespace capture::descriptors {
struct PcapHandler {  
  std::string mTrafficSource{};
  std::string mBpfFilter{};
  std::string mPcapFilePath{};
  std::string mNetworkIface{};
};

/**
 * @brief to_json
 * @param j
 * @param p
 */
[[maybe_unused]] static void to_json(nlohmann::json &j, const PcapHandler &p) {
  // clang-format off
    j = nlohmann::json{                
        {"traffic_source", p.mTrafficSource},
        {"pcap_file", p.mPcapFilePath},
        {"filter", p.mBpfFilter}
    };

    if(!p.mNetworkIface.empty())
        j.emplace("interface", p.mNetworkIface);
    else
        j.emplace("pcap_file", p.mPcapFilePath);

  // clang-format on
}
/**
 * @brief from_json
 * @param j
 * @param p
 */
[[maybe_unused]] static void from_json(const nlohmann::json &j,
                                       PcapHandler &p) {
  ///\warning execeptions if field name is mising  
  utility::json::tryGetValue(j, "traffic_source", p.mTrafficSource);
  utility::json::tryGetValue(j, "interface", p.mNetworkIface);
  utility::json::tryGetValue(j, "pcap_file", p.mPcapFilePath);
  utility::json::tryGetValue(j, "filter", p.mBpfFilter);
}
} // namespace descriptors
