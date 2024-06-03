#include <GetOptPP/ConsoleKeyOption.h>
#include <GetOptPP/ConsoleOptionsHandler.h>
#include <PcapHandler.h>
#include <PcapHandlerDscr.h>
#include <filesystem>
#include <fstream>
#include <pcap/pcap.h>
#include <string.h> //strlen
#include <thread>
#include <mutex>
#include <regex>
#include <TcpReassembly.h>
#include "tcpcb.h"

using namespace std;

constexpr std::string_view help = R"(
/******************************************************************************
 * Irtea test application
 * Usage:
 * app  [--ip_dst] [--tcp_sp] [--ip_src] [--tcp_dp] [--file]
 *
 * Examples:
 *
 * app --ip_dst 10.1.1.101 --tcp_sp 80 --ip_src 10.1.1.1 --tcp_dp 3200 --file /tmp/http_with_jpegs.cap
 *
 *
 * app --config /tmp/config/run.json
 *
 * Config example:
    {
       "handlers":[
          {
             "traffic_source":"file",
             "pcap_file":"/tmp/http_with_jpegs.cap",
             "filter":"ip and src 10.1.1.1 and dst 10.1.1.101 and tcp and src port 80 and dst port 3200"
          }
       ]
    }
 *
 *
 *****************************************************************************/
)";

namespace utils {
namespace filesystem {

/* Reads file in vector*/
[[maybe_unused]] auto
ReadBinaryFile(const std::filesystem::path &path) noexcept {
  std::ifstream stream(path.c_str(), std::ios::binary);

  std::vector<char> vec;

  if (stream.is_open()) {
    stream.seekg(0, std::ios::end);
    auto size = stream.tellg();
    stream.seekg(0, std::ios::beg);

    vec.resize(size);
    stream.read((char *)vec.data(), size);

    return vec;
  }

  return vec;
}
} // namespace filesystem
namespace ip {
/*
 * Converts a string containing an (IPv4) Internet Protocol
 * dotted address into a proper address
 */
static uint32_t ip2long(const char *ip) {
  struct in_addr s;

  if (!strlen(ip) || // pcap
      !inet_aton(ip, &s))
    return 0;

  return ntohl(s.s_addr);
}
} // namespace ip
} // namespace utils

int main(int argc, char **argv) {
  bool helpInvoked{false};

  GetOptPlusPlus::ConsoleOptionsHandler cmdHandler(argc, argv);  
  capture::descriptors::PcapHandler pcapCfg;

  std::string bpfFilterString{"ip and src <IP_SRC> and dst <IP_DST> and tcp and src port <TCP_SP> and dst port <TCP_DP>" };
  bool bpfFilterWasModified{false};

  std::vector<capture::descriptors::PcapHandler> handlersConfigs;
  std::vector<std::shared_ptr<capture::PcapHandler>> handlers{};
  std::vector<std::jthread> workers{};

  cmdHandler.AddKey({"help", nullptr, 0}, [&helpInvoked](auto *p) {
    helpInvoked = true;
    printf("%s", help.data());
  });

  cmdHandler.AddKey({"ip_src", nullptr, 1}, [&bpfFilterString, &bpfFilterWasModified](const auto *p) {
      bpfFilterString = std::regex_replace(bpfFilterString, std::regex(R"(<IP_SRC>)"), std::string{p});
      bpfFilterWasModified = true;
  });

  cmdHandler.AddKey({"ip_dst", nullptr, 1}, [&bpfFilterString, &bpfFilterWasModified](auto *p) {
      bpfFilterString =  std::regex_replace(bpfFilterString, std::regex(R"(<IP_DST>)"), std::string{p});
      bpfFilterWasModified = true;
  });

  cmdHandler.AddKey({"tcp_sp", nullptr, 1}, [&bpfFilterString, &bpfFilterWasModified](auto *p) {
      bpfFilterString =  std::regex_replace(bpfFilterString, std::regex(R"(<TCP_SP>)"), std::string{p});
      bpfFilterWasModified = true;
  });

  cmdHandler.AddKey({"tcp_dp", nullptr, 1}, [&bpfFilterString, &bpfFilterWasModified](auto *p) {
      bpfFilterString =  std::regex_replace(bpfFilterString, std::regex(R"(<TCP_DP>)"), std::string{p});
      bpfFilterWasModified = true;
  });

  cmdHandler.AddKey({"file", nullptr, 1}, [&pcapCfg](auto *p) {
      pcapCfg.mTrafficSource = "file";
      pcapCfg.mPcapFilePath = std::string{p};
  });

  cmdHandler.AddKey(
      {"config", nullptr, 1}, [&pcapCfg, &handlersConfigs](auto *p) {
        if (!p)
          return;

        std::filesystem::path path(p);
        if (const auto ext = path.extension(); ext != ".json")
          throw std::runtime_error("Unsupported config file format (" +
                                   ext.string() + ")!");

        {
          const auto cTxt = utils::filesystem::ReadBinaryFile(path);
          constexpr auto handlersSectionName = "handlers";

          nlohmann::json j{};
          std::istringstream inputStream(cTxt.data());
          inputStream >> j;

          if (j.contains(handlersSectionName))
            if (!j.at(handlersSectionName).is_array())
              throw std::runtime_error("Wrong configuration format!");

          for (const auto &jc : j.at(handlersSectionName)) {
            handlersConfigs.push_back(
                jc.template get<capture::descriptors::PcapHandler>());
          }
        }
      });

  cmdHandler.ProcessCmdLine();

  if (helpInvoked)
    return 0;

  if (!bpfFilterWasModified)
    return 0;

  pcapCfg.mBpfFilter = bpfFilterString;
  handlersConfigs.push_back(pcapCfg);

  TcpReassemblyConnMgr connMgr;
  std::mutex tcpReassemblyMutex;
  pcpp::TcpReassembly tcpReassembly(tcpReassemblyMsgReadyCallback, &connMgr,
                              tcpReassemblyConnectionStartCallback,
                              tcpReassemblyConnectionEndCallback);

  for(const auto &hc: handlersConfigs){
      auto handler = std::make_shared<capture::PcapHandler>(hc);
      handler->SetCallback(
          [&](uint32_t s, uint32_t uSec, const uint8_t *d, const size_t sz) {
            pcpp::RawPacket rawPacket(d, sz, timeval{s, uSec}, false);
            //Lock
            {
              std::lock_guard lock{tcpReassemblyMutex};
              tcpReassembly.reassemblePacket(&rawPacket);
            }
            return false;
          });
      auto worker = std::jthread([handler,&tcpReassembly](std::stop_token st) {
          handler->Open();
          handler->Loop();
          handler->Stop();
          // extract number of connections before closing all of them
          size_t numOfConnectionsProcessed = tcpReassembly.getConnectionInformation().size();

          // after all packets have been read - close the connections which are still opened
          tcpReassembly.closeAllConnections();
      });
      std::stop_callback cb(worker.get_stop_token(),[handler]{
          handler->Stop();
      });
      workers.push_back(std::move(worker));
      handlers.push_back(std::move(handler));
  }

  return 0;
}
