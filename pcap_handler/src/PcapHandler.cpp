#include "PcapHandler.h"

#include "PcapHandlerDscr.h"
#include <array>
#include <functional>
#include <iostream>
#include <memory>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap/vlan.h>

namespace capture {

struct PcapHandler::Impl {
  pcap_t *mPcapFdPtr{nullptr};
  size_t mPcapBufferSize{65535};
  bool mStop{false};
  descriptors::PcapHandler mConfig;
  // https://www.man7.org/linux/man-pages/man3/pcap_open_live.3pcap.html
  int mPcapPromiscMode{1};
  int mPcapPacketBufferTimeout{500};
  std::array<char, PCAP_ERRBUF_SIZE> mPcapErrorBuffer;
  struct bpf_program mPcapBpfProgram = {};
  bool mBreakOnEmtyDispatchFlag{false};
  std::function<PcapHandler::cb_function_t> mCallback{nullptr};
  // PcapHandler::Source mSource{PcapHandler::Source::Unset};
};

PcapHandler::PcapHandler(const capture::descriptors::PcapHandler &config)
    : mImpl{new PcapHandler::Impl(), [](auto p) { delete p; }} {
  mImpl->mConfig = config;
}

PcapHandler::~PcapHandler() noexcept {
  if (mImpl->mPcapFdPtr) {
    pcap_close(mImpl->mPcapFdPtr);
    mImpl->mPcapFdPtr = nullptr;
  }
}

void PcapHandler::Open() { this->OpenPcap(); }

void PcapHandler::Stop() {
  if (!mImpl->mStop) {
    pcap_breakloop(mImpl->mPcapFdPtr);
    mImpl->mStop = true;
  }
}

void PcapHandler::SetCallback(std::function<cb_function_t> &&f) {
  mImpl->mCallback = std::move(f);
}

auto PcapHandler::GetCallback() -> std::function<cb_function_t> {
  return mImpl->mCallback;
}

void PcapHandler::Loop() {
  while (!mImpl->mStop) {
    if (auto ret = pcap_dispatch(
            mImpl->mPcapFdPtr, -1,
            [](u_char *user, const pcap_pkthdr *pkth, const uint8_t *data) {
              auto sniffer = reinterpret_cast<PcapHandler *>(user);

              if (auto &cb = sniffer->mImpl->mCallback; cb)
                cb(static_cast<uint32_t>(pkth->ts.tv_sec),         //
                   static_cast<uint32_t>(pkth->ts.tv_usec),        //
                   data,                                           //
                   static_cast<size_t>(pkth->caplen));             //

              struct pcap_stat ps {};
              pcap_stats(sniffer->mImpl->mPcapFdPtr, &ps);
            },
            reinterpret_cast<u_char *>(this));
        ret == 0) {
          break;
    }
    else if (ret == -1) {
        throw std::runtime_error("Pcap error: " +
                                 std::string{pcap_geterr(mImpl->mPcapFdPtr)});
    }
  }
}

void PcapHandler::OpenPcap() {
    if (const auto &src = mImpl->mConfig.mTrafficSource; src == "hw") {
    mImpl->mPcapFdPtr = pcap_open_live(
        mImpl->mConfig.mTrafficSource.c_str(), mImpl->mPcapBufferSize,
        mImpl->mPcapPromiscMode, mImpl->mPcapPacketBufferTimeout,
        mImpl->mPcapErrorBuffer.data());
    // file_or_net = false;
  } else if (src == "file") {
    mImpl->mPcapFdPtr = pcap_open_offline(mImpl->mConfig.mPcapFilePath.c_str(),
                                          mImpl->mPcapErrorBuffer.data());
    mImpl->mBreakOnEmtyDispatchFlag = true;
    // file_or_net = true;
  } else {
    throw std::runtime_error(
        "Incompatible source: " + src +
        "\" (possible values are: \"interface\", \"pcap_file\"");
  }

  if (!mImpl->mPcapFdPtr)
    throw std::runtime_error(
        "Couldn't open \"" + mImpl->mConfig.mNetworkIface.empty()
            ? mImpl->mConfig.mPcapFilePath
            : mImpl->mConfig.mNetworkIface +
                  +"\": " + std::string{mImpl->mPcapErrorBuffer.data()});

  if (!mImpl->mConfig.mBpfFilter.empty()) {
    if (pcap_compile(mImpl->mPcapFdPtr, &mImpl->mPcapBpfProgram,
                     mImpl->mConfig.mBpfFilter.c_str(), 0, 0) == -1) {
      throw std::runtime_error(
          "pcap_compile: Couldn't parse filter \"" + mImpl->mConfig.mBpfFilter +
          "\": " + std::string{pcap_geterr(mImpl->mPcapFdPtr)});
    }
    if (pcap_setfilter(mImpl->mPcapFdPtr, &mImpl->mPcapBpfProgram) == -1) {
      throw std::runtime_error("pcap_setfilter: Couldn't set filter \"" +
                               mImpl->mConfig.mBpfFilter +
                               "\": " + pcap_geterr(mImpl->mPcapFdPtr));
    }
    pcap_freecode(&mImpl->mPcapBpfProgram);
  }
}
} // namespace capture
