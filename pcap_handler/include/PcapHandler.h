#include <memory>
#include <pcap.h>
#include <string_view>
#include <functional>

namespace capture {
namespace descriptors {
struct PcapHandler;
}

class PcapHandler {
public:
  // tm,tm_ns,data_prt, data_size
  using cb_function_t = bool(uint32_t, uint32_t, const uint8_t *, const size_t);

  // enum class Source { File, Hw, Unset };

  PcapHandler(const capture::descriptors::PcapHandler &config);
  virtual ~PcapHandler() noexcept;

  /*!
   * \brief Open
   */
  void Open();

  /*!
   * \brief Stop
   */
  void Stop();

  /*!
   * \brief Loop
   * \param stop
   */
  void Loop();

  /*!
   * \brief SetCallback
   * \param f
   */
  void SetCallback(std::function<cb_function_t> &&f);

  /*!
   * \brief GetCallback
   * \return std::function<cb_function_t>
   */
  auto GetCallback() -> std::function<cb_function_t>;

private:
  /*!
   * \brief openPcap
   * \param source
   */
  void OpenPcap();

  struct Impl;
  std::unique_ptr<Impl, void (*)(Impl *)> mImpl;
};

} // namespace capture
