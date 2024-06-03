#include <TcpReassembly.h>
#include <SystemUtils.h>
#include <LRUList.h>
#include <map>
#include <sstream>
#include <fstream>
#include <iostream>
#include <HttpLayer.h>
#include <vector>
#include <ranges>

using TcpReassemblyData = std::vector<char>;


// typedef representing the connection manager and its iterator
typedef std::map<uint32_t, TcpReassemblyData> TcpReassemblyConnMgr;

/**
 * The callback being called by the TCP reassembly module whenever new data arrives on a certain connection
 */
static void tcpReassemblyMsgReadyCallback(int8_t sideIndex, const pcpp::TcpStreamData& tcpData, void* userCookie)
{
    // extract the connection manager from the user cookie
    TcpReassemblyConnMgr* connMgr = (TcpReassemblyConnMgr*)userCookie;

    // check if this flow already appears in the connection manager. If not add it
    auto iter = connMgr->find(tcpData.getConnectionData().flowKey);

    TcpReassemblyData t;
    t.resize(tcpData.getDataLength());
    memcpy(t.data(),tcpData.getData(),tcpData.getDataLength());

    if (iter == connMgr->end()) {
      connMgr->insert(
          std::make_pair(tcpData.getConnectionData().flowKey, std::move(t)));
    } else {
        // std::ranges::view::concat(iter->second,t);
        std::ranges::move(t, std::back_inserter(iter->second));
    }
}


/**
 * The callback being called by the TCP reassembly module whenever a new connection is found. This method adds the connection to the connection manager
 */
static void tcpReassemblyConnectionStartCallback(const pcpp::ConnectionData& connectionData, void* userCookie)
{
    // get a pointer to the connection manager
    TcpReassemblyConnMgr* connMgr = (TcpReassemblyConnMgr*)userCookie;

    // look for the connection in the connection manager
    auto iter = connMgr->find(connectionData.flowKey);

    // assuming it's a new connection
    if (iter == connMgr->end())
    {
        // add it to the connection manager
        connMgr->insert(std::make_pair(connectionData.flowKey, TcpReassemblyData()));
    }
}


/**
 * The callback being called by the TCP reassembly module whenever a connection is ending. This method removes the connection from the connection manager and writes the metadata file if requested
 * by the user
 */
static void tcpReassemblyConnectionEndCallback(const pcpp::ConnectionData& connectionData, pcpp::TcpReassembly::ConnectionEndReason reason, void* userCookie)
{
    // get a pointer to the connection manager
    TcpReassemblyConnMgr* connMgr = (TcpReassemblyConnMgr*)userCookie;

    // find the connection in the connection manager by the flow key
    auto iter = connMgr->find(connectionData.flowKey);

    // connection wasn't found - shouldn't get here
    if (iter == connMgr->end())
        return;

    pcpp::Packet tP;//Hack to prevent SIGFAULT (Bug in pcpp::Layer)
    pcpp::HttpResponseLayer layer((uint8_t*)iter->second.data(), iter->second.size(), nullptr, &tP);
    pcpp::HeaderField* f{nullptr};

    if (f = layer.getFieldByName("Content-Type");
        f->getFieldValue() != "image/jpeg")
      return;

    if (f = layer.getFieldByName("Date"); !f)
      return;

    const size_t cl = layer.getContentLength();
    const size_t dl = layer.getDataLen();
    if (!cl)
      return;
    if (dl < cl)
      return;

    const size_t shift = dl-cl;

    //todo move in to dedicated class
    std::ofstream outputFileStream("/tmp/" + f->getFieldValue() +".jpeg", std::ios::out | std::ios::binary);
    outputFileStream.write((char*) ( iter->second.data()+shift), cl);
    outputFileStream.close();

    // remove the connection from the connection manager
    connMgr->erase(iter);
}
