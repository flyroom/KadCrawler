#pragma once

class KadCrawleManager
{
public:
	KadCrawleManager(void);
	~KadCrawleManager(void);
    unsigned long updateNodesByBootstrapReqPeriodically(unsigned long times);
	unsigned long updateNodesAndCleanUp(CUInt128& node_id,unsigned int base,unsigned int coff);
	unsigned long updateNodesByBootstrapReq(unsigned int version);
    unsigned long updateNodeByFullQuery(unsigned int coff);
    unsigned long updateNodesByMixedReq(unsigned long delay_between_packets_mseconds,const KadCrawl::KadFilter& pass_filter,const KadCrawl::KadFilter& block_filter);
    unsigned long updateNodesBySampleBootstrapReq(unsigned int version,unsigned long sample_rate);

	unsigned long scanWithPing();
	unsigned long scanWithHelloReq();
    unsigned long scanWithHelloReqUseSybils(uint8 udp_port);
	void crawlSingleNode(unsigned int coff);
	void searchKeywordOp(string keyword);
	void crawl8bitZone(CUInt128& node_id);
	void setKadScanner(KadScanner* scanner);
	void findUnbuddyedActiveNodes(list<KadNode>& nodes);
	void setFileQueryEngine(KadFileDownloader* downloader);
	void searchFileSharedPeers(string keyword);
	void receiveMessageEventHandler(unsigned long ip,unsigned char*data,unsigned long len);
private:
	KadScanner* scanner;
	KadFileDownloader* fileQueryEngine;
	reset_event singleCrawleEvent;

	vector<unsigned long> ActiveIPs;
};
