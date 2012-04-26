#pragma once

class DatabaseLogger
{
public:
	DatabaseLogger(void);
	~DatabaseLogger(void);

	bool init(string db_path);
	void destroy();

	bool InsertKadNode(const KadNode& node,string country_name,const string country_code);
	bool InsertKadSharedFile(const KadSharedFile& file);
	bool InsertKadKeywordNode(const CUInt128& file_hash,const KadKeywordNode& keywordNode);
	bool InsertKadSourceNode(const CUInt128& file_hash,const KadFileSource& keywordNode);
	bool SaveAllKadNode(const list<KadNode>& nodes);
	bool SaveAllFileNode(const list<KadSharedFile>& files);
	bool DeleteTableData(string table_name);
	bool DeleteAllData();

	list<KadNode> LoadNodesDataFromFile();
	list<KadSharedFile> LoadSharedFileDataFromFile();
	vector<KadKeywordNode> LoadKeywordNodesFromFileHash(CUInt128 file_hash);
	vector<KadFileSource> LoadKadFileSourceFromFileHash(CUInt128 file_hash);
private:
	sqlite3* db;
	string db_path;
};
