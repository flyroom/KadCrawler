#include"config.h"
#include"KadUtil.h"
#include"DatabaseLogger.h"
#include"KadScanner.h"
// The caller must explitcitly call init and destroy method of this class

using namespace KadCrawl;

typedef int (*sqlite3_callback)(void*,int,char**,char**);

int LoadInfo(void * para,int n_column,char** column_value,char** column_name)
{
	DEBUG_PRINT2("this record contains %d field\n",n_column);
	
	return 0;
}

DatabaseLogger::DatabaseLogger(void)
{
}

DatabaseLogger::~DatabaseLogger(void)
{
}

bool DatabaseLogger::init(string path)
{
	db_path = path;
	char* errmsg = NULL;
	int result = sqlite3_open(db_path.c_str(),&db);
	if(result != SQLITE_OK)
	{
		DEBUG_PRINT2("sqlite3 database open failed %s\n",db_path.c_str());
		return false;
	}

	//result = sqlite3_exec(db,"drop table nodes",LoadInfo,NULL,&errmsg);

	string create_kadnodes_table_sql="create table nodes(ID integer primary key autoincrement,kad_id nvarchar(32),bit_zone unsigned integer,ipaddr_net unsigned integer,ip nvarchar(20),country nvarchar(50),country_code nvarchar(4),udp_port unsigned smallint,tcp_port unsigned smallint,version unsigned smallint,udp_key unsigned big int)";
	result = sqlite3_exec(db,create_kadnodes_table_sql.c_str(),NULL,NULL,&errmsg);
	if(result != SQLITE_OK)
	{
		DEBUG_PRINT3("create table nodes failed  error code:%d, detailed reasion:%s\n",result,errmsg);
		return false;
	}

	string create_kadkeywords_table_sql="create table keywords(ID integer primary key autoincrement,file_hash nvarchar(32),file_length unsigned integer,keyword_hash nvarchar(32))";
	result = sqlite3_exec(db,create_kadkeywords_table_sql.c_str(),NULL,NULL,&errmsg);
	if(result != SQLITE_OK)
	{
		DEBUG_PRINT3("create table kad keyword table failed  error code:%d, detailed reasion:%s\n",result,errmsg);
		return false;
	}

	string create_kadkeywordsNodes_table_sql="create table keywordNodes(ID integer primary key autoincrement,file_hash nvarchar(32),ipaddr_net unsigned integer,udp_port unsigned integer,file_name nvarchar(200),source_id nvarchar(32))";
	result = sqlite3_exec(db,create_kadkeywordsNodes_table_sql.c_str(),NULL,NULL,&errmsg);
	if(result != SQLITE_OK)
	{
		DEBUG_PRINT3("create table kad keywordNodes table failed  error code:%d, detailed reasion:%s\n",result,errmsg);
		return false;
	}
	
	string create_kadfilesources_table_sql="create table filesources(ID integer primary key autoincrement,type unsigned integer,file_hash nvarchar(32),ipaddr_net unsigned integer,tcp_port unsigned integer,udp_port unsigned integer,buddy_ip unsigned integer,buddy_port unsigned integer,buddy_id nvarchar(32))";
	result = sqlite3_exec(db,create_kadfilesources_table_sql.c_str(),NULL,NULL,&errmsg);
	if(result != SQLITE_OK)
	{
		DEBUG_PRINT3("create table kad filesources table failed  error code:%d, detailed reasion:%s\n",result,errmsg);
		return false;
	}

	result = sqlite3_exec(db,"select count(*) from nodes",LoadInfo,NULL,&errmsg);
	if(result != SQLITE_OK)
	{
		DEBUG_PRINT3("query table nodes failed  error code:%d, detailed reasion:%s\n",result,errmsg);
		return false;
	}
	return true;
}

bool DatabaseLogger::InsertKadNode(const KadNode& node,string country_name,const string country_code)
{
	char* errmsg;
	std::ostringstream stream;
	stream<<"insert into nodes(kad_id,bit_zone,ipaddr_net,ip,country,country_code,udp_port,tcp_port,version,udp_key) values(";
	stream<<"'"<<node.kad_id.ToHexString()<<"',";
	stream<<((unsigned int)node.kad_id.GetByteChunk(0))<<",";
	stream<<node.ipNetOrder<<",";
	stream<<"'"<<inet_ntoa(*((in_addr*)&node.ipNetOrder))<<"',";
    replace(country_name,"'","''");
	stream<<"'"<<country_name<<"',";
    stream<<"'"<<country_code<<"',";
	stream<<node.udp_port<<",";
	stream<<node.tcp_port<<",";
	stream<<((unsigned int)node.version)<<",";
	stream<<node.kadUDPkey.GetInt64Value()<<")";
	
	int result = sqlite3_exec(db,stream.str().c_str(),NULL,NULL,&errmsg);
	if(result != SQLITE_OK)
	{
		DEBUG_PRINT4("kadnode insert into database failed,error code:%d,detailed reason:%s %s\n",result,errmsg,stream.str().c_str());
		return false;
	}
	return true;
}

bool DatabaseLogger::InsertKadSharedFile(const KadSharedFile& file)
{
	char* errmsg;
	std::ostringstream stream;
	stream<<"insert into keywords(file_hash,file_length,keyword_hash) values(";
	stream<<"'"<<file.fileHash.ToHexString()<<"',";
	stream<<file.fileSize<<",";
	stream<<"'"<<file.keywordID.ToHexString()<<"')";
	int result = sqlite3_exec(db,stream.str().c_str(),NULL,NULL,&errmsg);
	if(result != SQLITE_OK)
	{
		DEBUG_PRINT4("keywords insert into database failed,error code:%d,detailed reason:%s %s\n",result,errmsg,stream.str().c_str());
		return false;
	}

	for(unsigned int i=0;i<file.keywordNodeList.size();i++)
	{
		InsertKadKeywordNode(file.fileHash,file.keywordNodeList[i]);
	}

	for(unsigned int j=0;j<file.sourceList.size();j++)
	{
		InsertKadSourceNode(file.fileHash,file.sourceList[j]);
	}

	return true;
}

bool DatabaseLogger::InsertKadKeywordNode(const CUInt128& file_hash,const KadKeywordNode& keywordNode)
{
	//file_hash nvarchar(32),ipaddr_net unsigned integer,udp_port unsigned integer,file_name nvarchar(200),source_id nvarchar(32)
	char* errmsg;
	std::ostringstream stream;
	stream<<"insert into keywordNodes(file_hash,ipaddr_net,udp_port,file_name,source_id) values(";
	stream<<"'"<<file_hash.ToHexString()<<"',";
	stream<<keywordNode.srcNodeIP<<",";
	stream<<keywordNode.srcNodeUdpPort<<",";
	string filename = keywordNode.fileName;
	replace(filename,"'",".");
	stream<<"'"<<filename<<"',";
	stream<<"'"<<keywordNode.srcNodeID.ToHexString()<<"')";
	int result = sqlite3_exec(db,stream.str().c_str(),NULL,NULL,&errmsg);
	if(result != SQLITE_OK)
	{
		DEBUG_PRINT4("keyword Node insert into database failed,error code:%d,detailed reason:%s %s\n",result,errmsg,stream.str().c_str());
		return false;
	}
	return true;
}

bool DatabaseLogger::InsertKadSourceNode(const CUInt128& file_hash,const KadFileSource& sourceNode)
{
	//type nvarchar(1),file_hash nvarchar(32),ipaddr_net unsigned integer,tcp_port unsigned integer,udp_port unsigned integer,buddy_ip unsigned integer,buddy_port unsigned integer,buddy_id nvarchar(32)

	char* errmsg;
	std::ostringstream stream;
	stream<<"insert into filesources(type,file_hash,ipaddr_net,tcp_port,udp_port,buddy_ip,buddy_port,buddy_id) values(";
	stream<<((unsigned int)sourceNode.uType)<<",";
	stream<<"'"<<file_hash.ToHexString()<<"',";
	stream<<sourceNode.sourceIP<<",";
	stream<<sourceNode.serverTcpPort<<",";
	stream<<sourceNode.serverUdpPort<<",";
	stream<<sourceNode.buddyIP<<",";
	stream<<sourceNode.buddyPort<<",";
	stream<<"'"<<sourceNode.buddyID.ToHexString()<<"')";
	int result = sqlite3_exec(db,stream.str().c_str(),NULL,NULL,&errmsg);
	if(result != SQLITE_OK)
	{
		DEBUG_PRINT4("source node insert into database failed,error code:%d,detailed reason:%s %s\n",result,errmsg,stream.str().c_str());
		return false;
	}
	return true;
}

bool DatabaseLogger::SaveAllFileNode(const list<KadSharedFile>& files)
{
	DeleteTableData("keywords");
	DeleteTableData("keywordNodes");
	DeleteTableData("filesources");
	list<KadSharedFile>::const_iterator it = files.begin();
	for(;it != files.end();it++)
	{
		const KadSharedFile& fileNode = *it;
		InsertKadSharedFile(fileNode);
	}
	return true;
}

bool DatabaseLogger::SaveAllKadNode(const list<KadNode>& nodes)
{
	if(!DeleteAllData())
		return false;
	GeoIP * gi;
	gi = GeoIP_new(GEOIP_STANDARD);
	list<KadNode>::const_iterator it = nodes.begin();
	for(;it != nodes.end();it++)
	{
		const KadNode& node = *it;
		char* ipaddr_str = inet_ntoa(*((in_addr*)&node.ipNetOrder));
        const char* country_code = GeoIP_country_code_by_addr(gi,ipaddr_str);
		int country_id = GeoIP_id_by_addr(gi,ipaddr_str);
		const char * full_country_string = GeoIP_country_name_by_id(gi,country_id);

		string country,country_code_str;
		if(full_country_string==NULL || country_code==NULL)
		{
			country = "None";
			country_code_str = "O1";
		}
		else
		{
			country = full_country_string;
			country_code_str = country_code;
		}
		InsertKadNode(node,country,country_code_str);
	}
	return true;
}

list<KadSharedFile> DatabaseLogger::LoadSharedFileDataFromFile()
{
	list<KadSharedFile> nodes;

	int nrow=0;
	int ncolumn=0;
	char** result=0;
	char* errMsg;

	string sql="select file_hash,file_length,keyword_hash from keywords";
	int error_code = sqlite3_get_table(db,sql.c_str(),&result,&nrow,&ncolumn,&errMsg);
	if(error_code != SQLITE_OK)
	{
		DEBUG_PRINT3("load table keywords failed  error code:%d, detailed reasion:%s\n",error_code,errMsg);
		return nodes;
	}
	DEBUG_PRINT3("Reading KadNodes datafile with %d rows and %d columns",nrow,ncolumn);
	for(int i=1;i<=nrow;i++)
	{
		char* file_hash = result[i*ncolumn];
		char* file_length = result[i*ncolumn+1];
		char* keyword_hash = result[i*ncolumn+2];

		KadSharedFile kadFile;
		kadFile.fileHash.FromHexString(file_hash);
		kadFile.fileSize = (unsigned short)atol(file_length);
		kadFile.keywordID.FromHexString(keyword_hash);
		
		kadFile.keywordNodeList = LoadKeywordNodesFromFileHash(kadFile.fileHash);
		kadFile.sourceList = LoadKadFileSourceFromFileHash(kadFile.fileHash);
		nodes.push_back(kadFile);
	}
	return nodes;
}

vector<KadKeywordNode> DatabaseLogger::LoadKeywordNodesFromFileHash(CUInt128 file_hash)
{
	vector<KadKeywordNode> nodes;

	int nrow=0;
	int ncolumn=0;
	char** result=0;
	char* errMsg;
	//file_hash,ipaddr_net,udp_port,file_name,source_id
	string sql="select file_hash,ipaddr_net,udp_port,file_name,source_id from keywordNodes where file_hash='";
	sql.append(file_hash.ToHexString());
	sql.append("'");
	int error_code = sqlite3_get_table(db,sql.c_str(),&result,&nrow,&ncolumn,&errMsg);
	if(error_code != SQLITE_OK)
	{
		DEBUG_PRINT3("load table keywordNodes failed  error code:%d, detailed reasion:%s\n",error_code,errMsg);
		return nodes;
	}

	for(int i=1;i<=nrow;i++)
	{
		char* file_hash = result[i*ncolumn];
		char* ipaddr_net = result[i*ncolumn+1];
		char* udp_port = result[i*ncolumn+2];
		char* file_name = result[i*ncolumn+3];
		char* source_id = result[i*ncolumn+4];
		
		KadKeywordNode keywordNode;
		keywordNode.srcNodeIP = atol(ipaddr_net);
		keywordNode.srcNodeUdpPort = atol(udp_port);
		keywordNode.fileName = file_name;
		
		keywordNode.srcNodeID.FromHexString(source_id);
		nodes.push_back(keywordNode);
	}
	return nodes;
}

vector<KadFileSource> DatabaseLogger::LoadKadFileSourceFromFileHash(CUInt128 file_hash)
{
	vector<KadFileSource> nodes;

	int nrow=0;
	int ncolumn=0;
	char** result=0;
	char* errMsg;
	//// filesources(type,file_hash,ipaddr_net,tcp_port,udp_port,buddy_ip,buddy_port,buddy_id)
	string sql="select type,ipaddr_net,tcp_port,udp_port,buddy_ip,buddy_port,buddy_id from filesources where file_hash='";
	sql.append(file_hash.ToHexString());
	sql.append("'");
	int error_code = sqlite3_get_table(db,sql.c_str(),&result,&nrow,&ncolumn,&errMsg);
	if(error_code != SQLITE_OK)
	{
		DEBUG_PRINT3("load table keywordNodes failed  error code:%d, detailed reasion:%s\n",error_code,errMsg);
		return nodes;
	}

	for(int i=1;i<=nrow;i++)
	{
		char* type = result[i*ncolumn];
		char* ipaddr_net = result[i*ncolumn+1];
		char* tcp_port = result[i*ncolumn+2];
		char* udp_port = result[i*ncolumn+3];
		char* buddy_ip = result[i*ncolumn+4];
		char* buddy_port = result[i*ncolumn+5];
		char* buddy_id = result[i*ncolumn+6];
		
		KadFileSource fileSource;
		fileSource.uType = atoi(type);
		fileSource.sourceIP = atol(ipaddr_net);
		fileSource.serverTcpPort = atol(tcp_port);
		fileSource.serverUdpPort = atol(udp_port);
		fileSource.buddyIP = atol(buddy_ip);
		fileSource.buddyPort = atol(buddy_port);
		fileSource.buddyID.FromHexString(buddy_id);
		nodes.push_back(fileSource);
	}
	return nodes;
}

list<KadNode> DatabaseLogger::LoadNodesDataFromFile()
{
	list<KadNode> nodes;

	int nrow=0;
	int ncolumn=0;
	char** result=0;
	char* errMsg;

	string sql="select kad_id,ipaddr_net,udp_port,tcp_port,version,udp_key from nodes";
	int error_code = sqlite3_get_table(db,sql.c_str(),&result,&nrow,&ncolumn,&errMsg);
	if(error_code != SQLITE_OK)
	{
		DEBUG_PRINT3("load table nodes failed  error code:%d, detailed reasion:%s\n",error_code,errMsg);
		return nodes;
	}

	DEBUG_PRINT3("Reading KadNodes datafile with %d rows and %d columns",nrow,ncolumn);
	for(int i=1;i<=nrow;i++)
	{
		char* kad_id = result[i*ncolumn];
		char* ipaddr_net = result[i*ncolumn+1];
		char* udp_port_str = result[i*ncolumn+2];
		char* tcp_port_str = result[i*ncolumn+3];
		char* version_str = result[i*ncolumn+4];
		char* udp_key_string = result[i*ncolumn+5];

		unsigned short udp_port = (unsigned short)atol(udp_port_str);
		unsigned short tcp_port = (unsigned short)atol(tcp_port_str);

		unsigned int version = atoi(version_str);

		CUInt128 node_id;
		node_id.FromHexString(kad_id);

		KadUDPKey udp_key;
		udp_key.fromInt64String(udp_key_string);
		KadNode target_node(node_id,inet_addr(ipaddr_net),udp_port,tcp_port,KadUtil::kad_id,version,udp_key,true);
		nodes.push_back(target_node);
	}

	return nodes;
}
bool DatabaseLogger::DeleteTableData(string table_name)
{
	string delete_table_sql="delete from ";
	delete_table_sql.append(table_name);
	char* errmsg = NULL;
	int result = sqlite3_exec(db,delete_table_sql.c_str(),NULL,NULL,&errmsg);
	if(result != SQLITE_OK)
	{
		DEBUG_PRINT3("delete table nodes failed  error code:%d, detailed reasion:%s\n",result,errmsg);
		return false;
	}
	return true;
}
bool DatabaseLogger::DeleteAllData()
{
	DeleteTableData("nodes");
	char* errmsg = NULL;
	string reset_table_index_sql = "update sqlite_sequence SET seq=0 where name='nodes'";
	int result = sqlite3_exec(db,reset_table_index_sql.c_str(),NULL,NULL,&errmsg);
	if(result != SQLITE_OK)
	{
		DEBUG_PRINT3("reset table nodes autoincrement index failed  error code:%d, detailed reasion:%s\n",result,errmsg);
		return false;
	}
	return true;
}

void DatabaseLogger::destroy()
{
	sqlite3_close(db);
}

