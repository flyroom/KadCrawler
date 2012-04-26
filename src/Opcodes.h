// UDP Server Port
#define UDP_SERVER_PORT 55586

// maximum number of nodes in one leaf node
#define  K	8000

// maximum path index of leaf node
#define KK   5

// Maximum depth of tree
#define KBASE 4

// KADEMLIA (opcodes) (udp)
#define KADEMLIA_BOOTSTRAP_REQ_DEPRECATED			0x00	// <PEER (sender) [25]>
#define KADEMLIA2_BOOTSTRAP_REQ			0x01	//

#define KADEMLIA_BOOTSTRAP_RES_DEPRECATED			0x08	// <CNT [2]> <PEER [25]>*(CNT)
#define KADEMLIA2_BOOTSTRAP_RES			0x09	//

#define KADEMLIA_HELLO_REQ	 			0x10	// <PEER (sender) [25]>
#define KADEMLIA2_HELLO_REQ				0x11	//

#define KADEMLIA_HELLO_RES     			0x18	// <PEER (receiver) [25]>
#define KADEMLIA2_HELLO_RES				0x19	//

#define KADEMLIA_REQ		   			0x20	// <TYPE [1]> <HASH (target) [16]> <HASH (receiver) 16>
#define KADEMLIA2_REQ					0x21	//

#define KADEMLIA2_HELLO_RES_ACK			0x22	// <NodeID><uint8 tags>

#define KADEMLIA_RES					0x28	// <HASH (target) [16]> <CNT> <PEER [25]>*(CNT)
#define KADEMLIA2_RES					0x29	//

#define KADEMLIA_SEARCH_REQ				0x30	// <HASH (key) [16]> <ext 0/1 [1]> <SEARCH_TREE>[ext]
//#define UNUSED						0x31	// Old Opcode, don't use.
#define KADEMLIA_SEARCH_NOTES_REQ		0x32	// <HASH (key) [16]>
#define KADEMLIA2_SEARCH_KEY_REQ		0x33	//
#define KADEMLIA2_SEARCH_SOURCE_REQ		0x34	//
#define KADEMLIA2_SEARCH_NOTES_REQ		0x35	//

#define KADEMLIA_SEARCH_RES				0x38	// <HASH (key) [16]> <CNT1 [2]> (<HASH (answer) [16]> <CNT2 [2]> <META>*(CNT2))*(CNT1)
//#define UNUSED						0x39	// Old Opcode, don't use.
#define KADEMLIA_SEARCH_NOTES_RES		0x3A	// <HASH (key) [16]> <CNT1 [2]> (<HASH (answer) [16]> <CNT2 [2]> <META>*(CNT2))*(CNT1)
#define KADEMLIA2_SEARCH_RES			0x3B	//

#define KADEMLIA_PUBLISH_REQ			0x40	// <HASH (key) [16]> <CNT1 [2]> (<HASH (target) [16]> <CNT2 [2]> <META>*(CNT2))*(CNT1)
//#define UNUSED						0x41	// Old Opcode, don't use.
#define KADEMLIA_PUBLISH_NOTES_REQ		0x42	// <HASH (key) [16]> <HASH (target) [16]> <CNT2 [2]> <META>*(CNT2))*(CNT1)
#define	KADEMLIA2_PUBLISH_KEY_REQ		0x43	//
#define	KADEMLIA2_PUBLISH_SOURCE_REQ	0x44	//
#define KADEMLIA2_PUBLISH_NOTES_REQ		0x45	//

#define KADEMLIA_PUBLISH_RES			0x48	// <HASH (key) [16]>
//#define UNUSED						0x49	// Old Opcode, don't use.
#define KADEMLIA_PUBLISH_NOTES_RES		0x4A	// <HASH (key) [16]>
#define	KADEMLIA2_PUBLISH_RES			0x4B	//
#define	KADEMLIA2_PUBLISH_RES_ACK		0x4C	// null

#define KADEMLIA_FIREWALLED_REQ			0x50	// <TCPPORT (sender) [2]>
#define KADEMLIA_FINDBUDDY_REQ			0x51	// <TCPPORT (sender) [2]>
#define KADEMLIA_CALLBACK_REQ			0x52	// <TCPPORT (sender) [2]>
#define KADEMLIA_FIREWALLED2_REQ		0x53	// <TCPPORT (sender) [2]><userhash><connectoptions 1>

#define KADEMLIA_FIREWALLED_RES			0x58	// <IP (sender) [4]>
#define KADEMLIA_FIREWALLED_ACK_RES		0x59	// (null)
#define KADEMLIA_FINDBUDDY_RES			0x5A	// <TCPPORT (sender) [2]>

#define KADEMLIA2_PING					0x60	// (null)
#define KADEMLIA2_PONG					0x61	// (null)

#define KADEMLIA2_FIREWALLUDP			0x62	// <errorcode [1]><UDPPort_Used [2]>

// KADEMLIA (parameter)
#define KADEMLIA_FIND_VALUE				0x02
#define KADEMLIA_STORE					0x04
#define KADEMLIA_FIND_NODE				0x0B


#define UDP_KAD_MAXFRAGMENT		1420		// based on a 1500 ethernet MTU, use a conservative value to leave enough room for IP/UDP headers, tunnel headers, Kad headers(16) and misconfigs 
#define	MAXFRAGSIZE				1300 //Xman avoid the silly window syndrome
#define EMBLOCKSIZE				184320
#define OP_EDONKEYHEADER		0xE3
#define OP_KADEMLIAHEADER		0xE4
#define OP_KADEMLIAPACKEDPROT	0xE5
#define OP_EDONKEYPROT			OP_EDONKEYHEADER
#define OP_PACKEDPROT			0xD4
#define OP_EMULEPROT			0xC5
#define OP_UDPRESERVEDPROT1		0xA3	// reserved for later UDP headers (important for EncryptedDatagramSocket)
#define OP_UDPRESERVEDPROT2		0xB2	// reserved for later UDP headers (important for EncryptedDatagramSocket)
#define OP_MLDONKEYPROT			0x00


#define TAGTYPE_HASH			0x01
#define TAGTYPE_STRING			0x02
#define TAGTYPE_UINT32			0x03
#define TAGTYPE_FLOAT32			0x04
#define TAGTYPE_BOOL			0x05
#define TAGTYPE_BOOLARRAY		0x06
#define TAGTYPE_BLOB			0x07
#define TAGTYPE_UINT16			0x08
#define TAGTYPE_UINT8			0x09
#define TAGTYPE_BSOB			0x0A
#define TAGTYPE_UINT64			0x0B

#define TAG_FILENAME			"\x01"
#define TAG_FILESIZE			"\x02"
#define TAG_FILETYPE			"\x03"
#define TAG_FILEFORMAT			"\x04"
#define TAG_MEDIA_ARTIST		"\xD0"
#define TAG_MEDIA_ALBUM			"\xD1"
#define TAG_MEDIA_TITLE			"\xD2"
#define TAG_MEDIA_LENGTH		"\xD3"
#define TAG_MEDIA_BITRATE		"\xD4"
#define TAG_MEDIA_CODEC			"\xD5"
#define TAG_SOURCES				"\x15"
#define TAG_PUBLISHINFO			"\x33"

#define TAG_ENCRYPTION			"\xF3"
#define TAG_BUDDYHASH			"\xF8"
#define TAG_SERVERPORT			"\xFA"
#define TAG_SERVERIP			"\xFB"
#define TAG_SOURCEUPORT		    "\xFC"
#define TAG_SOURCEPORT			"\xFD"
#define TAG_SOURCEIP			"\xFE"
#define TAG_SOURCETYPE			"\xFF"

#define TAG_KADMISCOPTIONS		"\xF2"

#define EDONKEYVERSION			 0x01
#define KADEMLIA_VERSION1_46c	 0x01
#define KADEMLIA_VERSION2_47a	 0x02
#define KADEMLIA_VERSION3_47b	 0x03
#define KADEMLIA_VERSION5_48a	 0x05
#define KADEMLIA_VERSION6_49aBETA 0x06
#define KADEMLIA_VERSION7_49a	 0x07
#define KADEMLIA_VERSION8_49b	 0x08
#define KADEMLIA_VERSION9_50a	 0x09

#define RSAKEYSIZE				384

//flag used when asking remote peer for file
#define CT_NAME					0x01
#define CT_PORT					0x0f
#define CT_VERSION				0x11
#define CT_SERVER_FLAGS			0x20
#define CT_MOD_VERSION			0x55
#define CT_EMULECOMPAT_OPTIONS1	0xef
#define CT_EMULE_UDPPORTS		0xf9
#define CT_EMULE_MISCOPTION1	0xfa
#define CT_EMULE_VERSION		0xfb
#define CT_EMULE_BUDDYIP		0xfc
#define CT_EMULE_BUDDYUDP		0xfd
#define CT_EMULE_MISCOPTION2	0xfe
#define CT_SERVER_UDPSEARCH_FLAGS	0x0E

// emule client <-> client
#define OP_HELLO				0x01
#define OP_SENDINGPART			0x46
#define OP_REQUESTPARTS			0x47
#define OP_FILEREQANSNOFIL		0x48
#define OP_END_OF_DOWNLOAD		0x49
#define OP_ASKSHAREDFILES		0x4A
#define OP_ASKSHAREDFILESANSWER  0x4B
#define OP_HELLOANSWER			0x4C
#define OP_CHANGE_CLIENT_ID		0x4D
#define OP_MESSAGE				0x4E
#define OP_SETREQFILEID			0x4F
#define OP_FILESTATUS			0x50
#define OP_HASHSETREQUEST		0x51
#define OP_HASHSETANSWER		0x52
#define OP_STARTUPLOADREQ		0x54
#define OP_ACCEPTUPLOADREQ		0x55
#define OP_CANCELTRANSFER		0x56
#define OP_OUTOFPARTREQS		0x57
#define OP_REQUESTFILENAME		0x58
#define OP_REQFILENAMEANSWER	0x59
#define OP_CHANGE_SLOT			0x5B
#define OP_QUEUERANK			0x5C
#define OP_ASKSHAREDDIRS		0x5D
#define OP_ASKSHAREDFILESDIR	0x5E
#define OP_ASKSHAREDDIRSANS		0x5F
#define OP_ASKSHAREDFILESDIRANS	0x60
#define OP_ASKSHAREDDENIEDANS	0x61

// extend prot client <-> extend prot client
#define OP_EMULEINFO			0x01
#define OP_EMULEINFOANSWER		0x02
#define OP_COMPRESSEDPART		0x40
#define OP_QUEUERANKING			0x60
#define OP_FILEDESC				0x61
#define OP_REQUESTSOURCES		0x81
#define OP_ANSWERSOURCES		0x82
#define OP_REQUESTSOURCES2		0x83
#define OP_ANSWERSOURCES2		0x84
#define OP_PUBLICKEY			0x85
#define OP_SIGNATURE			0x86
#define OP_SECIDENTSTATE		0x87
#define OP_REQUESTPREVIEW		0x90
#define OP_PREVIEWANSWER		0x91
#define OP_MULTIPACKET			0x92
#define OP_COMPRESSEDPART_I64   0xA1
#define OP_SENDINGPART_I64		0xA2
#define OP_REQUESTPARTS_I64		0xA3

// emule tagnames
#define ET_COMPRESSION	0x20
#define ET_UDPPORT		0x21
#define ET_UDPVER		0x22
#define ET_SOURCEEXCHANGE	0x23
#define ET_COMMENTS		0x24
#define ET_EXTENDEDREQUEST	0x25
#define ET_COMPATIBLECLIENT	0x26
#define ET_FEATURES		0x27
#define ET_MOD_VERSION	CT_MOD_VERSION

#define MOD_VERSION "Xtreme 8.1"

#define MOD_MAIN_VER	8
#define MOD_MIN_VER		1
#define MOD_BUILD_VER	1

enum _EClientSoftware{
	SO_EMULE = 0,
	SO_CDONKEY = 1,
	SO_XMULE = 2,
	SO_AMULE = 3,
	SO_SHAREAZA = 4,
	SO_MLDONKEY = 10,
	SO_LPHANT = 20,
	SO_EDONKEYHYBRID = 50,
	SO_EDONKEY,
	SO_OLDEMULE,
	SO_URL,
	SO_UNKNOWN
};

enum _ESecureIdentState
{
	IS_UNAVAILABLE = 0,
	IS_ALLREQUESTSSEND = 0,
	IS_SIGNATURENEEDED = 1,
	IS_KEYANDSIGNEEDED = 2,
};

enum _EConnectingState
{
	CCS_NONE = 0,
	CCS_DIRECTTCP,
	CCS_DIRECTCALLBACK,
	CCS_KADCALLBACK,
	CCS_SERVERCALLBACK,
	CCS_PRECONDITIONS
};

enum _EIdentState{
	IS_NOTAVAILABLE,
	IS_IDNEEDED,
	IS_IDENTIFIED,
	IS_IDFAILED,
	IS_IDBADGUY,
};

enum _EInfoPacketState
{
	IP_NONE = 0,
	IP_EDONKEYPROTPACK = 1,
	IP_EMULEPROTPACK = 2,
	IP_BOTH	= 3,
};
