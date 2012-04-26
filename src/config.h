#ifndef CONFIG_H
#define CONFIG_H
#ifdef WIN32
#pragma optimize("gsy", on)					// Global optimization, Short sequences, Frame pointers.
#pragma comment(linker, "/ALIGN:4096")		// This will save you some size on the executable.
#pragma warning(disable:4996)
#pragma warning(disable:4786)
#pragma warning(disable:4244)
#endif
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#define USE_BOOST_ASIO
#define DEBUG
// compatible with the legacy boost library in the shit ubuntu server
#define BOOST_FILESYSTEM_VERSION 2

#ifdef WIN32
#ifdef _DEBUG
#pragma comment (lib,"cryptlibd.lib")
#pragma comment (lib,"sqlite3d.lib")
#pragma comment (lib,"zlibd.lib")
#pragma comment (lib,"GeoIP_mtd.lib")
#else
#pragma comment (lib,"cryptlib.lib")
#pragma comment (lib,"zlib.lib")
#pragma comment (lib,"sqlite3.lib")
#pragma comment (lib,"GeoIP_mt.lib")
#endif
#endif

#include <stdio.h>
#include <string.h>
#ifndef USE_BOOST_ASIO
#include <winsock2.h>
#include <winInet.h>
#include <windows.h>
#endif
#include <fstream>
#include <iostream>
#include <list>
#include <hash_map>
#include <sstream>
#include <utility>
#include <algorithm>
#include <boost/array.hpp>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/regex.hpp>
#include <boost/asio.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/date_time/gregorian/gregorian.hpp>
#include <boost/date_time/posix_time/posix_time_io.hpp>
#include <boost/graph/graph_traits.hpp>
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/dijkstra_shortest_paths.hpp>
#include <boost/graph/graph_utility.hpp>
#include <boost/graph/graphviz.hpp>
#include <boost/thread/thread.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/condition.hpp>
#include <boost/thread/condition_variable.hpp>
#include <boost/thread/xtime.hpp>
#include <boost/thread/locks.hpp>
#include <boost/program_options.hpp>
#include <boost/program_options/config.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/detail/config_file.hpp>
#include <boost/filesystem.hpp>
#include <boost/random/uniform_int.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/variate_generator.hpp>
#include <boost/exception/all.hpp>
#include <boost/exception/get_error_info.hpp>
#include <boost/unordered_map.hpp>
#include <boost/interprocess/sync/interprocess_semaphore.hpp>
#include <boost/interprocess/shared_memory_object.hpp>
#include <boost/interprocess/mapped_region.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/string.hpp>
#include <boost/serialization/list.hpp>
#include <boost/serialization/vector.hpp>
//#include <boost/log/trivial.hpp>
//#include <boost/log/sinks/text_file_backend.hpp>
#ifdef WIN32
#include <md5.h>
#include <md4.h>
#include <rsa.h>
#include <base64.h>
#include <osrng.h>
#include <secblock.h>
#include <files.h>
// bullshit latest ubuntu server does not have latest asio lib
#define BOOST_1_47
#else
#include <crypto++/md5.h>
#include <crypto++/md4.h>
#include <crypto++/rsa.h>
#include <crypto++/osrng.h>
#include <crypto++/base64.h>
#include <crypto++/osrng.h>
#include <crypto++/secblock.h>
#include <crypto++/files.h>
#endif
#include <assert.h>
#include <zlib.h>
#include <clocale>
#include <assert.h>
#include <GeoIP.h>
#ifdef WIN32
#include <conio.h>
#else
#define __stdcall
#endif
#include <time.h>
extern "C"
{
#include "sqlite3.h"
};

#ifdef _DEBUG
//#include<vld.h>
#endif

#ifdef _OPENMP
#include <omp.h>
#else
#define omp_get_thread_num() 0
#endif

// Cryptopp namespace 
using namespace CryptoPP;
using namespace Weak;
using namespace std;

//#include "..\CommonUtilLib\debugUtil.h"
#ifndef USE_BOOST_ASIO
#include "HighPerformanceUDPServer.h"
#endif
#include "QQIpInfo.h"
#include "OtherFunctions.h"
#include "KadLogger.h"
#include "Opcodes.h"
#include "UInt128.h"
#include "Tag.h"
#include "SafeMemFile.h"
#include "AsioUDPServer.h"
#include "AsioTCPServer.h"
#include "Packet.h"
#include "KadNode.h"
#include "RoutingBin.h"
#include "RoutingZone.h"
#include "KadSharedFile.h"
/*
#include "KadScanner.h"
#include "DatabaseLogger.h"
#include "KadCrawleManager.h"
*/
#ifdef DEBUG
#define DEBUG_PRINT1(arg1) printf(arg1)
#define DEBUG_PRINT2(arg1, arg2) printf(arg1, arg2)
#define DEBUG_PRINT3(arg1, arg2, arg3) printf(arg1, arg2, arg3)
#define DEBUG_PRINT4(arg1, arg2, arg3, arg4) printf(arg1, arg2, arg3, arg4)
#define DEBUG_PRINT5(arg1, arg2, arg3, arg4,arg5) printf(arg1, arg2, arg3, arg4,arg5)
#define DEBUG_PRINT6(arg1, arg2, arg3, arg4,arg5,arg6) printf(arg1, arg2, arg3, arg4,arg5,arg6)
#define DEBUG_PRINT7(arg1, arg2, arg3, arg4,arg5,arg6,arg7) printf(arg1, arg2, arg3, arg4,arg5,arg6,arg7)
#else
#define DEBUG_PRINT1(arg1)
#define DEBUG_PRINT2(arg1, arg2)
#define DEBUG_PRINT3(arg1, arg2, arg3) 
#define DEBUG_PRINT4(arg1, arg2, arg3, arg4) 
#define DEBUG_PRINT5(arg1, arg2, arg3, arg4,arg5)
#define DEBUG_PRINT6(arg1, arg2, arg3, arg4,arg5,arg6)
#define DEBUG_PRINT7(arg1, arg2, arg3, arg4,arg5,arg6,arg7)
#endif

#endif


