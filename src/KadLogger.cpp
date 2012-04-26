#include "config.h"

bool KadLogger::logPermitted=false;
string KadLogger::logPath="./kadRun.log";
ofstream KadLogger::fs;
_LOG_LEVEL KadLogger::currentLevel = INFO_KAD_LOG;
_LOG_OUTPUT KadLogger::output_style = FILE_STANDARD_OUTPUT;

KadLogger::KadLogger(void)
{
}

KadLogger::~KadLogger(void)
{
	if(!fs.is_open())
		return;
	fs.close();
}

void KadLogger::init()
{
	if(fs.is_open())
		return;
	fs.open(logPath.c_str(),ios_base::out);
}

void KadLogger::init(_LOG_LEVEL level,string path)
{
	logPath = path;
	init();
}
void KadLogger::init(_LOG_LEVEL level,_LOG_OUTPUT output_style_para,string path)
{
	logPath = path;
    output_style = output_style_para;
	init();
}
void KadLogger::setOutputStyle(_LOG_OUTPUT output_style_para)
{
    output_style = output_style_para;
}
void KadLogger::Log(_LOG_LEVEL level,string log)
{
    if(level < currentLevel)
		return;
	std::ostringstream logStream;
    logStream<<getCurrentTimeString()<<" ";
	if(level == DEBUG_KAD_LOG)
		logStream<<"KadDebug: ";
    if(level == INFO_KAD_LOG)
		logStream<<"KadInfo: ";
	else if(level == WARN_KAD_LOG)
		logStream<<"KadWarn: ";
	else if(level == CRITICAL_KAD_LOG)
		logStream<<"KadCritical: ";
	else if(level == FATAL_KAD_LOG)
		logStream<<"KadFatal: ";
	logStream<<log<<endl;

    switch(output_style)
    {
    case CONSOLE_OUTPUT:
        cout<<logStream.str();
        break;
    case FILE_STANDARD_OUTPUT:
        fs.write(logStream.str().c_str(),logStream.str().size());
    	fs.flush();
        break;
    case FILE_UTF8_OUTPUT:
        string log_string = s2utfs(logStream.str());
        fs.write(log_string.c_str(),log_string.size());
        fs.flush();
        break;
    }
}
