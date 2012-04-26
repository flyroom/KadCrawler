#pragma once

enum _LOG_LEVEL
{
    DEBUG_KAD_LOG,
	INFO_KAD_LOG,
	WARN_KAD_LOG,
	CRITICAL_KAD_LOG,
	FATAL_KAD_LOG
};
enum _LOG_OUTPUT
{
    FILE_STANDARD_OUTPUT=0,
    CONSOLE_OUTPUT,
    FILE_UTF8_OUTPUT
};

class KadLogger
{
public:
	KadLogger(void);
	~KadLogger(void);

	static void init();
	static void init(_LOG_LEVEL level,string path);
    static void init(_LOG_LEVEL level,_LOG_OUTPUT output_style,string path);
    static void setOutputStyle(_LOG_OUTPUT output_style_para);
	static void Log(_LOG_LEVEL level,string log);

	static bool logPermitted;
	static string logPath;
	static ofstream fs;
	static _LOG_LEVEL currentLevel;
    static _LOG_OUTPUT output_style;
};
