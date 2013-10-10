#ifndef H_PROCESS_DEAL_H
#define H_PROCESS_DEAL_H
#include <string>
#include <map>
#include <vector>
#include <string.h>
#include <stdlib.h>

#ifndef	__LINUX__
typedef __int64	int64_t;
#else
#endif

/**************************************
*	功能:	查找进程是否存在
*	参数：	可执行文件全路径
*	返回值：	成功返回进程id, 失败返回-1
*	作者:	zcw 13-8-17
***************************************/
int			is_proncess_run(const std::string& fullpath);

/**************************************
*	功能:	启动进程
*	参数：	命令行全命令
*	返回值：	成功返回true, 失败返回false
***************************************/
bool		start_process(const std::string& cmdline);

/**************************************
*	功能:	尝试结束进程
*	参数：	进程id, 等待时间
*	返回值：	成功返回true, 失败返回false
***************************************/
bool		stop_process(int pid, int wait_sec);

/**************************************
*	功能:	获取开机到现在的时钟周期
*	返回值：	返回纳秒数
***************************************/
int64_t		get_ticket();

/**************************************
*	功能:	获取当前进程的cpu占用率
*	返回值：	占用率 例21.1234
***************************************/
double		get_cpu_usage();

/**************************************
*	功能:	获取电脑的所有mac和ip
*	参数：	记录mac和所对应的ip的map结构
*	返回值：	成功返回true, 失败返回false
***************************************/
typedef std::map< std::string, std::vector<std::string> >		MAP_MAC_IP_INFO;
bool		get_mac_ip_info(MAP_MAC_IP_INFO& macip_info);

#endif