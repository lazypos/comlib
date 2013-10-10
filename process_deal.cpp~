#include "process_deal.h"
#ifndef __LINUX__
#include <Windows.h>
#include <Tlhelp32.h>
#include <IPHlpApi.h>
#include <Psapi.h>
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "IPHLPAPI.lib")
#else
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <signal.h>
#include <time.h>
#include <stdio.h>
#endif
using namespace std;

int is_proncess_run( const std::string& propath )
{
	int rst = -1;

#ifndef __LINUX__

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32);
	HANDLE hProcessSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0); // 创建进程快照
	if(hProcessSnap == INVALID_HANDLE_VALUE)
		return false;

	char fullpath[4096];
	BOOL bMore = ::Process32First(hProcessSnap,&pe32);
	while(bMore) // 遍历进程
	{
		HANDLE hp = ::OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
		if (hp)
		{
			ZeroMemory(fullpath, 4096);
			::GetModuleFileNameEx(hp, NULL, fullpath, 4096); // 获取全路径
			::CloseHandle(hp);
			if (_stricmp(fullpath, propath.c_str()) == 0) // 比较找到进程
			{
				rst = pe32.th32ProcessID;
				break;
			}
		}
		bMore = ::Process32Next(hProcessSnap, &pe32);
	}
	::CloseHandle(hProcessSnap);

#else

	DIR *dp = opendir("/proc");
	struct dirent *dirp;
	if(dp != NULL)
	{
		while ((dirp = readdir(dp))!= NULL)	// 遍历文件
		{
			if (strcmp(dirp->d_name, ".") == 0 
				|| strcmp(dirp->d_name, "..") == 0)
				continue;

			std::string fullpath("/proc/");	// 获取文件状态
			fullpath += dirp->d_name;

			struct stat fstat;
			if (lstat(fullpath.c_str(), &fstat) < 0)
				continue;

			char pathbuf[1024];
			if (S_ISDIR(fstat.st_mode))		// 如果是文件夹
			{
				memset(pathbuf, 0, 1024);
				int slt = readlink(std::string(fullpath + "/exe").c_str(), pathbuf, 1024);
				if (slt < 0)
					continue;
				pathbuf[slt] = '\0';

				if (strcasecmp(pathbuf, propath.c_str()) == 0) // 匹配到路径
				{
					rst = atoi(dirp->d_name);
					break;
				}
			}			
		}
		closedir(dp);
	}

#endif
	return rst;
}

bool start_process( const std::string& cmdline )
{
	bool rst = false;

#ifndef	__LINUX__

	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));

	si.cb = sizeof (si);	// 设置启动属性
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOWNORMAL;

	if (::CreateProcess(	// 创建进程
		NULL, (char*)cmdline.c_str(), NULL, NULL, false, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
	{
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		rst = true;
	}

#else

	pid_t pid = fork();
	if (pid < 0)
		rst = false;
	else if (pid == 0) // 子进程创建孙进程马上退出
	{
		// 忽略孙进程退出状态，防止孙进程执行execl失败先退出导致僵尸进程
		signal(SIGCHLD, SIG_IGN); 
		pid_t ppid = fork();
		if (ppid == 0)
			execl("/bin/sh", "sh", "-c", cmdline.c_str(), NULL);
	}
	else
	{
		waitpid(pid, NULL, 0);	// 等待子进程退出
		return rst;				// 父进程返回，其余退出
	}

#endif
	
	return 0;
}

bool stop_process( int pid, int wait_sec )
{
	bool result = true;
	int	 waittime = 5;

#ifndef __LINUX__

	HANDLE hdProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid); // 打开进程
	if (hdProc != INVALID_HANDLE_VALUE)
		TerminateProcess(hdProc,EXIT_FAILURE);	// 结束进程

	if (::WaitForSingleObject(hdProc, waittime*1000) == WAIT_TIMEOUT) // 等待进程结束
		result = false;
	::CloseHandle(hdProc);

#else

	kill(pid, SIGTERM);		// 向进程发结束信号
	while (waittime>0)
	{
		if (waitpid(pid, NULL, WNOHANG) > 0) // 正常退出
			break;

		waittime--;	// 继续等待
		sleep(1);
	}
	if (waittime <= 0) // 等待超时
		result = false;

#endif
	return result;
}

int64_t get_ticket()
{
	int64_t ticket_counts = 0;
#ifndef	__LINUX__
	ticket_counts = GetTickCount()*1000;
#else
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	ticket_counts = ts.tv_sec*1000000000+ts.tv_nsec;
#endif
	return ticket_counts;
}

#ifndef	__LINUX__

int get_process_counts()
{
	SYSTEM_INFO info;
	GetSystemInfo(&info);
	return (int)info.dwNumberOfProcessors;
}
__int64 filetime2int64(const FILETIME& time)
{
	ULARGE_INTEGER tt;
	tt.LowPart = time.dwLowDateTime;
	tt.HighPart = time.dwHighDateTime;
	return tt.QuadPart;
}
bool    get_time_info(__int64& systime, __int64& nowtime)
{
	systime = 0;
	nowtime = 0;
	bool rst = false;
	FILETIME createtime;
	FILETIME exittime;
	FILETIME kerneltime;
	FILETIME usertime;
	if (GetProcessTimes(GetCurrentProcess(), &createtime, &exittime, &kerneltime, &usertime))
	{
		FILETIME now;
		GetSystemTimeAsFileTime(&now);
		systime    = filetime2int64(kerneltime) + filetime2int64(usertime);
		nowtime    = filetime2int64(now);
		rst = true;
	}
	return rst;
}

#else

bool	get_time_info(int64_t& systime, int64_t& nowtime)
{	
	struct rusage rus;
	if (getrusage(RUSAGE_SELF, &rus) == 0)
	{
		int64_t use_time = rus.ru_utime.tv_sec*1.0e9 + rus.ru_utime.tv_usec*1.0e3; // 用户态所用时间
		int64_t sys_time = rus.ru_stime.tv_sec*1.0e9 + rus.ru_stime.tv_usec*1.0e3; // 系统态所用时间
		systime = use_time + sys_time;  // 记录当前总时间
		nowtime = get_ticket();		// 记录当前时间
		return true;
	}
	return false;
}

#endif

double get_cpu_usage()
{
	double cpu = 0;
#ifndef	__LINUX__
	static int processor_count_ = get_process_counts();
	__int64 systime = 0, nowtime = 0;
	if (get_time_info(systime, nowtime))
	{
		Sleep(1000);
		__int64 systime2 = 0, nowtime2 = 0;
		if (get_time_info(systime2, nowtime2))
		{
			cpu = ((double)(systime2 - systime) / (double)(nowtime2 - nowtime)) * (100/processor_count_); 
		}
	}
#else
	static int cpu_count = sysconf(_SC_NPROCESSORS_CONF); // cpu core number
	int64_t systime=0, nowtime=0;	
	if (get_time_info(systime, nowtime)) // 记录上一次运行的状态
	{
		sleep(1);		// 间隔一秒
		int64_t systime2=0, nowtime2=0;
		if (get_time_info(systime2, nowtime2)) // 获得现在的状态
		{
			cpu = ((double)(systime2-systime)/(double)(nowtime2-nowtime))*(100/cpu_count); // 计算出cpu使用率
			return cpu;
		}
	}
#endif
	return cpu;
}

bool get_mac_ip_info( MAP_MAC_IP_INFO& macip_info )
{
	bool rst = true;
#ifndef	__LINUX__
	DWORD ulbuflen = sizeof(PIP_ADAPTER_INFO);
	PIP_ADAPTER_INFO paddress = (IP_ADAPTER_INFO*)malloc(ulbuflen);
	if (paddress)
	{	
		if (GetAdaptersInfo(paddress, &ulbuflen) == ERROR_BUFFER_OVERFLOW) // 申请空间不够
		{
			free(paddress);
			paddress = (IP_ADAPTER_INFO*)malloc(ulbuflen);
		}

		if (paddress)
		{
			PIP_ADAPTER_INFO ptmp = 0;
			if (GetAdaptersInfo(paddress, &ulbuflen) == NO_ERROR) // 获取设备信息
			{
				ptmp = paddress;
				while(ptmp)	// 遍历设备
				{
					if (ptmp->Type == MIB_IF_TYPE_ETHERNET)  // 是以太网
					{
						PIP_ADDR_STRING pIPList = &ptmp->IpAddressList;
						if (pIPList)
						{
							char szMacStr[50] = {0}; // 获取MAC
							sprintf(szMacStr,"%.2X%.2X%.2X%.2X%.2X%.2X",
								ptmp->Address[0],ptmp->Address[1],
								ptmp->Address[2],ptmp->Address[3],
								ptmp->Address[4],ptmp->Address[5]);
							
							string strMAC(szMacStr);
							if (!strMAC.empty() && strMAC != "000000000000")
							{
								std::vector<string> lst_ip;
								for(int i=0; pIPList != NULL; i++)	// 获取该MAC的ip
								{
									string strIP = string((char*)&pIPList->IpAddress);
									if(!strIP.empty() && strIP != "0.0.0.0" && strIP != "127.0.0.1")
										lst_ip.push_back(strIP);
									pIPList = pIPList->Next;
								}
								macip_info.insert(make_pair(strMAC, lst_ip));
							}
						}
					}
					ptmp = ptmp->Next;
				}
			}
		}
		free(paddress);
	}
#else
	struct ifreq ifrbuf[16];
	struct ifconf ifc;
	int fd = socket(AF_INET, SOCK_STREAM, 0); 
	if (fd != -1)
	{
		ifc.ifc_len = sizeof(ifrbuf);
		ifc.ifc_buf = (caddr_t)ifrbuf;
		if (!ioctl(fd, SIOCGIFCONF, (char*)&ifc)) // 获取套接字状态
		{
			int n = ifc.ifc_len / sizeof(struct ifreq);
			for (int i=0; i<n; i++)		// 遍历设备
			{
// 				if (!ioctl(fd, SIOCGIFFLAGS, (char*)&ifrbuf[i])) // 获取状态
// 				{
// 					if (ifrbuf[i].ifr_flags & IFF_UP) // 如果是启用状态
// 					{
// 									
// 					}
// 				}

				if (!ioctl(fd, SIOCGIFHWADDR, (char*)&ifrbuf[i])) // 获取mac
				{
					char szMacStr[32];
					memset(szMacStr, 0, 32);
					sprintf(szMacStr,"%.2X%.2X%.2X%.2X%.2X%.2X",
						(unsigned char)ifrbuf[i].ifr_hwaddr.sa_data[0],
						(unsigned char)ifrbuf[i].ifr_hwaddr.sa_data[1],
						(unsigned char)ifrbuf[i].ifr_hwaddr.sa_data[2],
						(unsigned char)ifrbuf[i].ifr_hwaddr.sa_data[3],
						(unsigned char)ifrbuf[i].ifr_hwaddr.sa_data[4],
						(unsigned char)ifrbuf[i].ifr_hwaddr.sa_data[5]);

					std::string strmac(szMacStr);
					if (!strmac.empty() && strmac != "000000000000")
					{
						if (!ioctl(fd, SIOCGIFADDR, (char*)&ifrbuf[i])) // 获取ip
						{
							std::vector<std::string> lst_ip;
							std::string strip(inet_ntoa(((struct sockaddr_in*)(&ifrbuf[i].ifr_addr))->sin_addr));
							if(!strip.empty() && strip != "127.0.0.1" && strip != "0.0.0.0")
								lst_ip.push_back(strip);
						}		
					}
				}
			}
		}
		close(fd);
	}
#endif
	return rst;
}

int main()
{return 0;}
