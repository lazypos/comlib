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
*	����:	���ҽ����Ƿ����
*	������	��ִ���ļ�ȫ·��
*	����ֵ��	�ɹ����ؽ���id, ʧ�ܷ���-1
*	����:	zcw 13-8-17
***************************************/
int			is_proncess_run(const std::string& fullpath);

/**************************************
*	����:	��������
*	������	������ȫ����
*	����ֵ��	�ɹ�����true, ʧ�ܷ���false
***************************************/
bool		start_process(const std::string& cmdline);

/**************************************
*	����:	���Խ�������
*	������	����id, �ȴ�ʱ��
*	����ֵ��	�ɹ�����true, ʧ�ܷ���false
***************************************/
bool		stop_process(int pid, int wait_sec);

/**************************************
*	����:	��ȡ���������ڵ�ʱ������
*	����ֵ��	����������
***************************************/
int64_t		get_ticket();

/**************************************
*	����:	��ȡ��ǰ���̵�cpuռ����
*	����ֵ��	ռ���� ��21.1234
***************************************/
double		get_cpu_usage();

/**************************************
*	����:	��ȡ���Ե�����mac��ip
*	������	��¼mac������Ӧ��ip��map�ṹ
*	����ֵ��	�ɹ�����true, ʧ�ܷ���false
***************************************/
typedef std::map< std::string, std::vector<std::string> >		MAP_MAC_IP_INFO;
bool		get_mac_ip_info(MAP_MAC_IP_INFO& macip_info);

#endif