/*
* Tencent is pleased to support the open source community by making Libco available.

* Copyright (C) 2014 THL A29 Limited, a Tencent company. All rights reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License"); 
* you may not use this file except in compliance with the License. 
* You may obtain a copy of the License at
*
*	http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, 
* software distributed under the License is distributed on an "AS IS" BASIS, 
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
* See the License for the specific language governing permissions and 
* limitations under the License.
*/

#include "co_routine.h"

#include <errno.h>
#include <string.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <stack>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string>
#include <iostream>

using namespace std;
struct SEndPoint
{
	string sIp;
	uint16_t port;
};

static void SetAddr(const char *pszIP,const unsigned short shPort,struct sockaddr_in &addr)
{
	bzero(&addr,sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(shPort);
	int nIP = 0;
	if( !pszIP || '\0' == *pszIP   
			|| 0 == strcmp(pszIP,"0") || 0 == strcmp(pszIP,"0.0.0.0") 
			|| 0 == strcmp(pszIP,"*") 
	  )
	{
		nIP = htonl(INADDR_ANY);
	}
	else
	{
		nIP = inet_addr(pszIP);
	}
	addr.sin_addr.s_addr = nIP;

}

static void *readwrite_routine( void *arg )
{
	co_enable_hook_sys();

	SEndPoint *endpoint = (SEndPoint *)arg;
	int fd = 0;
	int ret = 0;

	fd = socket(AF_INET , SOCK_STREAM, 0);

	struct timeval timeout={1,0};
	ret = setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,(const char*)&timeout,sizeof(timeout));

	if(ret < 0)
	{
		printf("setsockopt fail fd:%d\n",fd);
		close(fd);
		return 0;
	}

	struct sockaddr_in addr;
	SetAddr(endpoint->sIp.c_str(), endpoint->port, addr);
	ret = connect(fd,(struct sockaddr*)&addr,sizeof(addr));

	printf("connect fd:%d\n",fd);
				
	if ( errno == EALREADY || errno == EINPROGRESS )
	{   
		printf("fd:%d,connecting\n",fd);
		struct pollfd pf = { 0 };
		pf.fd = fd;
		pf.events = (POLLOUT|POLLERR|POLLHUP);
		ret = co_poll( co_get_epoll_ct(),&pf,1,2000);

		if(ret <= 0)
		{
			printf("connect timeout fd:%d\n", fd);
			close(fd);
			return 0;
		}

		int error = 0;
		uint32_t socklen = sizeof(error);
		ret = getsockopt(fd, SOL_SOCKET, SO_ERROR,(void *)&error,  &socklen);
		
		if ( ret < 0 ) 
		{       
			printf("getsockopt ERROR ret %d %d:%s\n", ret, errno, strerror(errno));
			close(fd);
			return 0;
		}     

		if ( error ) 
		{       
			errno = error;
			printf("connect ERROR ret %d %d:%s\n", error, errno, strerror(errno));
			close(fd);
			return 0;
		}       
	} 
	else
	{
		printf("connect ERROR ret %d:%s\n",  errno, strerror(errno));
		close(fd);
		return 0;
	}

	string sRequest;
	sRequest = "GET http://www.baidu.com/ HTTP/1.1\r\n";
	sRequest+="Accept: text/html, application/xhtml+xml, */*\r\n";
	sRequest+="Accept-Language: zh-CN\r\n";
	sRequest+="Host: www.baidu.com\r\n";
	sRequest+="Connection: close\r\n\r\n";
	ret = write( fd,sRequest.data(), sRequest.size());

	if(ret < 0)
	{
		printf("co %p write ret %d errno %d (%s)\n",co_self(), ret,errno,strerror(errno));
		close(fd);
		return 0;
	}

	char szRecvBuf[8193];
	string sResp;

	while(ret> 0)
	{
		memset(szRecvBuf,0,sizeof(szRecvBuf));

		ret = read(fd,szRecvBuf,sizeof(szRecvBuf)-1);
		printf("recv data len:%d\n",ret);
		if(ret > 0)
		{
			sResp.append(szRecvBuf);
		}
	}

	printf("get data from fd:%d:\n%s\n",fd, sResp.c_str());
	close(fd);
	return 0;

}

int main(int argc,char *argv[])
{
	if(argc < 4)
	{
		cout<<"usage:"<<argv[0]<<" ip port cnt"<<endl;
		return 0;
	}
	SEndPoint endpoint;
	endpoint.sIp = argv[1];
	endpoint.port = atoi(argv[2]);
	int cnt = atoi( argv[3] );
	
	struct sigaction sa;
	sa.sa_handler = SIG_IGN;
	sigaction( SIGPIPE, &sa, NULL );
	

	for(int i=0;i<cnt;i++)
	{
		stCoRoutine_t *co = 0;
		co_create( &co,NULL,readwrite_routine, &endpoint);
		co_resume( co );
	}
	co_eventloop( co_get_epoll_ct(),0,0 );

	return 0;
}
/*./example_echosvr 127.0.0.1 10000 100 50*/
