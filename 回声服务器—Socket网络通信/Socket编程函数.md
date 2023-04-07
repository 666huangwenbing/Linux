#### Socket通信三要素

1）通信的目的地址——IP地址

2）使用的端口号——http 80 smtp 25

3）使用的传输层协议——TCP、UDP



#### Socket通信模型

![image-20230407174223699](C:\Users\Admin\AppData\Roaming\Typora\typora-user-images\image-20230407174223699.png)



#### 什么是套接字

Socket中文意思是“插座”，在Linux环境下，用于表示进程之间网络通信的特殊文件类型。本质为内核借助缓冲区形成的伪文件。

既然是文件，那么理所当然的，我们可以使用文件描述符引用套接字。Linux系统将其封装成文件的目的是为了统一接口，使得读写套接字和读写文件的操作一致。区别是文件主要应用于本地持久化数据的读写，而套接字多应用于网络进程间数据的传递。

在TCP/IP协议中，“IP地址+TCP或UDP端口号”唯一标识网络通讯中的一个进程。“IP地址+端口号”就对应一个socket。欲建立连接的两个进程各自有一个socket来标识，那么这两个socket组成的socket pair就唯一标识一个连接。因此可以用Socket来描述网络连接的一对一关系。

**套接字通信原理图**

![image-20230407174418420](C:\Users\Admin\AppData\Roaming\Typora\typora-user-images\image-20230407174418420.png)

在网络通信中，套接字一定是成对出现的。一端的发送缓冲区对应相对端的接收缓冲区。我们使用同一个文件描述符索发送缓冲区和接收缓冲区。



#### Socket通信创建流程图

![image-20230407174541772](C:\Users\Admin\AppData\Roaming\Typora\typora-user-images\image-20230407174541772.png)



**什么是网络字节序：**

在计算机世界里，有两种字节序：

  							大端字节序 - 低地址高字节,高地址低字节

  							小段字节序 - 低地址低字节,高地址高字节



内存中的多字节数据相对于内存地址有大端和小端之分，磁盘文件中的多字节数据相对于文件中的偏移地址也有大端小端之分。网络数据流同样有大端小端之分，那么如何定义网络数据流的地址呢？发送主机通常将发送缓冲区中的数据按内存地址从低到高的顺序发出，接收主机把从网络上接到的字节依次保存在接收缓冲区中，也是按内存地址从低到高的顺序保存，因此，网络数据流的地址应这样规定：先发出的数据是低地址，后发出的数据是高地址。

![image-20230407174724114](C:\Users\Admin\AppData\Roaming\Typora\typora-user-images\image-20230407174724114.png)

TCP/IP协议规定，网络数据流应采用大端字节序，即低地址高字节。

  			例如端口号是1001（0x3e9），由两个字节保存，采用大端字节序，则低地址是0x03，高地址是0xe9，也就是先发0x03，再发0xe9，这16位在发送主机的缓冲区中也应该是低地址存0x03，高地址存0xe9。但是，如果发送主机是小端字节序的，这16位被解释成0xe903，而不是1001。因此，发送主机把1001填到发送缓冲区之前需要做字节序的转换。同样地，接收主机如果是小端字节序的，接到16位的源端口号也要做字节序的转换。如果主机是大端字节序的，发送和接收都不需要做转换。同理，32位的IP地址也要考虑网络字节序和主机字节序的问题。



**网络字节序与主机字节序之间的转化：**

```
#include <arpa/inet.h>

uint32_t htonl(uint32_t hostlong);

uint16_t htons(uint16_t hostshort);

uint32_t ntohl(uint32_t netlong);

uint16_t ntohs(uint16_t netshort);
```

h表示host，n表示network，l表示32位长整数，s表示16位短整数。

如果主机是小端字节序，这些函数将参数做相应的大小端转换然后返回，如果主机是大端字节序，这些函数不做转换，将参数原封不动地返回。



**socketaddr数据结构**

很多网络编程函数诞生早于IPv4协议，那时候都使用的是sockaddr结构体,为了向前兼容，现在sockaddr退化成了（void *）的作用，传递一个地址给函数，至于这个函数是sockaddr_in还是其他的，由地址族确定，然后函数内部再强制类型转化为所需的地址类型。

IPV4—AF_INET

IPV6—AF_INET6

 

![image-20230407180858942](C:\Users\Admin\AppData\Roaming\Typora\typora-user-images\image-20230407180858942.png)

```
struct sockaddr {

​    sa_family_t sa_family;      /* address family, AF_xxx */

​    char sa_data[14];       /* 14 bytes of protocol address */

};

 

 struct sockaddr_in {

   sa_family_t  sin_family; /* address family: AF_INET */

   in_port_t   sin_port;  /* port in network byte order */

   struct **in_addr** **sin_addr**;  /* internet address */

 };

 

 /* Internet address. */

struct **in_addr** {

  uint32_t    s_addr;   /* address in network byte order */

};
```

IPv4的地址格式定义在netinet/in.h中，IPv4地址用sockaddr_in结构体表示，包括16位端口号和32位IP地址，但是sock API的实现早于ANSI C标准化，那时还没有void *类型，因此这些像bind 、accept函数的参数都用struct sockaddr *类型表示，在传递参数之前要强制类型转换一下，例如：

```
struct sockaddr_in servaddr;

bind(listen_fd, (struct sockaddr *)&servaddr, sizeof(servaddr));     /* initialize servaddr */
```





#### IP地址转化函数

![image-20230407175229901](C:\Users\Admin\AppData\Roaming\Typora\typora-user-images\image-20230407175229901.png)

```
	#include <arpa/inet.h>

    int **inet_pton**(int af, const char *src, void *dst);

    const char ***inet_ntop**(int af, const void *src, char *dst, socklen_t size);

    //af 取值可选为 AF_INET 和 AF_INET6 ，即和 ipv4 和ipv6对应

    //支持IPv4和IPv6
```

 

其中inet_pton和inet_ntop不仅可以转换IPv4的in_addr，还可以转换IPv6的in6_addr。



**示例：**

```
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

int main(void){

    char ip[]="2.3.4.5";
    char server_ip[64];

    struct sockaddr_in server_addr;

    inet_pton(AF_INET, ip, &server_addr.sin_addr.s_addr);//ip地址转化为整形

    printf("s_addr : %x\n", server_addr.sin_addr.s_addr);
    //网络字节序转为主机字节序
    printf("s_addr from net to host: %x\n", ntohl(server_addr.sin_addr.s_addr));
    //ip地址转为字符型
    inet_ntop(AF_INET, &server_addr.sin_addr.s_addr, server_ip, 64);

    printf("server ip : %s\n", server_ip);
    //INADDR_ANY = '0.0.0.0'
    printf("INADDR_ANY: %d\n", INADDR_ANY);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    inet_ntop(AF_INET, &server_addr.sin_addr.s_addr, server_ip, 64);
    printf("INADDR_ANY ip : %s\n", server_ip);
    return 0;
}

```





## Socket编程函数

#### socket函数

```
#include <sys/types.h>
#include <sys/socket.h>
int socket(int domain, int type, int protocol);
domain:
	AF_INET 这是大多数用来产生socket的协议，使用TCP或UDP来传输，用IPv4的地址
	AF_INET6 与上面类似，不过是来用IPv6的地址
	AF_UNIX 本地协议，使用在Unix和Linux系统上，一般都是当客户端和服务器在同一台及其上的时候使用
type:
	SOCK_STREAM 这个协议是按照顺序的、可靠的、数据完整的基于字节流的连接。这是一个使用最多的socket类型，这个socket是使用TCP来进行传输。
	SOCK_DGRAM 这个协议是无连接的、固定长度的传输调用。该协议是不可靠的，使用UDP来进行它的连接。
	SOCK_SEQPACKET该协议是双线路的、可靠的连接，发送固定长度的数据包进行传输。必须把这个包完整的接受才能进行读取。
	SOCK_RAW socket类型提供单一的网络访问，这个socket类型使用ICMP公共协议。（ping、traceroute使用该协议）
	SOCK_RDM 这个类型是很少使用的，在大部分的操作系统上没有实现，它是提供给数据链路层使用，不保证数据包的顺序
protocol:
	传0 表示使用默认协议。
返回值：
	成功：返回指向新创建的socket的文件描述符，失败：返回-1，设置errno
```

socket()打开一个网络通讯端口，如果成功的话，就像open()一样返回一个文件描述符，应用程序可以像读写文件一样用read/write在网络上收发数据，如果socket()调用出错则返回-1。对于IPv4，domain参数指定为AF_INET。对于TCP协议，type参数指定为SOCK_STREAM，表示面向流的传输协议。如果是UDP协议，则type参数指定为SOCK_DGRAM，表示面向数据报的传输协议。protocol参数的介绍从略，指定为0即可。





#### bind函数

```
#include <sys/types.h>
#include <sys/socket.h>
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
sockfd：
	socket文件描述符
addr:
	构造出IP地址加端口号
addrlen:
	sizeof(addr)长度
返回值：
	成功返回0，失败返回-1, 设置errno
```

服务器程序所监听的网络地址和端口号通常是固定不变的，客户端程序得知服务器程序的地址和端口号后就可以向服务器发起连接，因此服务器需要调用bind绑定一个固定的网络地址和端口号。

bind()的作用是将参数sockfd和addr绑定在一起，使sockfd这个用于网络通讯的文件描述符监听addr所描述的地址和端口号。前面讲过，struct sockaddr *是一个通用指针类型，addr参数实际上可以接受多种协议的sockaddr结构体，而它们的长度各不相同，所以需要第三个参数addrlen指定结构体的长度。如：

```
struct sockaddr_in servaddr;
bzero(&servaddr, sizeof(servaddr));//清零
servaddr.sin_family = AF_INET;
servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
servaddr.sin_port = htons(6666);
```

首先将整个结构体清零，然后设置地址类型为AF_INET，网络地址为INADDR_ANY，这个宏表示本地的任意IP地址，因为服务器可能有多个网卡，每个网卡也可能绑定多个IP地址，这样设置可以在所有的IP地址上监听，直到与某个客户端建立了连接时才确定下来到底用哪个IP地址，端口号为6666。



#### listen函数

```
#include <sys/types.h> 
#include <sys/socket.h>
int listen(int sockfd, int backlog);
sockfd:
	socket文件描述符
backlog:
	在Linux 系统中，它是指排队等待建立3次握手队列长度
```

查看系统默认backlog

```
cat /proc/sys/net/ipv4/tcp_max_syn_backlog
```

改变 系统限制的backlog 大小

```
vim /etc/sysctl.conf
```


 最后添加

```
net.core.somaxconn = 1024

net.ipv4.tcp_max_syn_backlog = 1024

保存，然后执行
sysctl -p
```


典型的服务器程序可以同时服务于多个客户端，当有客户端发起连接时，服务器调用的accept()返回并接受这个连接，如果有大量的客户端发起连接而服务器来不及处理，尚未accept的客户端就处于连接等待状态，listen()声明sockfd处于监听状态，并且最多允许有backlog个客户端处于连接待状态，如果接收到更多的连接请求就忽略。listen()成功返回0，失败返回-1。



#### accpet函数

```
#include <sys/types.h>
#include <sys/socket.h>
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
sockdf:
	socket文件描述符
addr:
	传出参数，返回链接客户端地址信息，含IP地址和端口号
addrlen:
	传入传出参数（值-结果）,传入sizeof(addr)大小，函数返回时返回真正接收到地址结构体的大小
返回值：
	成功返回一个新的socket文件描述符，用于和客户端通信，失败返回-1，设置errno

```

![image-20230407180323393](C:\Users\Admin\AppData\Roaming\Typora\typora-user-images\image-20230407180323393.png)

三次握手完成后，服务器调用accept()接受连接，如果服务器调用accept()时还没有客户端的连接请求，就阻塞等待直到有客户端连接上来。addr是一个传出参数，accept()返回时传出客户端的地址和端口号。addrlen参数是一个传入传出参数（value-result argument），传入的是调用者提供的缓冲区addr的长度以避免缓冲区溢出问题，传出的是客户端地址结构体的实际长度（有可能没有占满调用者提供的缓冲区）。如果给addr参数传NULL，表示不关心客户端的地址。

我们的服务器程序结构是这样的：

```
while (1) {

  cliaddr_len = sizeof(cliaddr);

  connfd = accept(listenfd, (struct sockaddr *)&cliaddr, &cliaddr_len);

  n = read(connfd, buf, MAXLINE);

  ......

  close(connfd);

}
```

整个是一个while死循环，每次循环处理一个客户端连接。由于cliaddr_len是传入传出参数，每次调用accept()之前应该重新赋初值。accept()的参数listenfd是先前的监听文件描述符，而accept()的返回值是另外一个文件描述符connfd，之后与客户端之间就通过这个connfd通讯，最后关闭connfd断开连接，而不关闭listenfd，再次回到循环开头listenfd仍然用作accept的参数。accept()成功返回一个文件描述符，出错返回-1。



#### connect函数

```
#include <sys/types.h> 

#include <sys/socket.h>

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

sockdf:

  socket文件描述符

addr:

  传入参数，指定服务器端地址信息，含IP地址和端口号

addrlen:

  传入参数,传入sizeof(addr)大小

返回值：

  成功返回0，失败返回-1，设置errno
```

客户端需要调用connect()连接服务器，connect和bind的参数形式一致，区别在于bind的参数是自己的地址，而connect的参数是对方的地址。connect()成功返回0，出错返回-1。



#### 出错处理函数

```
#include <errno.h>

#include <string.h>

char *strerror(int errnum);   /* See NOTES */

errnum:

  传入参数,错误编号的值，一般取 errno 的值

返回值：

  错误原因

 

#include <stdio.h>

#include <errno.h>

void perror(const char *s);  /* See NOTES */

s:

  传入参数,自定义的描述

返回值：

  无

向标准出错stderr 输出出错原因
```





**示例：**

```

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <errno.h>

#define IP "1.1.1.1"

#define SERVER_PORT 666


perror_exit(const char * des){
    //fprintf(stderr, "%s error, reason: %s\n", des, strerror(errno));
    perror(des);
    exit(1);
}

int main(void){

    int sock;//代表信箱
    int i, ret;
    struct sockaddr_in server_addr;


    //1.美女创建信箱
    sock = socket(AF_INET, SOCK_STREAM, 0);

    if(sock == -1){
        perror_exit("create socket");
    }

    //2.清空标签，写上地址和端口号
    bzero(&server_addr, sizeof(server_addr));

    server_addr.sin_family = AF_INET;//选择协议族IPV4
    inet_pton(AF_INET, IP, &server_addr.sin_addr.s_addr);
    //server_addr.sin_addr.s_addr = htonl(INADDR_ANY);//监听本地所有IP地址
    server_addr.sin_port = htons(SERVER_PORT);//绑定端口号

    //实现标签贴到收信得信箱上
    ret = bind(sock, (struct sockaddr *)&server_addr,  sizeof(server_addr));
    if(ret == -1){
        perror_exit("bind");
    }

    //把信箱挂置到传达室，这样，就可以接收信件了
    ret = listen(sock, 128);
    if(ret == -1){
        perror_exit("listen");
    }

    //万事俱备，只等来信
    printf("等待客户端的连接\n");


    int done =1;

    while(done){
        struct sockaddr_in client;
        int client_sock, len;
        char client_ip[64];
        char buf[256];

        socklen_t  client_addr_len;
        client_addr_len = sizeof(client);
        client_sock = accept(sock, (struct sockaddr *)&client, &client_addr_len);

        //打印客服端IP地址和端口号
        printf("client ip: %s\t port : %d\n",
                 inet_ntop(AF_INET, &client.sin_addr.s_addr,client_ip,sizeof(client_ip)),
                 ntohs(client.sin_port));
        /*读取客户端发送的数据*/
        len = read(client_sock, buf, sizeof(buf)-1);
        buf[len] = '\0';
        printf("recive[%d]: %s\n", len, buf);

        //转换成大写
        for(i=0; i<len; i++){
            /*if(buf[i]>='a' && buf[i]<='z'){
                buf[i] = buf[i] - 32;
            }*/
            buf[i] = toupper(buf[i]);
        }

        len = write(client_sock, buf, len);
        printf("write finished. len: %d\n", len);
        close(client_sock);

    }
    return 0;
}
```

