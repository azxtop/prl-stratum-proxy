#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

/* Scope: a single explicitly named executable. Other processes are ignored. */
static int logfd=-1, enabled=0;
static char routefile[1024];
static char logpath[1024];
static pthread_mutex_t log_lock=PTHREAD_MUTEX_INITIALIZER;
static _Atomic uint64_t ids[65536];
static _Atomic uint64_t serial=1;
static __thread int inside=0;
static pthread_mutex_t dns_lock=PTHREAD_MUTEX_INITIALIZER;
static struct {char ip[INET6_ADDRSTRLEN];char host[256];} dns_map[128];
static unsigned dns_count=0;
static int (*next_connect)(int,const struct sockaddr*,socklen_t);
static int (*next_gai)(const char*,const char*,const struct addrinfo*,struct addrinfo**);
static ssize_t (*next_send)(int,const void*,size_t,int);
static ssize_t (*next_recv)(int,void*,size_t,int);
static ssize_t (*next_write)(int,const void*,size_t);
static ssize_t (*next_read)(int,void*,size_t);
static ssize_t (*next_writev)(int,const struct iovec*,int);
static ssize_t (*next_sendmsg)(int,const struct msghdr*,int);
static ssize_t (*next_recvmsg)(int,struct msghdr*,int);
static int (*next_close)(int);
static int (*next_dup)(int);

static void escaped(char *dst,size_t cap,const unsigned char *src,size_t n){
    size_t pos=0;
    for(size_t i=0;i<n && pos+7<cap;i++){
        unsigned char c=src[i];
        if(c=='"'||c=='\\'){dst[pos++]='\\';dst[pos++]=c;}
        else if(c>=32&&c<127)dst[pos++]=c;
        else pos+=(size_t)snprintf(dst+pos,cap-pos,"\\u%04x",c);
    }
    dst[pos]=0;
}
static void emit(const char *body){
    if(logfd<0)return;
    int saved=errno;char line[7000];struct timespec ts;
    pthread_mutex_lock(&log_lock);
    struct stat current,pathstat;
    if(logpath[0] && (stat(logpath,&pathstat)<0 || fstat(logfd,&current)<0 || current.st_ino!=pathstat.st_ino || current.st_dev!=pathstat.st_dev)){
        int replacement=(int)syscall(SYS_openat,AT_FDCWD,logpath,O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC,0600);
        if(replacement>=0){syscall(SYS_close,logfd);logfd=replacement;}
    }
    clock_gettime(CLOCK_REALTIME,&ts);
    int n=snprintf(line,sizeof line,"{\"time\":%lld.%09ld,\"pid\":%d,\"tid\":%ld,%s}\n",(long long)ts.tv_sec,ts.tv_nsec,getpid(),syscall(SYS_gettid),body);
    if(n>0&&n<(int)sizeof line)syscall(SYS_write,logfd,line,(size_t)n);
    pthread_mutex_unlock(&log_lock);
    errno=saved;
}
__attribute__((constructor)) static void init(void){
    inside=1;
    next_connect=dlsym(RTLD_NEXT,"connect");next_gai=dlsym(RTLD_NEXT,"getaddrinfo");
    next_send=dlsym(RTLD_NEXT,"send");next_recv=dlsym(RTLD_NEXT,"recv");
    next_write=dlsym(RTLD_NEXT,"write");next_read=dlsym(RTLD_NEXT,"read");
    next_writev=dlsym(RTLD_NEXT,"writev");next_close=dlsym(RTLD_NEXT,"close");next_dup=dlsym(RTLD_NEXT,"dup");
    next_sendmsg=dlsym(RTLD_NEXT,"sendmsg");next_recvmsg=dlsym(RTLD_NEXT,"recvmsg");
    const char *want=getenv("PRL_OBSERVE_BINARY"),*path=getenv("PRL_OBSERVE_LOG"),*rules=getenv("PRL_OBSERVE_ROUTES");
    char exe[2048];ssize_t n=readlink("/proc/self/exe",exe,sizeof exe-1);
    if(n>0){exe[n]=0;if(want&&path&&!strcmp(exe,want)){
        snprintf(logpath,sizeof logpath,"%s",path);
        logfd=open(path,O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC,0600);enabled=logfd>=0;
        if(rules)snprintf(routefile,sizeof routefile,"%s",rules);
    }}
    if(enabled)emit("\"event\":\"observer_loaded\",\"file_modified\":false");
    inside=0;
}
static uint64_t getid(int fd){return fd>=0&&fd<65536?atomic_load(&ids[fd]):0;}
static int dns_matches(const char *ip,const char *host){
    int match=0;pthread_mutex_lock(&dns_lock);
    for(unsigned i=0;i<128;i++)if(!strcmp(dns_map[i].ip,ip)&&!strcasecmp(dns_map[i].host,host)){match=1;break;}
    pthread_mutex_unlock(&dns_lock);return match;
}
static int route(const char *ip,int port){
    if(!routefile[0])return 0;
    int fd=(int)syscall(SYS_openat,AT_FDCWD,routefile,O_RDONLY|O_CLOEXEC,0);
    if(fd<0)return 0;
    char buf[16384];ssize_t n=syscall(SYS_read,fd,buf,sizeof buf-1);syscall(SYS_close,fd);
    if(n<=0)return 0;
    buf[n]=0;
    char *save=NULL,*line=strtok_r(buf,"\n",&save);
    while(line){char target[128];int p=0,local=0;
        if(sscanf(line,"%127s %d %d",target,&p,&local)==3 && p==port && (!strcmp(target,ip)||dns_matches(ip,target))&&local>0&&local<65536)return local;
        line=strtok_r(NULL,"\n",&save);
    }
    return 0;
}
int connect(int fd,const struct sockaddr *addr,socklen_t len){
    if(!next_connect)return (int)syscall(SYS_connect,fd,addr,len);
    if(!enabled||inside||!addr||(addr->sa_family!=AF_INET&&addr->sa_family!=AF_INET6))return next_connect(fd,addr,len);
    inside=1;char ip[INET6_ADDRSTRLEN]="";int port=0;
    if(addr->sa_family==AF_INET){const struct sockaddr_in *a=(const void*)addr;inet_ntop(AF_INET,&a->sin_addr,ip,sizeof ip);port=ntohs(a->sin_port);}
    else {const struct sockaddr_in6 *a=(const void*)addr;inet_ntop(AF_INET6,&a->sin6_addr,ip,sizeof ip);port=ntohs(a->sin6_port);}
    int local=route(ip,port),result;uint64_t id=atomic_fetch_add(&serial,1);
    if(fd>=0&&fd<65536)atomic_store(&ids[fd],id);
    if(local&&addr->sa_family==AF_INET){struct sockaddr_in a=*(const struct sockaddr_in*)addr;a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);a.sin_port=htons((uint16_t)local);result=next_connect(fd,(const void*)&a,sizeof a);}
    else if(local&&addr->sa_family==AF_INET6){struct sockaddr_in6 a=*(const struct sockaddr_in6*)addr;a.sin6_addr=in6addr_loopback;a.sin6_port=htons((uint16_t)local);result=next_connect(fd,(const void*)&a,sizeof a);}
    else result=next_connect(fd,addr,len);
    int saved=errno;char body[1000];snprintf(body,sizeof body,"\"event\":\"connect\",\"connection\":%llu,\"fd\":%d,\"ip\":\"%s\",\"port\":%d,\"route_port\":%d,\"result\":%d,\"errno\":%d",(unsigned long long)id,fd,ip,port,local,result,result<0?saved:0);emit(body);inside=0;errno=saved;return result;
}
int getaddrinfo(const char *node,const char *service,const struct addrinfo *hints,struct addrinfo **res){
    if(!next_gai){errno=ENOSYS;return EAI_SYSTEM;}
    int r=next_gai(node,service,hints,res);
    int saved=errno;
    if(enabled&&!inside){inside=1;char name[1500],svc[400],body[2200];escaped(name,sizeof name,(const unsigned char*)(node?node:""),node?strnlen(node,200):0);escaped(svc,sizeof svc,(const unsigned char*)(service?service:""),service?strnlen(service,40):0);snprintf(body,sizeof body,"\"event\":\"dns\",\"host\":\"%s\",\"service\":\"%s\",\"result\":%d",name,svc,r);emit(body);inside=0;}
    if(enabled&&r==0&&node&&res){
        inside=1;
        for(struct addrinfo *a=*res;a;a=a->ai_next){char ip[INET6_ADDRSTRLEN]="";
            if(a->ai_family==AF_INET)inet_ntop(AF_INET,&((struct sockaddr_in*)a->ai_addr)->sin_addr,ip,sizeof ip);
            else if(a->ai_family==AF_INET6)inet_ntop(AF_INET6,&((struct sockaddr_in6*)a->ai_addr)->sin6_addr,ip,sizeof ip);
            else continue;
            pthread_mutex_lock(&dns_lock);unsigned i=dns_count++%128;snprintf(dns_map[i].ip,sizeof dns_map[i].ip,"%s",ip);snprintf(dns_map[i].host,sizeof dns_map[i].host,"%s",node);pthread_mutex_unlock(&dns_lock);
            char name[1500],body[2000];escaped(name,sizeof name,(const unsigned char*)node,strnlen(node,200));snprintf(body,sizeof body,"\"event\":\"dns_address\",\"host\":\"%s\",\"ip\":\"%s\"",name,ip);emit(body);
        }
        inside=0;
    }
    errno=saved;
    return r;
}
/* Record metadata only. Do not log authorization or proof payloads. */
static void data(int fd,const void *buf,ssize_t n,const char *direction){
    (void)buf;
    uint64_t id=getid(fd);if(!enabled||inside||!id||n<=0)return;
    inside=1;char body[400];
    snprintf(body,sizeof body,"\"event\":\"io_metadata\",\"connection\":%llu,\"fd\":%d,\"direction\":\"%s\",\"bytes\":%lld",(unsigned long long)id,fd,direction,(long long)n);
    emit(body);inside=0;
}
ssize_t send(int fd,const void *b,size_t n,int f){ssize_t r=next_send?next_send(fd,b,n,f):syscall(SYS_sendto,fd,b,n,f,NULL,0);int e=errno;data(fd,b,r,"out");errno=e;return r;}
ssize_t recv(int fd,void *b,size_t n,int f){ssize_t r=next_recv?next_recv(fd,b,n,f):syscall(SYS_recvfrom,fd,b,n,f,NULL,NULL);int e=errno;data(fd,b,r,"in");errno=e;return r;}
ssize_t write(int fd,const void *b,size_t n){ssize_t r=next_write?next_write(fd,b,n):syscall(SYS_write,fd,b,n);int e=errno;data(fd,b,r,"out");errno=e;return r;}
ssize_t read(int fd,void *b,size_t n){ssize_t r=next_read?next_read(fd,b,n):syscall(SYS_read,fd,b,n);int e=errno;data(fd,b,r,"in");errno=e;return r;}
static void vector_data(int fd,const struct iovec *v,size_t n,ssize_t result,const char *direction){
    (void)v;(void)n;data(fd,NULL,result,direction);
}
ssize_t writev(int fd,const struct iovec *v,int n){ssize_t r=next_writev?next_writev(fd,v,n):syscall(SYS_writev,fd,v,n);int e=errno;if(n>0)vector_data(fd,v,(size_t)n,r,"out");errno=e;return r;}
ssize_t sendmsg(int fd,const struct msghdr *msg,int flags){ssize_t r=next_sendmsg?next_sendmsg(fd,msg,flags):syscall(SYS_sendmsg,fd,msg,flags);int e=errno;if(msg)vector_data(fd,msg->msg_iov,msg->msg_iovlen,r,"out");errno=e;return r;}
ssize_t recvmsg(int fd,struct msghdr *msg,int flags){ssize_t r=next_recvmsg?next_recvmsg(fd,msg,flags):syscall(SYS_recvmsg,fd,msg,flags);int e=errno;if(msg)vector_data(fd,msg->msg_iov,msg->msg_iovlen,r,"in");errno=e;return r;}
int close(int fd){if(fd>=0&&fd<65536)atomic_store(&ids[fd],0);return next_close?next_close(fd):(int)syscall(SYS_close,fd);}
int dup(int fd){int r=next_dup?next_dup(fd):(int)syscall(SYS_dup,fd);if(r>=0&&r<65536)atomic_store(&ids[r],getid(fd));return r;}
