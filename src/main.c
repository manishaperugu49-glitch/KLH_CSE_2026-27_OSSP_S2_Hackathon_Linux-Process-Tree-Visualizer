#define _POSIX_C_SOURCE 200809L
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAXP 20000
#define NAMELEN 256
#define SNAP "logs/process_snapshot.txt"
#define LOGFILE "logs/monitor.log"
#define RECORDS "logs/records.txt"
typedef struct { pid_t pid, ppid; char name[NAMELEN], state; int printed; } Proc;
static Proc procs[MAXP];
static size_t np;
static volatile sig_atomic_t got_signal;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static long shared_count;

static void clearline(void) { int c; while ((c=getchar())!='\n' && c!=EOF) {} }
static int getint(const char *prompt, int *v) {
    printf("%s", prompt); fflush(stdout);
    if (scanf("%d", v)!=1) { clearline(); return 0; }
    clearline(); return 1;
}
static int digits(const char *s) {
    if (!s || !*s) return 0;
    for (; *s; ++s) if (!isdigit((unsigned char)*s)) return 0;
    return 1;
}
static void ensure_logs(void) {
    struct stat st;
    if (stat("logs",&st)==-1 && mkdir("logs",0755)==-1 && errno!=EEXIST) perror("mkdir logs");
}
static void readprocs(void) {
    DIR *d=opendir("/proc"); struct dirent *e; np=0;
    if (!d) { perror("open /proc"); return; }
    while ((e=readdir(d)) && np<MAXP) {
        if (!digits(e->d_name)) continue;
        char path[512], line[4096];
        snprintf(path,sizeof path,"/proc/%s/stat",e->d_name);
        FILE *f=fopen(path,"r"); if (!f) continue;
        if (fgets(line,sizeof line,f)) {
            char *l=strchr(line,'('), *r=strrchr(line,')'); long pid,ppid;
            if (l && r && r>l && r[1]==' ' && sscanf(line,"%ld",&pid)==1 &&
                sscanf(r+4,"%ld",&ppid)==1 && pid>0 && ppid>=0) {
                Proc *p=&procs[np++]; size_t n=(size_t)(r-l-1);
                if (n>=sizeof p->name) n=sizeof p->name-1;
                memcpy(p->name,l+1,n); p->name[n]='\0';
                p->pid=(pid_t)pid; p->ppid=(pid_t)ppid; p->state=r[2]; p->printed=0;
            }
        }
        fclose(f);
    }
    closedir(d);
}
static int idxpid(pid_t pid) { for(size_t i=0;i<np;i++) if(procs[i].pid==pid) return (int)i; return -1; }
static void details(const Proc *p) {
    printf("\nName: %s\nPID: %ld\nParent PID: %ld\nState: %c\n",
           p->name,(long)p->pid,(long)p->ppid,p->state);
    char path[128], line[512]; snprintf(path,sizeof path,"/proc/%ld/status",(long)p->pid);
    FILE *f=fopen(path,"r"); if(!f) return;
    while(fgets(line,sizeof line,f))
        if(!strncmp(line,"Uid:",4)||!strncmp(line,"Gid:",4)||!strncmp(line,"VmSize:",7)||
           !strncmp(line,"VmRSS:",6)||!strncmp(line,"Threads:",8)) fputs(line,stdout);
    fclose(f);
}
static void children(pid_t parent,int depth) {
    if(depth>80) return;
    for(size_t i=0;i<np;i++) if(procs[i].ppid==parent&&!procs[i].printed) {
        procs[i].printed=1;
        for(int j=0;j<depth;j++) printf("    ");
        printf("|-- %-20s PID:%-7ld State:%c\n",procs[i].name,(long)procs[i].pid,procs[i].state);
        children(procs[i].pid,depth+1);
    }
}
static void live_monitor(void) {
    char in[32];
    do {
        readprocs(); for(size_t i=0;i<np;i++) procs[i].printed=0;
        printf("\033[2J\033[H===== LIVE PROCESS TREE =====\nDetected processes: %zu\n\n",np);
        for(size_t i=0;i<np;i++) if(!procs[i].printed && idxpid(procs[i].ppid)<0) {
            procs[i].printed=1;
            printf("%s PID:%ld State:%c\n",procs[i].name,(long)procs[i].pid,procs[i].state);
            children(procs[i].pid,1);
        }
        printf("\nEnter to refresh; q then Enter to return: "); fflush(stdout);
        if(!fgets(in,sizeof in,stdin)) break;
    } while(in[0]!='q'&&in[0]!='Q');
}
static void search_proc(void) {
    char q[NAMELEN]; printf("Enter PID or part of process name: ");
    if(scanf("%255s",q)!=1){clearline();puts("Invalid input.");return;} clearline();
    readprocs(); int found=0;
    for(size_t i=0;i<np;i++) {
        char p[32]; snprintf(p,sizeof p,"%ld",(long)procs[i].pid);
        if((digits(q)&&!strcmp(q,p))||(!digits(q)&&strstr(procs[i].name,q))) { details(&procs[i]); found++; }
    }
    if(!found) puts("No matching process found.");
}
static void process_details(void) {
    int pid; if(!getint("Enter PID: ",&pid)||pid<=0){puts("Enter a positive PID.");return;}
    readprocs(); int i=idxpid((pid_t)pid);
    if(i<0) puts("Process not found; it may have exited."); else details(&procs[i]);
}
static void lifecycle(void) {
    int c;
    while(1) {
        puts("\n===== PROCESS LIFECYCLE =====\n1. Create child and wait\n2. Show parent/child IDs\n0. Back");
        if(!getint("Choice: ",&c)){puts("Invalid input.");continue;} if(c==0)return;
        if(c!=1&&c!=2){puts("Invalid choice.");continue;}
        pid_t p=fork(); if(p<0){perror("fork");continue;}
        if(p==0){printf("Child PID=%ld PPID=%ld\n",(long)getpid(),(long)getppid());fflush(stdout);_exit(0);}
        printf("Parent PID=%ld; child PID=%ld\n",(long)getpid(),(long)p);
        if(waitpid(p,NULL,0)<0)perror("waitpid");else puts("Parent collected child exit status.");
    }
}
static void pipe_demo(void) {
    int f[2]; if(pipe(f)<0){perror("pipe");return;} pid_t p=fork();
    if(p<0){perror("fork");close(f[0]);close(f[1]);return;}
    if(p==0){close(f[1]);char b[128];ssize_t n=read(f[0],b,sizeof b-1);if(n>0){b[n]=0;printf("Child received: %s\n",b);}close(f[0]);fflush(stdout);_exit(0);}
    close(f[0]);const char *m="Hello from parent";if(write(f[1],m,strlen(m))<0)perror("write");close(f[1]);waitpid(p,NULL,0);
}
static void fifo_demo(void) {
    const char *path="/tmp/process_tree_visualizer.fifo",*msg="Message through named FIFO";
    if(mkfifo(path,0600)<0&&errno!=EEXIST){perror("mkfifo");return;}
    int fd=open(path,O_RDWR|O_NONBLOCK);if(fd<0){perror("open FIFO");unlink(path);return;}
    if(write(fd,msg,strlen(msg))<0)perror("write FIFO");
    else {char b[128];ssize_t n=read(fd,b,sizeof b-1);if(n>0){b[n]=0;printf("FIFO received: %s\n",b);}else puts("FIFO created, but no data was read.");}
    close(fd);unlink(path);
}
static void sighandler(int s){got_signal=s;}
static void signal_demo(void) {
    struct sigaction a;memset(&a,0,sizeof a);a.sa_handler=sighandler;sigemptyset(&a.sa_mask);got_signal=0;
    if(sigaction(SIGUSR1,&a,NULL)<0){perror("sigaction");return;}
    raise(SIGUSR1);if(got_signal==SIGUSR1)puts("SIGUSR1 received and handled successfully.");else puts("Signal demo failed.");
}
static void ipc_center(void) {
    int c;while(1){puts("\n===== IPC CENTER =====\n1. Anonymous pipe\n2. Named FIFO\n3. Signal handling\n0. Back");
        if(!getint("Choice: ",&c)){puts("Invalid input.");continue;}
        if (c == 0) return;
        switch (c) {
            case 1: pipe_demo(); break;
            case 2: fifo_demo(); break;
            case 3: signal_demo(); break;
            default: puts("Invalid choice.");
        }
    }
}
static void memory_monitor(void) {
    FILE *f=fopen("/proc/meminfo","r");char line[512];if(!f){perror("/proc/meminfo");return;}
    puts("\n===== MEMORY USAGE =====");while(fgets(line,sizeof line,f))
        if(!strncmp(line,"MemTotal:",9)||!strncmp(line,"MemAvailable:",13)||!strncmp(line,"MemFree:",8)||!strncmp(line,"SwapTotal:",10)||!strncmp(line,"SwapFree:",9))fputs(line,stdout);
    fclose(f);snprintf(line,sizeof line,"/proc/%ld/status",(long)getpid());f=fopen(line,"r");if(!f)return;
    puts("Visualizer process:");while(fgets(line,sizeof line,f))if(!strncmp(line,"VmSize:",7)||!strncmp(line,"VmRSS:",6))fputs(line,stdout);fclose(f);
}
static void file_manager(void) {
    int c;while(1){puts("\n===== FILE AND RECORD MANAGEMENT =====\n1. Add record\n2. View records\n3. File metadata\n0. Back");
        if(!getint("Choice: ",&c)){puts("Invalid input.");continue;}if(c==0)return;
        if(c==1){char b[512];printf("Enter one-line record: ");if(!fgets(b,sizeof b,stdin))continue;b[strcspn(b,"\n")]=0;
            ensure_logs();FILE *f=fopen(RECORDS,"a");if(!f){perror("open records");continue;}fprintf(f,"[%ld] %s\n",(long)time(NULL),b);fclose(f);printf("Saved to %s\n",RECORDS);
        }else if(c==2){FILE *f=fopen(RECORDS,"r");if(!f){puts("No records yet.");continue;}char b[1024];while(fgets(b,sizeof b,f))fputs(b,stdout);fclose(f);
        }else if(c==3){struct stat s;if(stat(RECORDS,&s)<0)perror("stat");else printf("Path: %s\nSize: %lld bytes\nPermissions: %o\n",RECORDS,(long long)s.st_size,(unsigned)(s.st_mode&0777));
        }else puts("Invalid choice.");
    }
}
static void *worker(void *arg) { long n=*(long*)arg;for(long i=0;i<n;i++){pthread_mutex_lock(&lock);shared_count++;pthread_mutex_unlock(&lock);}return NULL; }
static void thread_demo(void) {
    pthread_t t[4];long loops=100000;int made=0;shared_count=0;
    for(int i=0;i<4;i++){int e=pthread_create(&t[i],NULL,worker,&loops);if(e){fprintf(stderr,"pthread_create: %s\n",strerror(e));break;}made++;}
    for(int i=0;i<made;i++)pthread_join(t[i],NULL);
    printf("\nThreads created: %d\nExpected counter: %ld\nActual counter: %ld\nMutex prevents data races.\n",made,(long)made*loops,shared_count);
}
static void scheduling(void) {
    int p=sched_getscheduler(0);puts("\n===== SCHEDULING AND PROCESS STATES =====");printf("Current PID: %ld\n",(long)getpid());
    if(p<0)perror("sched_getscheduler");else if(p==SCHED_OTHER)puts("Policy: SCHED_OTHER (normal)");else if(p==SCHED_FIFO)puts("Policy: SCHED_FIFO");else if(p==SCHED_RR)puts("Policy: SCHED_RR");else printf("Policy ID: %d\n",p);
    readprocs();long r=0,s=0,t=0,z=0,o=0;for(size_t i=0;i<np;i++)switch(procs[i].state){case 'R':r++;break;case 'S':case 'I':s++;break;case 'T':case 't':t++;break;case 'Z':z++;break;default:o++;}
    printf("Processes: %zu | Running: %ld | Sleeping/idle: %ld | Stopped: %ld | Zombie: %ld | Other: %ld\n",np,r,s,t,z,o);
}
static void deadlock_demo(void) {
    puts("\n===== CONCURRENCY AND DEADLOCK ANALYSIS =====");
    puts("Safe-state example with 3 processes and 3 available resource units.");
    int available=3, alloc[]={1,1,0}, max[]={3,2,2}, finish[]={0,0,0}, seq[3],n=0;
    while(n<3){int moved=0;for(int i=0;i<3;i++){int need=max[i]-alloc[i];if(!finish[i]&&need<=available){available+=alloc[i];finish[i]=1;seq[n++]=i;moved=1;}}if(!moved)break;}
    if(n==3){printf("Safe state. Sequence: ");for(int i=0;i<3;i++)printf("P%d%s",seq[i],i==2?"\n":" -> ");}
    else puts("No safe sequence found.");
    puts("Educational simulation only; no real resources are changed.");
}
static void save_snapshot(void) {
    ensure_logs();readprocs();FILE *f=fopen(SNAP,"w");if(!f){perror("snapshot");return;}
    time_t now=time(NULL);fprintf(f,"Linux Process Snapshot\nGenerated: %s",ctime(&now));fprintf(f,"PID\tPPID\tSTATE\tNAME\n");
    for(size_t i=0;i<np;i++)fprintf(f,"%ld\t%ld\t%c\t%s\n",(long)procs[i].pid,(long)procs[i].ppid,procs[i].state,procs[i].name);
    fclose(f);printf("Saved %zu processes to %s\n",np,SNAP);
}
static void view_logs(void) {
    ensure_logs();FILE *f=fopen(LOGFILE,"a+");if(!f){perror("logs");return;}fseek(f,0,SEEK_END);
    if (ftell(f) == 0)
        fprintf(f, "[%ld] Monitoring log initialized.\n", (long)time(NULL));
    rewind(f);
    puts("\n===== MONITORING LOGS =====");char b[1024];while(fgets(b,sizeof b,f))fputs(b,stdout);fclose(f);
}
static void system_view(void) {
    char cwd[1024],line[128];printf("\n===== LINUX SYSTEM SERVICE VIEW =====\nPID: %ld\nPPID: %ld\nUID: %ld\nGID: %ld\n",(long)getpid(),(long)getppid(),(long)getuid(),(long)getgid());
    if (getcwd(cwd, sizeof cwd))
        printf("Current directory: %s\n", cwd);
    FILE *f = fopen("/proc/sys/kernel/ostype", "r");
    if (f) {
        if (fgets(line, sizeof line, f)) printf("Kernel type: %s", line);
        fclose(f);
    }
    puts("Uses Linux system calls and the /proc virtual filesystem.");
}
static void process_groups(void) {
    printf("\n===== PROCESS GROUPS AND JOB CONTROL =====\nPID: %ld\nPPID: %ld\nProcess group: %ld\nSession: %ld\n",
           (long)getpid(),(long)getppid(),(long)getpgrp(),(long)getsid(0));
    puts("Read-only process/session information; no other process is modified.");
}
static void menu(void) {
    puts("\n====================================================\n       LINUX PROCESS TREE VISUALIZER\n====================================================");
    puts(" 1. Live Process Monitoring\n 2. Search Process\n 3. Process Details\n 4. Process Lifecycle Manager");
    puts(" 5. Inter-Process Communication\n 6. Process Groups and Job Control\n 7. Memory Usage Monitor");
    puts(" 8. File and Record Management\n 9. Thread Synchronization\n10. Scheduling and Process States");
    puts("11. Concurrency and Deadlock Analysis\n12. Save Process Snapshot\n13. View Monitoring Logs\n14. Linux System Service View\n 0. Exit");
    puts("====================================================");
}
int main(void) {
    ensure_logs();int c;
    for(;;){menu();if(!getint("Enter your choice: ",&c)){puts("Invalid input; enter a number.");continue;}
        switch(c){case 0:puts("Exiting. Goodbye!");return 0;case 1:live_monitor();break;case 2:search_proc();break;case 3:process_details();break;
        case 4:lifecycle();break;case 5:ipc_center();break;case 6:process_groups();break;case 7:memory_monitor();break;case 8:file_manager();break;
        case 9:thread_demo();break;case 10:scheduling();break;case 11:deadlock_demo();break;case 12:save_snapshot();break;case 13:view_logs();break;case 14:system_view();break;
        default:puts("Invalid choice. Choose 0 to 14.");}
    }
}
