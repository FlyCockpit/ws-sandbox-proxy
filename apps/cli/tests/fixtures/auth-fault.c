// Linux syscall fault probe, adapted from /tmp/c20-fault.c. Never loaded by production.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/stat.h>

static int armed(void) {
    const char *marker = getenv("WSSP_TEST_FAULT_ARMED");
    return marker && access(marker, F_OK) == 0;
}
static int selected_path(const char *path, int directory) {
    const char *dir = getenv("WSSP_TEST_FAULT_DIR");
    if (!dir || !path) return 0;
    if (directory) return !strcmp(path, dir);
    return !strncmp(path, dir, strlen(dir)) && path[strlen(dir)] == '/' && strstr(path, "/.wssp-staging-") != NULL;
}
static int selected_fd(int fd, int directory) {
    char name[64], path[4096];
    snprintf(name, sizeof(name), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(name, path, sizeof(path)-1);
    if (n < 0) return 0;
    path[n] = 0;
    return selected_path(path, directory);
}
static int mode(const char *value) {
    const char *actual = getenv("WSSP_TEST_AUTH_FAULT");
    return armed() && actual && !strcmp(actual, value);
}
static void hit(void) {
    // The marker proves the intended syscall was reached. Use libc syscall
    // directly to avoid recursively invoking the intercepted open/write.
    const char *path = getenv("WSSP_TEST_FAULT_HIT");
    int (*real_open)(const char*,int,...) = dlsym(RTLD_NEXT,"open64");
    if (path) { int fd = real_open(path,O_CREAT|O_WRONLY,0600); if(fd >= 0) close(fd); }
}
int open64(const char *path, int flags, ...) {
    int (*next)(const char*,int,...) = dlsym(RTLD_NEXT,"open64");
    mode_t permissions=0;
    if (flags & O_CREAT) { va_list args;va_start(args,flags);permissions=va_arg(args,int);va_end(args); }
    if (mode("create") && selected_path(path,0)) {hit();errno=EIO;return -1;}
    return next(path,flags,permissions);
}
ssize_t write(int fd, const void *data, size_t n) {
    ssize_t (*next)(int,const void*,size_t)=dlsym(RTLD_NEXT,"write");
    if (selected_fd(fd,0)) {
        if (mode("write")) {hit();errno=EIO;return -1;}
        if (mode("crash-partial")) {ssize_t result=next(fd,data,n/2);hit();raise(SIGSTOP);return result;}
    }
    return next(fd,data,n);
}
int fdatasync(int fd) {
    int (*next)(int)=dlsym(RTLD_NEXT,"fdatasync");
    if ((mode("file-sync") && selected_fd(fd,0)) || (mode("dir-sync") && selected_fd(fd,1))) {hit();errno=EIO;return -1;}
    if (mode("parent-sync") && selected_fd(fd,1)) {
        const char *parent = getenv("WSSP_TEST_FAULT_PARENT");
        char name[64], path[4096];
        snprintf(name, sizeof(name), "/proc/self/fd/%d", fd);
        ssize_t n = readlink(name, path, sizeof(path)-1);
        if (n >= 0 && parent) {
            path[n] = 0;
            if (!strcmp(path, parent)) hit();
        }
    }
    return next(fd);
}
int fsync(int fd) {
    int (*next)(int)=dlsym(RTLD_NEXT,"fsync");
    if ((mode("file-sync") && selected_fd(fd,0)) || (mode("dir-sync") && selected_fd(fd,1))) {hit();errno=EIO;return -1;}
    if (mode("parent-sync") && selected_fd(fd,1)) {
        const char *parent = getenv("WSSP_TEST_FAULT_PARENT");
        char name[64], path[4096];
        snprintf(name, sizeof(name), "/proc/self/fd/%d", fd);
        ssize_t n = readlink(name, path, sizeof(path)-1);
        if (n >= 0 && parent) {
            path[n] = 0;
            if (!strcmp(path, parent)) hit();
        }
    }
    int result=next(fd);
    if (mode("rename") && selected_fd(fd,0)) {
        // tempfile uses raw rustix rename syscalls on Linux. A directory at the
        // destination makes the actual kernel rename fail, without mocking it.
        const char *target=getenv("WSSP_TEST_FAULT_TARGET");
        if (target) { mkdir(target,0700);hit(); }
    }
    if (mode("crash-synced") && selected_fd(fd,0)) {hit();raise(SIGSTOP);}
    return result;
}
int rename(const char *from, const char *to) {
    int (*next)(const char*,const char*)=dlsym(RTLD_NEXT,"rename");
    if (mode("rename") && selected_path(from,0)) {hit();errno=EIO;return -1;}
    return next(from,to);
}

int fchmod(int fd, mode_t permissions) {
    int (*next)(int,mode_t)=dlsym(RTLD_NEXT,"fchmod");
    if (mode("permissions") && selected_fd(fd,0)) {hit();errno=EIO;return -1;}
    return next(fd,permissions);
}
