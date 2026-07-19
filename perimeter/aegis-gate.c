#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/seccomp.h>
#include <limits.h>
#include <poll.h>
#include <openssl/evp.h>
#include <seccomp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_ARGS 32
#define MAX_ARG_LEN 128
#define MAX_PATH_LEN 256
#define RESPONSE_LEN 2048

static volatile sig_atomic_t stop_signal = 0;
static pid_t supervised_child = -1;

static void handle_signal(int sig) {
    stop_signal = sig;
    // A task blocked in seccomp user notification may not process the
    // original interactive signal promptly. PID 1 shutdown must be
    // unconditional so docker attach/stop can never trap the user.
    if (supervised_child > 0) kill(supervised_child, SIGKILL);
}

static int send_fd(int sock, int fd) {
    char byte = 'F';
    struct iovec iov = {.iov_base = &byte, .iov_len = 1};
    char control[CMSG_SPACE(sizeof(int))] = {0};
    struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = control, .msg_controllen = sizeof(control)};
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
    return sendmsg(sock, &msg, 0);
}

static int recv_fd(int sock) {
    char byte;
    struct iovec iov = {.iov_base = &byte, .iov_len = 1};
    char control[CMSG_SPACE(sizeof(int))] = {0};
    struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = control, .msg_controllen = sizeof(control)};
    if (recvmsg(sock, &msg, 0) <= 0) return -1;
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) return -1;
    int fd;
    memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
    return fd;
}

static ssize_t read_remote(pid_t pid, uintptr_t remote, void *local, size_t len) {
    struct iovec liov = {.iov_base = local, .iov_len = len};
    struct iovec riov = {.iov_base = (void *)remote, .iov_len = len};
    return process_vm_readv(pid, &liov, 1, &riov, 1, 0);
}

static int read_remote_string(pid_t pid, uintptr_t remote, char *out, size_t cap) {
    if (!remote || cap == 0) return -1;
    memset(out, 0, cap);
    ssize_t n = read_remote(pid, remote, out, cap - 1);
    if (n <= 0) return -1;
    out[cap - 1] = '\0';
    return 0;
}

static void json_string(FILE *f, const char *s) {
    fputc('"', f);
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
        case '"': fputs("\\\"", f); break;
        case '\\': fputs("\\\\", f); break;
        case '\n': fputs("\\n", f); break;
        case '\r': fputs("\\r", f); break;
        case '\t': fputs("\\t", f); break;
        default:
            if (c < 0x20) fprintf(f, "\\u%04x", c);
            else fputc(c, f);
        }
    }
    fputc('"', f);
}

static int connect_gate(const char *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    if (strlen(path) >= sizeof(addr.sun_path)) { close(fd); errno = ENAMETOOLONG; return -1; }
    strcpy(addr.sun_path, path);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) { close(fd); return -1; }
    return fd;
}

static void canonical_exec_path(pid_t pid, const char *raw, char *out, size_t cap) {
    char candidate[PATH_MAX] = {0};
    if (raw[0] == '/') {
        snprintf(candidate, sizeof(candidate), "%s", raw);
    } else {
        char cwd_link[64];
        char cwd[PATH_MAX] = {0};
        snprintf(cwd_link, sizeof(cwd_link), "/proc/%d/cwd", pid);
        ssize_t n = readlink(cwd_link, cwd, sizeof(cwd) - 1);
        if (n > 0) snprintf(candidate, sizeof(candidate), "%s/%s", cwd, raw);
        else snprintf(candidate, sizeof(candidate), "%s", raw);
    }
    char resolved[PATH_MAX] = {0};
    if (realpath(candidate, resolved)) snprintf(out, cap, "%s", resolved);
    else snprintf(out, cap, "%s", raw);
}

static int sha256_file(const char *path, char out[65]) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { fclose(f); return -1; }
    int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1;
    unsigned char buf[8192];
    size_t n;
    while (ok && (n = fread(buf, 1, sizeof(buf), f)) > 0) {
        ok = EVP_DigestUpdate(ctx, buf, n) == 1;
    }
    if (ferror(f)) ok = 0;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    if (ok) ok = EVP_DigestFinal_ex(ctx, digest, &digest_len) == 1;
    EVP_MD_CTX_free(ctx);
    fclose(f);
    if (!ok || digest_len != 32) return -1;
    for (unsigned int i = 0; i < digest_len; i++) sprintf(out + i * 2, "%02x", digest[i]);
    out[64] = '\0';
    return 0;
}

static int ask_aegisd(pid_t pid, const char *path, const char *raw_path, const char *sha256, char args[MAX_ARGS][MAX_ARG_LEN], int argc, int bootstrap, char *response, size_t response_cap) {
    const char *socket_path = getenv("AEGIS_EXEC_GATE_SOCKET");
    if (!socket_path) socket_path = "/run/aegis/exec-gate.sock";

    int fd = -1;
    // run.sh may start before aegisd. Keep the first shell exec held while
    // the daemon starts and detects this already-running container.
    fprintf(stderr, "[aegis-gate] command held in kernel; waiting for aegisd at %s\n", socket_path);
    for (int i = 0; i < 120 && fd < 0; i++) {
        if (stop_signal) {
            snprintf(response, response_cap, "interrupted while waiting for aegisd");
            return 0;
        }
        fd = connect_gate(socket_path);
        if (fd < 0) usleep(500000);
    }
    if (fd < 0) {
        snprintf(response, response_cap, "exec gate unavailable after 60s: %s", strerror(errno));
        return 0;
    }

    FILE *io = fdopen(fd, "r+");
    if (!io) { close(fd); return 0; }
    char cwd[PATH_MAX] = {0};
    char cwd_link[64];
    snprintf(cwd_link, sizeof(cwd_link), "/proc/%d/cwd", pid);
    ssize_t n = readlink(cwd_link, cwd, sizeof(cwd) - 1);
    if (n < 0) strcpy(cwd, "?");

    fprintf(io, "{\"pid\":%d,\"path\":", pid);
    json_string(io, path);
    fputs(",\"raw_path\":", io);
    json_string(io, raw_path);
    fputs(",\"sha256\":", io);
    json_string(io, sha256);
    fputs(",\"argv\":[", io);
    for (int i = 0; i < argc; i++) {
        if (i) fputc(',', io);
        json_string(io, args[i]);
    }
    fputs("],\"cwd\":", io);
    json_string(io, cwd);
    if (bootstrap) fputs(",\"bootstrap\":true", io);
    fputs("}\n", io);
    fflush(io);

    if (!fgets(response, response_cap, io)) response[0] = '\0';
    fclose(io);
    return strstr(response, "\"decision\":\"Allow\"") != NULL;
}

static int install_filter_and_send(int sock) {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) return -1;
    if (seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(execve), 0) < 0 ||
        seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(execveat), 0) < 0 ||
        seccomp_load(ctx) < 0) {
        seccomp_release(ctx);
        return -1;
    }
    int notify_fd = seccomp_notify_fd(ctx);
    if (notify_fd < 0 || send_fd(sock, notify_fd) < 0) {
        seccomp_release(ctx);
        return -1;
    }
    // Keep ctx alive until exec; the listener FD remains owned by parent.
    return 0;
}

static int supervise(int notify_fd, pid_t child, const char *bootstrap_path) {
    struct seccomp_notif *req = NULL;
    struct seccomp_notif_resp *resp = NULL;
    if (seccomp_notify_alloc(&req, &resp) < 0) return 1;

    int child_status = 0;
    int bootstrap_used = 0;

    while (1) {
        pid_t ended = waitpid(child, &child_status, WNOHANG);
        if (ended == child) break;
        if (stop_signal) {
            kill(child, SIGKILL);
            waitpid(child, &child_status, 0);
            break;
        }

        // seccomp notification FDs are pollable. The timeout lets PID 1
        // notice a denied/failed child exit instead of blocking forever.
        struct pollfd pfd = {.fd = notify_fd, .events = POLLIN};
        int ready = poll(&pfd, 1, 250);
        if (ready < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (ready == 0) continue;
        if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL)) break;
        if (!(pfd.revents & POLLIN)) continue;

        memset(req, 0, sizeof(*req));
        memset(resp, 0, sizeof(*resp));
        if (seccomp_notify_receive(notify_fd, req) < 0) {
            if (errno == EINTR || errno == ENOENT) continue;
            break;
        }

        char raw_path[MAX_PATH_LEN] = {0};
        char path[MAX_PATH_LEN] = {0};
        char args[MAX_ARGS][MAX_ARG_LEN] = {{0}};
        uintptr_t filename_ptr;
        uintptr_t argv_ptr;
        int execveat_fd = -1;
#ifdef __NR_execveat
        if (req->data.nr == __NR_execveat) {
            execveat_fd = (int)req->data.args[0];
            filename_ptr = (uintptr_t)req->data.args[1];
            argv_ptr = (uintptr_t)req->data.args[2];
        } else
#endif
        {
            filename_ptr = (uintptr_t)req->data.args[0];
            argv_ptr = (uintptr_t)req->data.args[1];
        }
        read_remote_string(req->pid, filename_ptr, raw_path, sizeof(raw_path));
        // fexecve/execveat(AT_EMPTY_PATH) may use an empty pathname. Resolve
        // the target FD through procfs so the decision still names the binary.
        if (raw_path[0] == '\0' && execveat_fd >= 0) {
            char fd_link[64];
            snprintf(fd_link, sizeof(fd_link), "/proc/%d/fd/%d", req->pid, execveat_fd);
            ssize_t n = readlink(fd_link, raw_path, sizeof(raw_path) - 1);
            if (n > 0) raw_path[n] = '\0';
        }
        canonical_exec_path(req->pid, raw_path, path, sizeof(path));

        int argc = 0;
        for (int i = 0; i < MAX_ARGS; i++) {
            uintptr_t argp = 0;
            if (read_remote(req->pid, argv_ptr + i * sizeof(argp), &argp, sizeof(argp)) != sizeof(argp) || !argp) break;
            if (read_remote_string(req->pid, argp, args[i], sizeof(args[i])) < 0) break;
            argc++;
        }

        char canonical_bootstrap[MAX_PATH_LEN] = {0};
        canonical_exec_path(req->pid, bootstrap_path, canonical_bootstrap, sizeof(canonical_bootstrap));
        int bootstrap = !bootstrap_used && req->pid == child && strcmp(path, canonical_bootstrap) == 0;
        if (bootstrap) bootstrap_used = 1;

        char result[RESPONSE_LEN] = {0};
        char sha256[65] = {0};
        int hash_ok = sha256_file(path, sha256) == 0;
        int allow = hash_ok && ask_aegisd(req->pid, path, raw_path, sha256, args, argc, bootstrap, result, sizeof(result));
        if (!hash_ok) snprintf(result, sizeof(result), "could not hash executable; refusing to continue");
        fprintf(stderr, "[aegis-gate] %s%s %s -> %s\n", allow ? "ALLOW" : "DENY", bootstrap ? " (bootstrap)" : "", path, result[0] ? result : "no response");

        resp->id = req->id;
        if (allow) {
            resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        } else {
            resp->error = -EPERM;
        }
        if (seccomp_notify_respond(notify_fd, resp) < 0 && errno != ENOENT) break;
    }

    seccomp_notify_free(req, resp);
    // poll may report HUP before waitpid observes the child's exec failure.
    // Never return the zero-initialized status in that path: reap the child
    // (or kill it if the notifier itself failed while it was still alive).
    pid_t ended = waitpid(child, &child_status, WNOHANG);
    if (ended == 0) {
        kill(child, SIGKILL);
        waitpid(child, &child_status, 0);
    } else if (ended < 0 && errno != ECHILD) {
        child_status = 1 << 8;
    }
    return child_status;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: aegis-gate <program> [args...]\n");
        return 2;
    }

    int pair[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, pair) < 0) {
        perror("socketpair"); return 1;
    }
    pid_t child = fork();
    if (child < 0) { perror("fork"); return 1; }
    if (child == 0) {
        close(pair[0]);
        if (install_filter_and_send(pair[1]) < 0) {
            perror("install seccomp notify filter");
            _exit(126);
        }
        close(pair[1]);
        execvp(argv[1], &argv[1]); // held here until supervisor receives Allow
        perror("execvp");
        _exit(127);
    }

    close(pair[1]);
    supervised_child = child;
    struct sigaction sa = {0};
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    int notify_fd = recv_fd(pair[0]);
    close(pair[0]);
    if (notify_fd < 0) {
        fprintf(stderr, "failed to receive seccomp listener fd\n");
        kill(child, SIGKILL);
        return 1;
    }
    int status = supervise(notify_fd, child, argv[1]);
    close(notify_fd);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}
