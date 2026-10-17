#include "NativeBroker.h"
#include <launch.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <libproc.h>
#include <sys/proc_info.h>

// Bridge launch.h's non-null result-array annotation to a single descriptor.
// Unix listeners must each have exactly one result; close unexpected arrays.
int AccountAccessActivateSocket(const char *name, int *descriptor) {
    if (!name || !descriptor) return EINVAL;
    *descriptor = -1;
    int *values = NULL;
    size_t count = 0;
    int result = launch_activate_socket(name, &values, &count);
    if (result != 0) return result;
    if (!values || count != 1 || values[0] < 3) {
        if (values) for (size_t index = 0; index < count; index++) close(values[index]);
        free(values);
        return EINVAL;
    }
    int value = values[0];
    free(values);
    if (fcntl(value, F_SETFD, FD_CLOEXEC) != 0) {
        result = errno;
        close(value);
        return result;
    }
    *descriptor = value;
    return 0;
}

bool AccountAccessProcessIdentity(int pid, unsigned int uid, unsigned int gid, int parent, int group) {
    if (pid <= 0 || parent <= 0 || group <= 0 || uid == 0 || gid == 0) return false;
    struct proc_bsdinfo value = {0};
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &value, sizeof(value)) != sizeof(value)) return false;
    return value.pbi_pid == (unsigned int)pid && value.pbi_ppid == (unsigned int)parent &&
        value.pbi_pgid == (unsigned int)group && value.pbi_uid == uid && value.pbi_ruid == uid && value.pbi_svuid == uid &&
        value.pbi_gid == gid && value.pbi_rgid == gid && value.pbi_svgid == gid;
}
