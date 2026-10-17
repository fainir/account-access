#include "NativeBroker.h"
#include <launch.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

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
