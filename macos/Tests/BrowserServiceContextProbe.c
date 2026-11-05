// Disposable hosted-Mac diagnosis only. No installed authority or secrets.
#include <Security/AuthSession.h>
#include <servers/bootstrap.h>
#include <mach/mach.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int isolate_bootstrap(void) {
    mach_port_t isolated = MACH_PORT_NULL;
    kern_return_t result = bootstrap_subset(bootstrap_port, mach_task_self(), &isolated);
    fprintf(stderr, "bootstrap_subset=%d\n", result);
    if (result != KERN_SUCCESS) return 74;
    result = task_set_bootstrap_port(mach_task_self(), isolated);
    if (result != KERN_SUCCESS) return 74;
    bootstrap_port = isolated;
    return 0;
}

int main(int argc, char **argv) {
    if (getuid() != 0 || geteuid() != 0 || argc < 3) return 77;
    const char *mode = argv[1];
    if (strcmp(mode, "plain") && strcmp(mode, "session") && strcmp(mode, "subset-before")
        && strcmp(mode, "subset-after")) return 77;
    struct passwd *actor = getpwnam("_accountaccess");
    if (!actor || actor->pw_uid < 450 || actor->pw_uid >= 500) return 77;
    uid_t uid = actor->pw_uid;
    gid_t gid = actor->pw_gid;
    if (!strcmp(mode, "session")) {
        OSStatus result = SessionCreate(0, 0);
        fprintf(stderr, "SessionCreate=%d\n", (int)result);
        if (result != 0) return 74;
    }
    if (!strcmp(mode, "subset-before") && isolate_bootstrap()) return 74;
    if (setgroups(0, NULL) || setgid(gid) || setuid(uid)
        || getuid() != uid || geteuid() != uid || getgid() != gid || getegid() != gid) return 77;
    if (!strcmp(mode, "subset-after") && isolate_bootstrap()) return 74;
    fprintf(stderr, "context=%s uid=%u gid=%u\n", mode, (unsigned)uid, (unsigned)gid);
    execv(argv[2], &argv[2]);
    return 76;
}
