#ifndef ACCOUNT_ACCESS_NATIVE_BROKER_H
#define ACCOUNT_ACCESS_NATIVE_BROKER_H
#include "KeychainInteraction.h"
int AccountAccessActivateSocket(const char *name, int *descriptor);
bool AccountAccessProcessIdentity(int pid, unsigned int uid, unsigned int gid, int parent, int group);
#endif
