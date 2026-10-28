#include "KeychainInteraction.h"
#include <Security/Security.h>

bool AccountAccessDisableKeychainInteraction(void) {
    // System daemons must use the file-based keychain (Apple TN3137). Its
    // SecItem shim does not implement data-protection authentication contexts.
    // This documented legacy control disables prompts in this process only;
    // authentication still fails when the OS requires owner interaction.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    OSStatus status = SecKeychainSetUserInteractionAllowed(false);
#pragma clang diagnostic pop
    return status == errSecSuccess;
}
