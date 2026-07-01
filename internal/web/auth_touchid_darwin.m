//go:build darwin && cgo

#import <LocalAuthentication/LocalAuthentication.h>
#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>

// mys_touchid_authenticate presents the macOS device-owner authentication
// sheet — Touch ID when available, with automatic fallback to the account
// password (LAPolicyDeviceOwnerAuthentication). It blocks until the user
// responds (the caller runs it on a dedicated goroutine and races it
// against context cancellation).
//
// Return codes:
//    1  authenticated (Touch ID or password accepted)
//    0  the user cancelled or authentication failed
//   -1  the policy cannot be evaluated at all (no biometrics enrolled and
//       no password set, or the process is not permitted)
int mys_touchid_authenticate(const char *reason) {
    @autoreleasepool {
        LAContext *context = [[LAContext alloc] init];
        NSError *authError = nil;
        if (![context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication
                                   error:&authError]) {
            return -1;
        }

        NSString *localizedReason =
            [NSString stringWithUTF8String:(reason ? reason : "authenticate")];

        dispatch_semaphore_t sema = dispatch_semaphore_create(0);
        __block int result = 0;
        [context evaluatePolicy:LAPolicyDeviceOwnerAuthentication
                localizedReason:localizedReason
                          reply:^(BOOL success, NSError *error) {
                            result = success ? 1 : 0;
                            dispatch_semaphore_signal(sema);
                          }];
        dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
        return result;
    }
}
