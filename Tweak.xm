
#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>

%ctor {
    dispatch_after(
        dispatch_time(DISPATCH_TIME_NOW,
            (int64_t)(5 * NSEC_PER_SEC)),
        dispatch_get_main_queue(), ^{
        
        UIAlertController *alert =
            [UIAlertController
                alertControllerWithTitle:@"TWEAK ACTIVO"
                    message:@"El tweak cargo correctamente"
             preferredStyle:UIAlertControllerStyleAlert];
        
        [alert addAction:[UIAlertAction
            actionWithTitle:@"OK"
                      style:UIAlertActionStyleDefault
                    handler:nil]];
        
        UIViewController *root =
            [UIApplication sharedApplication]
            .keyWindow.rootViewController;
        [root presentViewController:alert
                           animated:YES
                         completion:nil];
    });
}
