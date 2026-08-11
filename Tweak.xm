#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#include <mach-o/dyld.h>
#include <mach-o/nlist.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <stdatomic.h>
#include <pthread.h>

// ================================================
// CONFIG
// ================================================
#define MAX_FRAMES   32
#define SAMPLE_MS    150
#define MAX_LOG      2048
#define LOG_MAX_CHAR (512*1024)

// ================================================
// ESTADO GLOBAL
// ================================================
static UIWindow      *g_window     = nil;
static UITextView    *g_textview   = nil;
static UIButton      *g_fab        = nil;
static UIView        *g_panel      = nil;
static BOOL           g_expanded   = NO;
static BOOL           g_tracing    = NO;
static pthread_t      g_thread;
static atomic_bool    g_running    = false;

static NSMutableString *g_log      = nil;
static NSLock          *g_lock     = nil;

// Base address de Instagram para resolver offsets
static uint64_t g_base = 0;
static NSString *g_bundle_name = nil;

// ================================================
// HELPERS
// ================================================

// Encontrar base address de la app target
static void find_base(void) {
    uint32_t count = _dyld_image_count();
    for(uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if(!name) continue;
        if(strstr(name,"LiveProcess")) continue;
        if(strstr(name,"usr/lib"))    continue;
        if(strstr(name,"System"))     continue;
        if(strstr(name,"framework"))  continue;
        // Primera imagen que no es sistema = app
        const struct mach_header *mh =
            _dyld_get_image_header(i);
        g_base = (uint64_t)mh;
        g_bundle_name = [NSString stringWithUTF8String:
            name ?: "?"];
        return;
    }
}

// Agregar línea al log
static void add_log(NSString *line) {
    [g_lock lock];
    if(g_log.length > LOG_MAX_CHAR)
        [g_log deleteCharactersInRange:
            NSMakeRange(0, g_log.length/2)];
    [g_log appendFormat:@"%@\n", line];
    [g_lock unlock];
}

// ================================================
// TRACER — sampling thread
// ================================================
static void *tracer_thread(void *arg) {
    void *frames[MAX_FRAMES];

    while(atomic_load(&g_running)) {
        if(g_tracing) {
            int n = backtrace(frames, MAX_FRAMES);

            NSMutableString *entry =
                [NSMutableString new];

            for(int i = 1; i < n && i < 8; i++) {
                uint64_t addr = (uint64_t)frames[i];

                // Intentar resolver símbolo con dladdr
                Dl_info info;
                if(dladdr(frames[i], &info) &&
                   info.dli_sname) {
                    // Tiene símbolo
                    [entry appendFormat:
                        @"  [%d] %s\n",
                        i, info.dli_sname];
                } else {
                    // Sin símbolo — mostrar offset
                    // relativo a la base de la app
                    uint64_t offset =
                        addr > g_base ?
                        addr - g_base : addr;
                    [entry appendFormat:
                        @"  [%d] 0x%llx\n",
                        i, offset];
                }
            }

            if(entry.length > 0) {
                NSString *ts = [NSString
                    stringWithFormat:@"─── %@",
                    [[NSDate date] descriptionWithLocale:nil]];
                add_log(ts);
                add_log(entry);
            }
        }

        // Sleep SAMPLE_MS milisegundos
        usleep(SAMPLE_MS * 1000);
    }
    return NULL;
}

// ================================================
// UI — actualizar textview desde main thread
// ================================================
static void update_ui(void) {
    if(!g_expanded || !g_textview) return;
    [g_lock lock];
    NSString *text = [g_log copy];
    [g_lock unlock];

    // Mostrar las últimas líneas
    NSArray *lines =
        [text componentsSeparatedByString:@"\n"];
    NSInteger start =
        lines.count > MAX_LOG ?
        lines.count - MAX_LOG : 0;
    NSArray *recent =
        [lines subarrayWithRange:
            NSMakeRange(start,
                lines.count - start)];
    NSString *display =
        [recent componentsJoinedByString:@"\n"];

    g_textview.text = display;

    // Scroll al final
    if(display.length > 0) {
        NSRange r = NSMakeRange(
            display.length - 1, 1);
        [g_textview scrollRangeToVisible:r];
    }
}

// ================================================
// ACTIONS
// ================================================
@interface DisasmController : NSObject
+ (void)togglePanel;
+ (void)toggleTrace;
+ (void)clearLog;
+ (void)saveLog;
+ (void)fabDragged:(UIPanGestureRecognizer*)pan;
@end

@implementation DisasmController

+ (void)togglePanel {
    g_expanded = !g_expanded;
    [UIView animateWithDuration:0.25 animations:^{
        g_panel.alpha = g_expanded ? 1.0 : 0.0;
        g_panel.hidden = !g_expanded;
    }];
    [g_fab setTitle:g_expanded ? @"✕" : @"⚙"
           forState:UIControlStateNormal];
}

+ (void)toggleTrace {
    g_tracing = !g_tracing;

    UIButton *btn = (UIButton*)
        [g_panel viewWithTag:200];
    [btn setTitle:g_tracing ?
        @"⏸ PAUSE" : @"▶ TRACE"
        forState:UIControlStateNormal];
    [btn setBackgroundColor:g_tracing ?
        [UIColor colorWithRed:0.8
                        green:0.2
                         blue:0.2
                        alpha:1] :
        [UIColor colorWithRed:0.1
                        green:0.6
                         blue:0.1
                        alpha:1]];
}

+ (void)clearLog {
    [g_lock lock];
    [g_log setString:@""];
    [g_lock unlock];
    g_textview.text = @"";
}

+ (void)saveLog {
    [g_lock lock];
    NSString *text = [g_log copy];
    [g_lock unlock];

    NSString *docs =
        NSSearchPathForDirectoriesInDomains(
            NSDocumentDirectory,
            NSUserDomainMask, YES).firstObject;
    NSString *path =
        [docs stringByAppendingPathComponent:
            @"live_trace.txt"];
    [text writeToFile:path
           atomically:YES
             encoding:NSUTF8StringEncoding
                error:nil];

    UIAlertController *a =
        [UIAlertController
            alertControllerWithTitle:@"Guardado"
                message:path
         preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction
        actionWithTitle:@"OK"
                  style:UIAlertActionStyleDefault
                handler:nil]];
    UIViewController *root =
        g_window.rootViewController;
    [root presentViewController:a
                       animated:YES
                     completion:nil];
}

+ (void)fabDragged:(UIPanGestureRecognizer*)pan {
    CGPoint t = [pan translationInView:g_window];
    g_fab.center = CGPointMake(
        g_fab.center.x + t.x,
        g_fab.center.y + t.y);
    [pan setTranslation:CGPointZero
                 inView:g_window];
}

@end


// ── Window que pasa toques a la app ──
@interface PassthroughWindow : UIWindow
@end

@implementation PassthroughWindow

- (UIView *)hitTest:(CGPoint)point
          withEvent:(UIEvent *)event {
    UIView *hit = [super hitTest:point
                       withEvent:event];
    // Si el hit es la ventana o el vc root
    // pasar el toque a la app debajo
    if(hit == self ||
       hit == self.rootViewController.view) {
        return nil;
    }
    return hit;
}

@end


// ================================================
// BUILD UI
// ================================================
static void build_ui(void) {
    CGRect screen = UIScreen.mainScreen.bounds;
    CGFloat W = screen.size.width;
    CGFloat H = screen.size.height;

    // ── Ventana overlay ──
    g_window = [[PassthroughWindow alloc]
        initWithFrame:screen];
    g_window.windowLevel =
        UIWindowLevelAlert + 200;
    g_window.backgroundColor =
        [UIColor clearColor];
    g_window.userInteractionEnabled = YES;

    UIViewController *vc =
        [UIViewController new];
    vc.view.backgroundColor =
        [UIColor clearColor];
    g_window.rootViewController = vc;

    // ── FAB (botón flotante) ──
    CGFloat fab_size = 52;
    g_fab = [[UIButton alloc]
        initWithFrame:CGRectMake(
            W - fab_size - 16,
            H * 0.4,
            fab_size, fab_size)];
    g_fab.backgroundColor =
        [UIColor colorWithRed:0
                        green:0.8
                         blue:0.4
                        alpha:0.92];
    g_fab.layer.cornerRadius = fab_size/2;
    g_fab.layer.shadowColor  =
        [UIColor blackColor].CGColor;
    g_fab.layer.shadowOpacity = 0.4;
    g_fab.layer.shadowRadius  = 6;
    g_fab.layer.shadowOffset  =
        CGSizeMake(0, 3);
    [g_fab setTitle:@"⚙"
           forState:UIControlStateNormal];
    g_fab.titleLabel.font =
        [UIFont systemFontOfSize:22
                          weight:UIFontWeightBold];
    [g_fab setTitleColor:UIColor.blackColor
                forState:UIControlStateNormal];

    // Touch handler
    [g_fab addTarget:DisasmController.class
              action:@selector(togglePanel)
    forControlEvents:UIControlEventTouchUpInside];

    // Drag
    UIPanGestureRecognizer *pan =
        [[UIPanGestureRecognizer alloc]
            initWithTarget:DisasmController.class
                    action:@selector(fabDragged:)];
    [g_fab addGestureRecognizer:pan];

    [g_window addSubview:g_fab];

    // ── Panel ──
    CGFloat pw = W - 32;
    CGFloat ph = H * 0.65;
    g_panel = [[UIView alloc]
        initWithFrame:CGRectMake(
            16, H - ph - 16,
            pw, ph)];
    g_panel.backgroundColor =
        [UIColor colorWithRed:0.05
                        green:0.05
                         blue:0.05
                        alpha:0.96];
    g_panel.layer.cornerRadius = 12;
    g_panel.layer.borderWidth  = 1;
    g_panel.layer.borderColor  =
        [UIColor colorWithRed:0
                        green:0.8
                         blue:0.4
                        alpha:0.5].CGColor;
    g_panel.hidden = YES;
    g_panel.alpha  = 0;

    // Header
    UILabel *header = [UILabel new];
    header.frame = CGRectMake(12, 10, pw-24, 28);
    header.text = [NSString stringWithFormat:
        @"LIVE TRACER — %@",
        g_bundle_name.lastPathComponent];
    header.font = [UIFont
        monospacedSystemFontOfSize:11
                            weight:UIFontWeightBold];
    header.textColor =
        [UIColor colorWithRed:0
                        green:0.8
                         blue:0.4
                        alpha:1];
    [g_panel addSubview:header];

    // Barra de botones
    CGFloat bw = (pw - 24) / 3.0;
    NSArray *btnTitles =
        @[@"▶ TRACE", @"🗑 CLEAR", @"💾 SAVE"];
    NSArray *btnSels = @[
        @"toggleTrace",
        @"clearLog",
        @"saveLog"
    ];
    NSArray *btnColors = @[
        [UIColor colorWithRed:0.1 green:0.6
                        blue:0.1 alpha:1],
        [UIColor colorWithRed:0.5 green:0.5
                        blue:0.5 alpha:1],
        [UIColor colorWithRed:0.1 green:0.3
                        blue:0.7 alpha:1],
    ];

    for(int i = 0; i < 3; i++) {
        UIButton *b = [UIButton
            buttonWithType:UIButtonTypeSystem];
        b.frame = CGRectMake(
            12 + i * (bw + 4), 44,
            bw, 34);
        b.backgroundColor = btnColors[i];
        b.layer.cornerRadius = 6;
        [b setTitle:btnTitles[i]
           forState:UIControlStateNormal];
        [b setTitleColor:UIColor.whiteColor
                forState:UIControlStateNormal];
        b.titleLabel.font =
            [UIFont monospacedSystemFontOfSize:10
                                        weight:UIFontWeightBold];
        SEL sel = NSSelectorFromString(btnSels[i]);
        [b addTarget:DisasmController.class
              action:sel
    forControlEvents:UIControlEventTouchUpInside];
        if(i == 0) b.tag = 200;
        [g_panel addSubview:b];
    }

    // TextView para el log
    CGFloat tv_y = 88;
    g_textview = [[UITextView alloc]
        initWithFrame:CGRectMake(
            8, tv_y,
            pw - 16, ph - tv_y - 8)];
    g_textview.backgroundColor =
        [UIColor colorWithRed:0.02
                        green:0.02
                         blue:0.02
                        alpha:1];
    g_textview.textColor =
        [UIColor colorWithRed:0
                        green:0.9
                         blue:0.5
                        alpha:1];
    g_textview.font =
        [UIFont monospacedSystemFontOfSize:9
                                    weight:UIFontWeightRegular];
    g_textview.editable = NO;
    g_textview.layer.cornerRadius = 6;
    g_textview.text =
        @"// Presiona TRACE para iniciar\n"
        @"// Se muestran los call stacks en vivo\n";
    [g_panel addSubview:g_textview];

    [g_window addSubview:g_panel];
    [g_window makeKeyAndVisible];

    // Timer para actualizar UI cada 500ms
    [NSTimer scheduledTimerWithTimeInterval:0.5
                                     target:[NSBlockOperation
                                        blockOperationWithBlock:^{
        update_ui();
    }]
                                   selector:@selector(main)
                                   userInfo:nil
                                    repeats:YES];
}

// ================================================
// CTOR
// ================================================
%ctor {
    g_log  = [NSMutableString new];
    g_lock = [NSLock new];

    find_base();

    // Info inicial en el log
    add_log([NSString stringWithFormat:
        @"Bundle: %@",
        NSBundle.mainBundle.bundleIdentifier]);
    add_log([NSString stringWithFormat:
        @"Base:   0x%llx", g_base]);
    add_log([NSString stringWithFormat:
        @"PID:    %d", getpid()]);
    add_log(@"─────────────────────────");
    add_log(@"Listo para trazar");

    // Iniciar thread del tracer
    atomic_store(&g_running, true);
    pthread_create(&g_thread, NULL,
                   tracer_thread, NULL);
    pthread_detach(g_thread);

    // Build UI en main thread
    dispatch_after(
        dispatch_time(DISPATCH_TIME_NOW,
            (int64_t)(3 * NSEC_PER_SEC)),
        dispatch_get_main_queue(), ^{
        build_ui();
    });
}


