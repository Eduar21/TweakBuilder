#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#include <mach/mach.h>
#include <mach/thread_act.h>
#include <mach-o/dyld.h>
#include <dlfcn.h>
#include <stdatomic.h>
#include <pthread.h>

#define SAMPLE_MS    150
#define MAX_LOG      1000
#define LOG_MAX_CHAR (512*1024)

// ── Estado global ──
static UIWindow        *g_window   = nil;
static UITextView      *g_textview = nil;
static UIButton        *g_fab      = nil;
static UIView          *g_panel    = nil;
static BOOL             g_expanded = NO;
static BOOL             g_tracing  = NO;
static atomic_bool      g_running  = false;
static pthread_t        g_thread;
static NSMutableString *g_log      = nil;
static NSLock          *g_lock     = nil;
static uint64_t         g_base     = 0;
static NSString        *g_appname  = nil;
static pthread_t        g_self_thread;

// ── Encontrar base de la app target ──
static void find_base(void) {
    uint32_t count = _dyld_image_count();
    for(uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if(!name) continue;
        if(strstr(name,"LiveProcess")) continue;
        if(strstr(name,"usr/lib"))    continue;
        if(strstr(name,"System"))     continue;
        if(strstr(name,"framework"))  continue;
        g_base = (uint64_t)_dyld_get_image_header(i);
        g_appname = [[NSString stringWithUTF8String:name]
            lastPathComponent];
        return;
    }
}

// ── Log ──
static void add_log(NSString *line) {
    [g_lock lock];
    if(g_log.length > LOG_MAX_CHAR)
        [g_log deleteCharactersInRange:
            NSMakeRange(0, g_log.length/2)];
    [g_log appendFormat:@"%@\n", line];
    [g_lock unlock];
}

// ── Tracer thread — samplea PCs de threads de la app ──
static void *tracer_thread(void *arg) {
    g_self_thread = pthread_self();

    while(atomic_load(&g_running)) {
        if(g_tracing) {
            thread_array_t threads;
            mach_msg_type_number_t count;
            kern_return_t kr =
                task_threads(mach_task_self(),
                             &threads, &count);
            if(kr != KERN_SUCCESS) {
                usleep(SAMPLE_MS * 1000);
                continue;
            }

            NSMutableString *entry =
                [NSMutableString new];

            for(uint32_t t = 0; t < count; t++) {
                // ── Filtrar nuestro propio thread ──
                pthread_t pt =
    pthread_from_mach_thread_np(threads[t]);
if(pt == g_self_thread) continue;
                // Obtener PC del thread
                arm_thread_state64_t state;
                mach_msg_type_number_t sc =
                    ARM_THREAD_STATE64_COUNT;
                kr = thread_get_state(
                    threads[t],
                    ARM_THREAD_STATE64,
                    (thread_state_t)&state,
                    &sc);
                if(kr != KERN_SUCCESS) continue;

                uint64_t pc =
                    arm_thread_state64_get_pc(state);
                if(pc == 0) continue;

                // ── Filtrar threads del sistema ──
                // Solo mostrar PCs dentro del
                // rango del binario de la app
                // o dylibs conocidas
                Dl_info info;
                if(!dladdr((void*)pc, &info)) continue;

                // Saltar si es del sistema
                const char *fname =
                    info.dli_fname ?: "";
                if(strstr(fname,"usr/lib"))   continue;
                if(strstr(fname,"System"))    continue;
                if(strstr(fname,"framework") &&
                   !strstr(fname,"instagram") &&
                   !strstr(fname,"Instagram")) continue;
                if(strstr(fname,"LiveProcess"))continue;

                // Resolver nombre
                NSString *sym;
                if(info.dli_sname) {
                    // Tiene símbolo — truncar si es largo
                    NSString *full = [NSString
                        stringWithUTF8String:
                        info.dli_sname];
                    sym = full.length > 60 ?
                        [full substringToIndex:60] :
                        full;
                } else {
                    // Sin símbolo — offset relativo
                    uint64_t off = g_base ?
                        pc - g_base : pc;
                    sym = [NSString stringWithFormat:
                        @"+0x%llx", off];
                }

                [entry appendFormat:
                    @"  [t%u] %@\n", t, sym];
            }

            if(entry.length > 0) {
                // Timestamp corto
                NSDateFormatter *df =
                    [NSDateFormatter new];
                df.dateFormat = @"HH:mm:ss.SSS";
                NSString *ts = [df stringFromDate:
                    [NSDate date]];
                add_log([NSString stringWithFormat:
                    @"─ %@", ts]);
                add_log(entry);
            }

            vm_deallocate(mach_task_self(),
                (vm_address_t)threads,
                count * sizeof(thread_act_t));
        }
        usleep(SAMPLE_MS * 1000);
    }
    return NULL;
}

// ── Actualizar UI ──
static void update_ui(void) {
    if(!g_expanded || !g_textview) return;
    [g_lock lock];
    NSString *text = [g_log copy];
    [g_lock unlock];

    NSArray *lines =
        [text componentsSeparatedByString:@"\n"];
    NSInteger start = lines.count > MAX_LOG ?
        lines.count - MAX_LOG : 0;
    NSString *display =
        [[lines subarrayWithRange:
            NSMakeRange(start, lines.count-start)]
         componentsJoinedByString:@"\n"];

    dispatch_async(dispatch_get_main_queue(), ^{
        g_textview.text = display;
        if(display.length > 0)
            [g_textview scrollRangeToVisible:
                NSMakeRange(display.length-1, 1)];
    });
}

// ── Passthrough Window ──
@interface PassthroughWindow : UIWindow
@end

@implementation PassthroughWindow
- (UIView *)hitTest:(CGPoint)point
          withEvent:(UIEvent *)event {
    // FAB
    if(g_fab && !g_fab.hidden) {
        CGPoint p = [self convertPoint:point
                                toView:g_fab];
        if([g_fab pointInside:p withEvent:event])
            return g_fab;
    }
    // Panel abierto
    if(g_panel && g_expanded && !g_panel.hidden) {
        CGPoint p = [self convertPoint:point
                                toView:g_panel];
        if([g_panel pointInside:p withEvent:event])
            return [g_panel hitTest:p
                          withEvent:event] ?: g_panel;
        // Toque FUERA del panel — cerrar
        dispatch_async(dispatch_get_main_queue(), ^{
            if(g_expanded) {
                g_expanded = NO;
                [UIView animateWithDuration:0.2
                                 animations:^{
                    g_panel.alpha = 0;
                } completion:^(BOOL done){
                    g_panel.hidden = YES;
                }];
                [g_fab setTitle:@"⚙"
                       forState:UIControlStateNormal];
            }
        });
    }
    return nil;
}
@end

// ── Acciones ──
@interface DisasmController : NSObject
@end
@implementation DisasmController

+ (void)togglePanel {
    g_expanded = !g_expanded;
    if(g_expanded) {
        g_panel.hidden = NO;
        g_panel.alpha  = 0;
        [UIView animateWithDuration:0.2 animations:^{
            g_panel.alpha = 1;
        }];
        [g_fab setTitle:@"✕"
               forState:UIControlStateNormal];
    } else {
        [UIView animateWithDuration:0.2
                         animations:^{
            g_panel.alpha = 0;
        } completion:^(BOOL done){
            g_panel.hidden = YES;
        }];
        [g_fab setTitle:@"⚙"
               forState:UIControlStateNormal];
    }
}

+ (void)toggleTrace {
    g_tracing = !g_tracing;
    UIButton *btn = (UIButton*)
        [g_panel viewWithTag:200];
    NSString *title = g_tracing ?
        @"⏸ PAUSE" : @"▶ TRACE";
    UIColor *color = g_tracing ?
        [UIColor colorWithRed:0.7 green:0.1
                        blue:0.1 alpha:1] :
        [UIColor colorWithRed:0.1 green:0.5
                        blue:0.1 alpha:1];
    [btn setTitle:title
         forState:UIControlStateNormal];
    btn.backgroundColor = color;
    if(!g_tracing) {
        add_log(@"── PAUSADO ──");
    } else {
        add_log(@"── TRACE INICIADO ──");
    }
}

+ (void)clearLog {
    [g_lock lock];
    [g_log setString:@""];
    [g_lock unlock];
    dispatch_async(dispatch_get_main_queue(), ^{
        g_textview.text = @"";
    });
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
    [text writeToFile:path atomically:YES
             encoding:NSUTF8StringEncoding
                error:nil];
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *a =
            [UIAlertController
                alertControllerWithTitle:@"Guardado"
                                 message:path
                          preferredStyle:
                            UIAlertControllerStyleAlert];
        [a addAction:[UIAlertAction
            actionWithTitle:@"OK"
                      style:UIAlertActionStyleDefault
                    handler:nil]];
        UIViewController *root =
            g_window.rootViewController;
        while(root.presentedViewController)
            root = root.presentedViewController;
        [root presentViewController:a
                           animated:YES
                         completion:nil];
    });
}

+ (void)fabDragged:(UIPanGestureRecognizer*)pan {
    CGPoint t = [pan translationInView:g_window];
    CGPoint newCenter = CGPointMake(
        g_fab.center.x + t.x,
        g_fab.center.y + t.y);
    // Mantener dentro de la pantalla
    CGFloat r = g_fab.bounds.size.width / 2;
    CGRect  b = g_window.bounds;
    newCenter.x = MAX(r, MIN(b.size.width-r,
                             newCenter.x));
    newCenter.y = MAX(r+44, MIN(b.size.height-r,
                               newCenter.y));
    g_fab.center = newCenter;
    [pan setTranslation:CGPointZero
                 inView:g_window];
}

@end

// ── Build UI ──
static void build_ui(void) {
    CGRect screen = UIScreen.mainScreen.bounds;
    CGFloat W = screen.size.width;
    CGFloat H = screen.size.height;

    g_window = [[PassthroughWindow alloc]
        initWithFrame:screen];
    g_window.windowLevel =
        UIWindowLevelAlert + 200;
    g_window.backgroundColor = UIColor.clearColor;

    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = UIColor.clearColor;
    g_window.rootViewController = vc;

    // ── FAB ──
    CGFloat fab_sz = 52;
    g_fab = [[UIButton alloc]
        initWithFrame:CGRectMake(
            W - fab_sz - 12,
            H * 0.38,
            fab_sz, fab_sz)];
    g_fab.backgroundColor =
        [UIColor colorWithRed:0
                        green:0.85
                         blue:0.45
                        alpha:0.93];
    g_fab.layer.cornerRadius = fab_sz / 2;
    g_fab.layer.shadowColor  =
        UIColor.blackColor.CGColor;
    g_fab.layer.shadowOpacity = 0.5;
    g_fab.layer.shadowRadius  = 8;
    g_fab.layer.shadowOffset  =
        CGSizeMake(0, 4);
    [g_fab setTitle:@"⚙"
           forState:UIControlStateNormal];
    g_fab.titleLabel.font =
        [UIFont systemFontOfSize:22
                          weight:UIFontWeightBold];
    [g_fab setTitleColor:UIColor.blackColor
                forState:UIControlStateNormal];
    [g_fab addTarget:DisasmController.class
              action:@selector(togglePanel)
    forControlEvents:UIControlEventTouchUpInside];

    UIPanGestureRecognizer *pan =
        [[UIPanGestureRecognizer alloc]
            initWithTarget:DisasmController.class
                    action:@selector(fabDragged:)];
    [g_fab addGestureRecognizer:pan];
    [g_window addSubview:g_fab];

    // ── Panel ──
    CGFloat pw = W - 24;
    CGFloat ph = H * 0.6;
    g_panel = [[UIView alloc]
        initWithFrame:CGRectMake(
            12, H - ph - 20, pw, ph)];
    g_panel.backgroundColor =
        [UIColor colorWithRed:0.04
                        green:0.04
                         blue:0.04
                        alpha:0.97];
    g_panel.layer.cornerRadius = 14;
    g_panel.layer.borderWidth  = 1;
    g_panel.layer.borderColor  =
        [UIColor colorWithRed:0
                        green:0.85
                         blue:0.45
                        alpha:0.4].CGColor;
    g_panel.hidden = YES;
    g_panel.alpha  = 0;

    // Header
    UILabel *hdr = [UILabel new];
    hdr.frame = CGRectMake(12, 12, pw-24, 22);
    hdr.text = [NSString stringWithFormat:
        @"◈ LIVE TRACER — %@", g_appname ?: @"app"];
    hdr.font = [UIFont monospacedSystemFontOfSize:11
                                           weight:UIFontWeightBold];
    hdr.textColor =
        [UIColor colorWithRed:0
                        green:0.85
                         blue:0.45
                        alpha:1];
    [g_panel addSubview:hdr];

    // Botones
    NSArray *titles  = @[@"▶ TRACE",
                         @"🗑 CLEAR",
                         @"💾 SAVE"];
    NSArray *sels    = @[@"toggleTrace",
                         @"clearLog",
                         @"saveLog"];
    NSArray *colors  = @[
        [UIColor colorWithRed:0.1 green:0.5
                        blue:0.1 alpha:1],
        [UIColor colorWithRed:0.3 green:0.3
                        blue:0.3 alpha:1],
        [UIColor colorWithRed:0.1 green:0.2
                        blue:0.6 alpha:1],
    ];
    CGFloat bw = (pw - 28) / 3.0;
    for(int i = 0; i < 3; i++) {
        UIButton *b = [UIButton
            buttonWithType:UIButtonTypeSystem];
        b.frame = CGRectMake(
            10 + i*(bw+4), 40, bw, 32);
        b.backgroundColor = colors[i];
        b.layer.cornerRadius = 6;
        [b setTitle:titles[i]
           forState:UIControlStateNormal];
        [b setTitleColor:UIColor.whiteColor
                forState:UIControlStateNormal];
        b.titleLabel.font =
            [UIFont monospacedSystemFontOfSize:10
                                        weight:UIFontWeightBold];
        [b addTarget:DisasmController.class
              action:NSSelectorFromString(sels[i])
    forControlEvents:UIControlEventTouchUpInside];
        if(i == 0) b.tag = 200;
        [g_panel addSubview:b];
    }

    // TextView
    CGFloat tv_y = 80;
    g_textview = [[UITextView alloc]
        initWithFrame:CGRectMake(
            6, tv_y,
            pw-12, ph-tv_y-8)];
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
    g_textview.layer.cornerRadius = 8;
    g_textview.text =
        @"// Toca TRACE para iniciar\n"
        @"// Solo threads de la app target\n";
    [g_panel addSubview:g_textview];
    [g_window addSubview:g_panel];
    [g_window makeKeyAndVisible];

    // Timer UI refresh
    NSTimer *timer = [NSTimer
        scheduledTimerWithTimeInterval:0.5
                               repeats:YES
                                 block:^(NSTimer *t){
        update_ui();
    }];
    [[NSRunLoop mainRunLoop] addTimer:timer
                              forMode:NSRunLoopCommonModes];
}

// ── CTOR ──
%ctor {
    g_log  = [NSMutableString new];
    g_lock = [NSLock new];

    find_base();

    add_log([NSString stringWithFormat:
        @"Bundle: %@",
        NSBundle.mainBundle.bundleIdentifier]);
    add_log([NSString stringWithFormat:
        @"Base:   0x%llx", g_base]);
    add_log([NSString stringWithFormat:
        @"App:    %@", g_appname ?: @"?"]);
    add_log(@"─────────────────────────");
    add_log(@"Ready. Toca TRACE.");

    atomic_store(&g_running, true);
    pthread_create(&g_thread, NULL,
                   tracer_thread, NULL);
    pthread_detach(g_thread);

    dispatch_after(
        dispatch_time(DISPATCH_TIME_NOW,
            (int64_t)(3 * NSEC_PER_SEC)),
        dispatch_get_main_queue(), ^{
        build_ui();
    });
}

