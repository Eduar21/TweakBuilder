#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AVFoundation/AVFoundation.h>
#import <objc/runtime.h>
#include <mach/mach.h>
#include <mach/thread_act.h>
#include <mach-o/dyld.h>
#include <dlfcn.h>
#include <stdatomic.h>
#include <pthread.h>
#include <mach-o/loader.h>
#include <stdlib.h>
#include <stdio.h>

#define SAMPLE_MS    150
#define MAX_LOG      1000
#define LOG_MAX_CHAR (512*1024)

// ── Estado global ──
static UIWindow    *g_window   = nil;
static UIButton    *g_fab      = nil;
static UIView      *g_panel    = nil;
static BOOL         g_expanded = NO;
static BOOL         g_tracing  = NO;
static atomic_bool  g_running  = false;
static pthread_t    g_thread;
static uint64_t     g_base     = 0;
static NSString    *g_appname  = nil;
static pthread_t    g_self_thread;

// Cuatro terminales: L=Log H=Hook D=Dump C=DRM/Crunchyroll
@class TermView;
static TermView    *g_termL = nil;
static TermView    *g_termH = nil;
static TermView    *g_termD = nil;
static TermView    *g_termC = nil;   // ← NUEVO
static int          g_tab   = 0;    // 0=L 1=H 2=D 3=C
static UIView      *g_ctlL = nil, *g_ctlH = nil, *g_ctlD = nil, *g_ctlC = nil;
static UITextField *g_hkCls = nil, *g_hkSel = nil, *g_hkVal = nil;
static UITextField *g_dumpField = nil;
static UISegmentedControl *g_seg = nil;
static BOOL         g_pick_mode = NO;
static UIView      *g_pickCatcher = nil;
static BOOL         g_recording = NO;
static IMP          g_orig_sendAction = NULL;
static IMP          g_orig_vda_rec    = NULL;
static char         g_app_bundle[1024] = {0};
static id           g_snap_token = nil;
static NSMutableArray *g_notif_obs = nil;
static id           g_drm_snap_token = nil;  // ← NUEVO

// ── Encontrar base de la app target ──
static uint32_t find_target_image(void) {
    uint32_t count = _dyld_image_count();
    for(uint32_t i = 0; i < count; i++) {
        const char *path = _dyld_get_image_name(i);
        if(!path) continue;
        if(strstr(path,"/System/"))      continue;
        if(strstr(path,"/usr/lib/"))     continue;
        if(strstr(path,"LiveContainer")) continue;
        if(strstr(path,"LiveProcess"))   continue;
        if(strstr(path,".framework/"))   continue;
        const char *base = strrchr(path,'/');
        if(!base || !base[1]) continue;
        base++;
        char needle[600];
        snprintf(needle, sizeof(needle), "/%s.app/", base);
        if(strstr(path, needle)) return i;
    }
    for(uint32_t i = 0; i < count; i++) {
        const char *path = _dyld_get_image_name(i);
        if(!path) continue;
        if(strstr(path,"/System/"))      continue;
        if(strstr(path,"/usr/lib/"))     continue;
        if(strstr(path,"LiveContainer")) continue;
        if(strstr(path,"LiveProcess"))   continue;
        if(strstr(path,".framework/"))   continue;
        if(strstr(path,".dylib"))        continue;
        if(strstr(path,".app/")) return i;
    }
    return 0;
}

static void find_base(void) {
    uint32_t i = find_target_image();
    const char *name = _dyld_get_image_name(i);
    g_base = (uint64_t)_dyld_get_image_header(i);
    g_appname = name
        ? [[NSString stringWithUTF8String:name] lastPathComponent]
        : @"app";
    const char *dotapp = name ? strstr(name, ".app/") : NULL;
    if(dotapp) {
        size_t len = (size_t)(dotapp - name) + 5;
        if(len < sizeof(g_app_bundle)) {
            memcpy(g_app_bundle, name, len);
            g_app_bundle[len] = 0;
        }
    }
}

// ── TermView ──
@interface TermView : UIView
@property(nonatomic,strong) UITextView *tv;
- (void)append:(NSString*)s;
- (void)clearAll;
- (NSString*)text;
@end

@implementation TermView
- (instancetype)initWithFrame:(CGRect)f {
    if((self = [super initWithFrame:f])) {
        _tv = [[UITextView alloc] initWithFrame:self.bounds];
        _tv.autoresizingMask =
            UIViewAutoresizingFlexibleWidth|UIViewAutoresizingFlexibleHeight;
        _tv.backgroundColor = [UIColor colorWithWhite:0.02 alpha:1];
        _tv.textColor = [UIColor colorWithRed:0.3 green:1 blue:0.45 alpha:1];
        _tv.font = [UIFont monospacedSystemFontOfSize:11
                                               weight:UIFontWeightRegular];
        _tv.editable = NO;
        _tv.layer.cornerRadius = 8;
        [self addSubview:_tv];
    }
    return self;
}
- (void)append:(NSString*)s {
    NSString *line = [s stringByAppendingString:@"\n"];
    dispatch_async(dispatch_get_main_queue(), ^{
        UITextView *tv = self.tv;
        CGFloat dist = tv.contentSize.height
            - tv.contentOffset.y - tv.bounds.size.height;
        BOOL atBottom = dist < 44;
        NSDictionary *attrs = @{
            NSFontAttributeName: tv.font,
            NSForegroundColorAttributeName: tv.textColor
        };
        [tv.textStorage appendAttributedString:
            [[NSAttributedString alloc] initWithString:line attributes:attrs]];
        if(tv.textStorage.length > 200000)
            [tv.textStorage deleteCharactersInRange:NSMakeRange(0,80000)];
        if(atBottom)
            [tv scrollRangeToVisible:NSMakeRange(tv.textStorage.length,0)];
    });
}
- (void)clearAll {
    dispatch_async(dispatch_get_main_queue(), ^{ self.tv.text = @""; });
}
- (NSString*)text { return self.tv.text ?: @""; }
@end

// ── Loggers ──
static void LOGL(NSString *s){ if(g_termL) [g_termL append:s]; }
static void LOGH(NSString *s){ if(g_termH) [g_termH append:s]; }
static void LOGD(NSString *s){ if(g_termD) [g_termD append:s]; }
static void LOGC(NSString *s){ if(g_termC) [g_termC append:s]; }
static void add_log(NSString *line){ LOGL(line); }

// ════════════════════════════════════════════
//  MÓDULO C — DRM / SCREENSHOT SCANNER
// ════════════════════════════════════════════

static void drm_screenshot_monitor_start(void) {
    if(g_drm_snap_token) {
        LOGC(@"[SS] Monitor ya activo");
        return;
    }
    NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
    __weak NSNotificationCenter *weakNC = nc;

    [nc addObserverForName:UIApplicationWillResignActiveNotification
        object:nil queue:[NSOperationQueue mainQueue]
        usingBlock:^(NSNotification *n) {
            LOGC(@"[SS] willResignActive (posible screenshot en curso)");
        }];

    g_drm_snap_token = [nc
        addObserverForName:UIApplicationUserDidTakeScreenshotNotification
        object:nil queue:[NSOperationQueue mainQueue]
        usingBlock:^(NSNotification *note) {
            LOGC(@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            LOGC(@"[SS] UIApplicationUserDidTakeScreenshotNotification");
            NSNotificationCenter *strongNC = weakNC;
            if(!strongNC) return;
            @try {
                id obsArray = [strongNC
                    performSelector:@selector(_observersForObject:name:)
                    withObject:nil
                    withObject:UIApplicationUserDidTakeScreenshotNotification];
                if([obsArray respondsToSelector:@selector(count)])
                    LOGC([NSString stringWithFormat:
                        @"  observers: %lu", (unsigned long)[obsArray count]]);
                for(id obs in obsArray)
                    LOGC([NSString stringWithFormat:@"  obs: %@", obs]);
            } @catch(NSException *e) {
                LOGC(@"  (no pude listar observers via API privada)");
            }
        }];
    LOGC(@"[DRM] Screenshot monitor activo — tomá una captura");
}

static void drm_scan_classes(void) {
    NSArray *kws = @[
        @"drm",@"DRM",@"widevine",@"Widevine",@"license",@"License",
        @"secure",@"Secure",@"playready",@"PlayReady",@"decr",@"Decr",
        @"crypto",@"Crypto",@"screenshot",@"Screenshot",@"protect",@"Protect",
        @"restrict",@"Restrict",@"hdcp",@"HDCP",@"fairplay",@"FairPlay",
        @"fps",@"FPS",@"token",@"Token",@"content",@"Content",
    ];
    LOGC(@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    LOGC(@"[SCAN] Clases relacionadas con DRM/Screenshot...");
    unsigned int total = 0;
    Class *all = objc_copyClassList(&total);
    NSMutableArray *hits = [NSMutableArray array];
    for(unsigned int i = 0; i < total; i++) {
        const char *img = class_getImageName(all[i]);
        if(!img||strstr(img,"/System/")||strstr(img,"/usr/lib/")) continue;
        NSString *cn = @(class_getName(all[i]));
        for(NSString *kw in kws) {
            if([cn rangeOfString:kw options:NSCaseInsensitiveSearch].location != NSNotFound) {
                [hits addObject:cn]; break;
            }
        }
    }
    if(all) free(all);
    [hits sortUsingSelector:@selector(compare:)];
    LOGC([NSString stringWithFormat:@"  %lu clases encontradas:", (unsigned long)hits.count]);
    for(NSString *cn in hits)
        LOGC([NSString stringWithFormat:@"  • %@", cn]);
}

static void drm_scan_avplayer(void) {
    LOGC(@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    LOGC(@"[AVPlayer] Métodos de protección...");
    NSArray *targets = @[
        @"AVPlayerLayer",@"AVPlayer",@"AVPlayerItem",
        @"AVContentKeySession",@"AVContentKeyRequest",
        @"AVAsset",@"AVPersistableContentKeyRequest",
    ];
    NSArray *kws = @[
        @"secure",@"protect",@"restrict",@"output",@"Output",
        @"screenshot",@"capture",@"screen",@"prevent",@"Prevent",
        @"disable",@"privacy",@"drm",@"license",@"fairplay",
        @"encrypted",@"Encrypt",@"hdcp",@"copy",@"Copy",@"airplay",
    ];
    for(NSString *tname in targets) {
        Class cls = NSClassFromString(tname);
        if(!cls) continue;
        NSMutableArray *found = [NSMutableArray array];
        unsigned int mc = 0;
        Method *ml = class_copyMethodList(cls, &mc);
        for(unsigned int i = 0; i < mc; i++) {
            NSString *sel = @(sel_getName(method_getName(ml[i])));
            for(NSString *kw in kws) {
                if([sel rangeOfString:kw options:NSCaseInsensitiveSearch].location != NSNotFound) {
                    [found addObject:[NSString stringWithFormat:
                        @"  -%@  [%s]", sel, method_getTypeEncoding(ml[i]) ?: "?"]];
                    break;
                }
            }
        }
        if(ml) free(ml);
        if(found.count) {
            LOGC([NSString stringWithFormat:@"[%@] %lu métodos:",
                tname, (unsigned long)found.count]);
            for(NSString *m in found) LOGC(m);
        }
    }
}

static void drm_find_player_views(void) {
    LOGC(@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    LOGC(@"[PLAYER] Clases con layerClass = AVPlayerLayer...");
    unsigned int total = 0;
    Class *all = objc_copyClassList(&total);
    for(unsigned int i = 0; i < total; i++) {
        const char *img = class_getImageName(all[i]);
        if(!img||strstr(img,"/System/")||strstr(img,"/usr/lib/")) continue;
        if(!class_getClassMethod(all[i], @selector(layerClass))) continue;
        @try {
            IMP layerClassIMP = method_getImplementation(class_getClassMethod(all[i], @selector(layerClass)));
            Class lc = ((Class(*)(id,SEL))layerClassIMP)(all[i], @selector(layerClass));
            if(lc == [AVPlayerLayer class] ||
               [NSStringFromClass(lc) containsString:@"AVPlayer"]) {
                LOGC([NSString stringWithFormat:@"  ✓ %s → %@",
                    class_getName(all[i]), NSStringFromClass(lc)]);
                unsigned int mc = 0;
                Method *ml = class_copyMethodList(all[i], &mc);
                for(unsigned int j = 0; j < mc; j++) {
                    NSString *sn = @(sel_getName(method_getName(ml[j])));
                    if([sn containsString:@"player"]||[sn containsString:@"Player"]||
                       [sn containsString:@"layer"]||[sn containsString:@"Layer"])
                        LOGC([NSString stringWithFormat:@"    -%@", sn]);
                }
                if(ml) free(ml);
            }
        } @catch(NSException *e) { continue; }
    }
    if(all) free(all);
}

static void drm_scan_got(void) {
    LOGC(@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    LOGC(@"[GOT] Símbolos DRM/screenshot en GOT...");
    NSArray *filters = @[
        @"screenshot",@"Screenshot",@"secure",@"Secure",
        @"protect",@"Protect",@"drm",@"DRM",@"restrict",
        @"airplay",@"AirPlay",@"prevent",@"output",@"disable",
    ];
    uint32_t target_idx = find_target_image();
    const struct mach_header_64 *mh =
        (const struct mach_header_64 *)_dyld_get_image_header(target_idx);
    intptr_t slide = _dyld_get_image_vmaddr_slide(target_idx);
    if(!mh) { LOGC(@"[GOT] no header"); return; }
    int found = 0;
    uint8_t *lc = (uint8_t *)mh + sizeof(struct mach_header_64);
    for(uint32_t i = 0; i < mh->ncmds; i++) {
        struct load_command *cmd = (struct load_command *)lc;
        if(cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            struct section_64 *sec =
                (struct section_64 *)(lc + sizeof(struct segment_command_64));
            for(uint32_t j = 0; j < seg->nsects; j++) {
                if(strncmp(sec[j].sectname,"__got",5)!=0 &&
                   strncmp(sec[j].sectname,"__la_symbol_ptr",15)!=0) continue;
                uint64_t *got = (uint64_t *)(uintptr_t)(sec[j].addr + slide);
                uint64_t n = sec[j].size / 8;
                for(uint64_t k = 0; k < n; k++) {
                    if(!got[k]) continue;
                    Dl_info info;
                    if(!dladdr((void*)got[k],&info)||!info.dli_sname) continue;
                    NSString *sym = @(info.dli_sname);
                    for(NSString *f in filters) {
                        if([sym rangeOfString:f options:NSCaseInsensitiveSearch].location != NSNotFound) {
                            LOGC([NSString stringWithFormat:
                                @"  0x%llx  %@", (uint64_t)&got[k], sym]);
                            found++; break;
                        }
                    }
                }
            }
        }
        lc += cmd->cmdsize;
    }
    LOGC([NSString stringWithFormat:@"[GOT] %d símbolos", found]);
}

static void drm_auto_hook_screenshot(void) {
    LOGC(@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    LOGC(@"[HOOK] Métodos relacionados con screenshot en la app...");
    unsigned int total = 0;
    Class *all = objc_copyClassList(&total);
    for(unsigned int i = 0; i < total; i++) {
        const char *img = class_getImageName(all[i]);
        if(!img||strstr(img,"/System/")||strstr(img,"/usr/lib/")) continue;
        unsigned int mc = 0;
        Method *ml = class_copyMethodList(all[i], &mc);
        for(unsigned int j = 0; j < mc; j++) {
            NSString *sn = @(sel_getName(method_getName(ml[j])));
            if([sn containsString:@"screenshot"]||
               [sn containsString:@"Screenshot"]||
               [sn containsString:@"didTakeScreenshot"]||
               [sn containsString:@"screenshotDetect"]) {
                LOGC([NSString stringWithFormat:
                    @"  %s → -%@", class_getName(all[i]), sn]);
                LOGC([NSString stringWithFormat:
                    @"    → Hook: Clase=%s  Sel=%@  Val=log",
                    class_getName(all[i]), sn]);
            }
        }
        if(ml) free(ml);
    }
    if(all) free(all);
    // Métodos AVPlayerLayer con restricción de output
    Class avpl = [AVPlayerLayer class];
    if(avpl) {
        unsigned int mc = 0;
        Method *ml = class_copyMethodList(avpl, &mc);
        for(unsigned int i = 0; i < mc; i++) {
            NSString *sn = @(sel_getName(method_getName(ml[i])));
            if([sn containsString:@"secure"]||[sn containsString:@"prevent"]||
               [sn containsString:@"output"]||[sn containsString:@"Output"]||
               [sn containsString:@"restrict"]||[sn containsString:@"privacy"]) {
                LOGC([NSString stringWithFormat:@"  AVPlayerLayer → -%@", sn]);
                LOGC([NSString stringWithFormat:
                    @"    → Hook: Clase=AVPlayerLayer  Sel=%@  Val=0", sn]);
            }
        }
        if(ml) free(ml);
    }
}

static void drm_full_scan(void) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        LOGC(@"╔══════════════════════════════════════╗");
        LOGC(@"║   CRUNCHYROLL DRM SCANNER  v1        ║");
        LOGC(@"╚══════════════════════════════════════╝");
        drm_screenshot_monitor_start();
        drm_scan_classes();
        drm_scan_avplayer();
        drm_find_player_views();
        drm_scan_got();
        drm_auto_hook_screenshot();
        LOGC(@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        LOGC(@"[DONE] Scan completo.");
        LOGC(@"Pasos:");
        LOGC(@" 1. Ve a H y hookea clases encontradas arriba");
        LOGC(@" 2. Abre un video en Crunchyroll");
        LOGC(@" 3. Toma screenshot → vuelve aquí a ver qué se llamó");
        LOGC(@" 4. Hookea el método que oculta el video (val=log primero)");
    });
}

// ════════════════════════════════════════════
//  CÓDIGO ORIGINAL (sin cambios)
// ════════════════════════════════════════════

static NSString *demangle(const char *sym) {
    if(!sym) return @"?";
    if(sym[0] != '_' || sym[1] != 'Z')
        return [NSString stringWithUTF8String:sym];
    typedef char* (*demangle_fn)(const char*, char*, size_t*, int*);
    static demangle_fn fn = NULL;
    if(!fn) fn = (demangle_fn)dlsym(RTLD_DEFAULT, "__cxa_demangle");
    if(fn) {
        int status = 0;
        char *d = fn(sym, NULL, NULL, &status);
        if(status == 0 && d) {
            NSString *r = [NSString stringWithUTF8String:d];
            free(d);
            if(r.length > 80) r = [[r substringToIndex:77] stringByAppendingString:@"..."];
            return r;
        }
    }
    NSString *orig = [NSString stringWithUTF8String:sym];
    return orig.length > 80 ? [[orig substringToIndex:77] stringByAppendingString:@"..."] : orig;
}

static NSString *categorize(NSString *sym) {
    if([sym containsString:@"quic"]||[sym containsString:@"QUIC"]||
       [sym containsString:@"socket"]||[sym containsString:@"Socket"]||
       [sym containsString:@"Network"]||[sym containsString:@"network"]||
       [sym containsString:@"http"]||[sym containsString:@"HTTP"])
        return @"[NET]";
    if([sym containsString:@"UI"]||[sym containsString:@"View"]||
       [sym containsString:@"Layout"]||[sym containsString:@"render"])
        return @"[UI ]";
    if([sym containsString:@"swift"]||[sym containsString:@"Swift"])
        return @"[SW ]";
    return @"[ . ]";
}

// ── GOT hook infrastructure ──
static bool got_write(void **slot, void *value) {
    if(!slot) return false;
    mach_port_t task = mach_task_self();
    vm_address_t page = (vm_address_t)slot & ~((vm_address_t)vm_page_size-1);
    kern_return_t kr = vm_protect(task, page, vm_page_size, false,
        VM_PROT_READ|VM_PROT_WRITE|VM_PROT_COPY);
    if(kr != KERN_SUCCESS) return false;
    *slot = value;
    vm_protect(task, page, vm_page_size, false, VM_PROT_READ);
    return true;
}
static bool got_hook(void **slot, void *replacement, void **out_original) {
    if(!slot) return false;
    void *orig = *slot;
    if(!got_write(slot, replacement)) return false;
    if(out_original) *out_original = orig;
    return true;
}
static bool got_unhook(void **slot, void *original) {
    return got_write(slot, original);
}
static void **find_got_slot(const char *want);
static long my_force0(void) { return 0; }
typedef struct { void **slot; void *orig; char name[128]; } force_hook_t;
#define MAX_FORCE 16
static force_hook_t g_force[MAX_FORCE];
static int          g_force_n = 0;
static BOOL force0_add(const char *name) {
    if(g_force_n >= MAX_FORCE) return NO;
    void **slot = find_got_slot(name);
    if(!slot) return NO;
    void *orig = NULL;
    if(!got_hook(slot, (void*)my_force0, &orig)) return NO;
    g_force[g_force_n].slot = slot;
    g_force[g_force_n].orig = orig;
    strncpy(g_force[g_force_n].name, name, 127);
    g_force[g_force_n].name[127] = 0;
    g_force_n++;
    return YES;
}
static void force0_clear_all(void) {
    for(int i = 0; i < g_force_n; i++) got_unhook(g_force[i].slot, g_force[i].orig);
    g_force_n = 0;
}

static void read_got_filtered(const char *filter) {
    BOOL all = (filter && filter[0]);
    uint32_t target_idx = find_target_image();
    const struct mach_header_64 *mh =
        (const struct mach_header_64 *)_dyld_get_image_header(target_idx);
    intptr_t slide = _dyld_get_image_vmaddr_slide(target_idx);
    if(!mh) { LOGD(@"[GOT] no encontré header"); return; }
    LOGD([NSString stringWithFormat:@"═══ GOT: %s ═══", all ? filter : "(primeras 40)"]);
    const int CAP = all ? 200 : 40;
    int shown = 0, matched = 0;
    uint8_t *lc = (uint8_t *)mh + sizeof(struct mach_header_64);
    for(uint32_t i = 0; i < mh->ncmds && shown < CAP; i++) {
        struct load_command *cmd = (struct load_command *)lc;
        if(cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            struct section_64 *sec =
                (struct section_64 *)(lc + sizeof(struct segment_command_64));
            for(uint32_t j = 0; j < seg->nsects && shown < CAP; j++) {
                BOOL is_got = strncmp(sec[j].sectname,"__got",5)==0;
                BOOL is_stubs = strncmp(sec[j].sectname,"__la_symbol_ptr",15)==0;
                if(!is_got && !is_stubs) continue;
                uint64_t *got = (uint64_t *)(uintptr_t)(sec[j].addr + slide);
                uint64_t n = sec[j].size / 8;
                for(uint64_t k = 0; k < n && shown < CAP; k++) {
                    uint64_t v = got[k];
                    if(!v) continue;
                    Dl_info info;
                    if(!dladdr((void*)v,&info)||!info.dli_sname) continue;
                    if(all && !strcasestr(info.dli_sname, filter)) continue;
                    matched++;
                    LOGD([NSString stringWithFormat:@"  0x%llx -> %@",
                        (uint64_t)&got[k], demangle(info.dli_sname)]);
                    shown++;
                }
            }
        }
        lc += cmd->cmdsize;
    }
    LOGD([NSString stringWithFormat:@"── match: %d ──", matched]);
}

static void **find_got_slot(const char *want) {
    uint32_t target_idx = find_target_image();
    const struct mach_header_64 *mh =
        (const struct mach_header_64 *)_dyld_get_image_header(target_idx);
    intptr_t slide = _dyld_get_image_vmaddr_slide(target_idx);
    if(!mh) return NULL;
    uint8_t *lc = (uint8_t *)mh + sizeof(struct mach_header_64);
    for(uint32_t i = 0; i < mh->ncmds; i++) {
        struct load_command *cmd = (struct load_command *)lc;
        if(cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            struct section_64 *sec =
                (struct section_64 *)(lc + sizeof(struct segment_command_64));
            for(uint32_t j = 0; j < seg->nsects; j++) {
                if(strncmp(sec[j].sectname,"__got",5)!=0 &&
                   strncmp(sec[j].sectname,"__la_symbol_ptr",15)!=0) continue;
                uint64_t *got = (uint64_t *)(uintptr_t)(sec[j].addr + slide);
                uint64_t n = sec[j].size / 8;
                for(uint64_t k = 0; k < n; k++) {
                    if(!got[k]) continue;
                    Dl_info info;
                    if(!dladdr((void*)got[k],&info)||!info.dli_sname) continue;
                    if(strcmp(info.dli_sname, want)==0) return (void **)&got[k];
                }
            }
        }
        lc += cmd->cmdsize;
    }
    return NULL;
}

// ── ObjC hook infrastructure ──
typedef struct {
    void   *cls;
    SEL     sel;
    IMP     orig;
    long long ival;
    double  dval;
    int     kind;   // 0=int 1=dbl 2=flt 3=void
    int     mode;   // 0=force 1=log
    char    enc[64];
} objchook_t;
#define MAX_OBJCHOOK 32
static objchook_t g_ohooks[MAX_OBJCHOOK];
static int        g_ohooks_n = 0;

static IMP swizzle_instance(Class cls, SEL sel, IMP newImp) {
    Method m = class_getInstanceMethod(cls, sel);
    if(!m) return NULL;
    return method_setImplementation(m, newImp);
}

static BOOL is_our_ui(id obj) {
    if(!g_window || !g_panel || !g_fab) return NO;
    UIView *v = (UIView *)obj;
    return (v == g_window || v == g_panel || v == g_fab ||
            [v isDescendantOfView:g_panel] || [v isDescendantOfView:g_fab]);
}

static objchook_t *ohook_for(id self, SEL cmd) {
    for(int i = 0; i < g_ohooks_n; i++)
        if((__bridge Class)g_ohooks[i].cls == object_getClass(self) &&
           g_ohooks[i].sel == cmd) return &g_ohooks[i];
    return NULL;
}

static long long ohook_int(id self, SEL _cmd) {
    objchook_t *h = ohook_for(self,_cmd);
    if(!h) return 0;
    if(is_our_ui(self)) return ((long long(*)(id,SEL))h->orig)(self,_cmd);
    if(h->mode == 1) {
        long long r = ((long long(*)(id,SEL))h->orig)(self,_cmd);
        LOGH([NSString stringWithFormat:@"[LOG] -%s → %lld", sel_getName(_cmd), r]);
        return r;
    }
    return h->ival;
}
static double ohook_dbl(id self, SEL _cmd) {
    objchook_t *h = ohook_for(self,_cmd);
    if(!h) return 0;
    if(is_our_ui(self)) return ((double(*)(id,SEL))h->orig)(self,_cmd);
    if(h->mode == 1) {
        double r = ((double(*)(id,SEL))h->orig)(self,_cmd);
        LOGH([NSString stringWithFormat:@"[LOG] -%s → %g", sel_getName(_cmd), r]);
        return r;
    }
    return h->dval;
}
static float ohook_flt(id self, SEL _cmd) {
    objchook_t *h = ohook_for(self,_cmd);
    if(!h) return 0;
    if(is_our_ui(self)) return ((float(*)(id,SEL))h->orig)(self,_cmd);
    if(h->mode == 1) {
        float r = ((float(*)(id,SEL))h->orig)(self,_cmd);
        LOGH([NSString stringWithFormat:@"[LOG] -%s → %g", sel_getName(_cmd),(double)r]);
        return r;
    }
    return (float)h->dval;
}

static NSString *decode_args(const char *enc, void **args, int maxn) {
    NSMethodSignature *sig = nil;
    @try { sig = [NSMethodSignature signatureWithObjCTypes:enc]; }
    @catch(__unused id e) { return @"?"; }
    if(!sig) return @"?";
    NSUInteger n = sig.numberOfArguments;
    NSMutableString *out = [NSMutableString string];
    for(NSUInteger i = 2; i < n && (int)(i-2) < maxn; i++) {
        const char *t = [sig getArgumentTypeAtIndex:i];
        void *raw = args[i-2];
        if(out.length) [out appendString:@", "];
        switch(t[0]) {
            case '@': { id obj = (__bridge id)raw; [out appendFormat:@"%@", obj?[obj description]:@"nil"]; break; }
            case 'B': case 'c': [out appendFormat:@"%d",(int)(intptr_t)raw]; break;
            case 'i': case 's': case 'l': case 'q': [out appendFormat:@"%ld",(long)(intptr_t)raw]; break;
            case 'I': case 'S': case 'L': case 'Q': [out appendFormat:@"%lu",(unsigned long)(uintptr_t)raw]; break;
            case ':': [out appendFormat:@":%s", raw?sel_getName((SEL)raw):"(null)"]; break;
            case '*': [out appendFormat:@"\"%s\"", raw?(char*)raw:"(null)"]; break;
            default: [out appendFormat:@"<%c %p>",t[0],raw]; break;
        }
    }
    return out.length ? out : @"";
}

static void ohook_void(id self, SEL _cmd,
                       void *a1, void *a2, void *a3,
                       void *a4, void *a5, void *a6) {
    objchook_t *h = ohook_for(self,_cmd);
    if(!h) return;
    typedef void (*fwd_t)(id,SEL,void*,void*,void*,void*,void*,void*);
    fwd_t orig = (fwd_t)h->orig;
    if(is_our_ui(self)) { orig(self,_cmd,a1,a2,a3,a4,a5,a6); return; }
    if(h->mode == 1) {
        static __thread int reent = 0;
        if(!reent) {
            reent = 1;
            void *args[6] = {a1,a2,a3,a4,a5,a6};
            LOGH([NSString stringWithFormat:@"[LOG] -%s(%@)",
                sel_getName(_cmd), decode_args(h->enc, args, 6)]);
            reent = 0;
        }
        orig(self,_cmd,a1,a2,a3,a4,a5,a6);
        return;
    }
    LOGH([NSString stringWithFormat:@"[BLOCK] -%s (swallow)", sel_getName(_cmd)]);
}

static Class resolve_class(const char *name, NSMutableArray *cands, NSString **resolved) {
    if(!name||!name[0]) return nil;
    Class direct = objc_getClass(name);
    if(direct) { if(resolved) *resolved = @(name); return direct; }
    NSString *dotTarget = [@"." stringByAppendingString:@(name)];
    unsigned int n = 0;
    Class *all = objc_copyClassList(&n);
    Class found = nil; int count = 0;
    for(unsigned int i = 0; i < n; i++) {
        const char *cn = class_getName(all[i]);
        if(!cn) continue;
        NSString *s = @(cn);
        if([s hasSuffix:dotTarget]) {
            count++;
            if(!found) found = all[i];
            if(cands && cands.count < 20) [cands addObject:s];
        }
    }
    if(all) free(all);
    if(count == 1) { if(resolved) *resolved = @(class_getName(found)); return found; }
    return nil;
}

static Class resolve_class_log(const char *name, void(*logfn)(NSString*)) {
    NSMutableArray *cands = [NSMutableArray array];
    NSString *resolved = nil;
    Class c = resolve_class(name, cands, &resolved);
    if(c) {
        if(![resolved isEqualToString:@(name)])
            logfn([NSString stringWithFormat:@"  resuelto: %@", resolved]);
        return c;
    }
    if(cands.count > 1) {
        logfn([NSString stringWithFormat:@"  ambiguo (%lu):", (unsigned long)cands.count]);
        for(NSString *s in cands) logfn([NSString stringWithFormat:@"    %@", s]);
    } else {
        logfn([NSString stringWithFormat:@"  clase no encontrada: %s", name]);
    }
    return nil;
}

static int objc_hook_add(const char *cn, const char *sn, const char *val, void(*logfn)(NSString*)) {
    if(g_ohooks_n >= MAX_OBJCHOOK) return -4;
    Class cls = resolve_class_log(cn, logfn);
    if(!cls) return -1;
    SEL sel = sel_registerName(sn);
    Method m = class_getInstanceMethod(cls, sel);
    if(!m) return -2;
    const char *enc = method_getTypeEncoding(m);
    if(!enc) return -3;
    objchook_t h; memset(&h, 0, sizeof(h));
    strncpy(h.enc, enc, sizeof(h.enc)-1);
    const char *renc = enc;
    while(*renc && strchr("rnNoORV", *renc)) renc++;
    char ret = *renc;
    h.cls = (__bridge void*)cls; h.sel = sel;
    h.mode = (val && strcmp(val,"log")==0) ? 1 : 0;
    IMP tramp = NULL;
    switch(ret) {
        case 'B': case 'c': case 'C':
        case 'i': case 's': case 'l': case 'q':
        case 'I': case 'S': case 'L': case 'Q':
            h.kind=0; h.ival=atoll(val); tramp=(IMP)ohook_int; break;
        case 'd': h.kind=1; h.dval=atof(val); tramp=(IMP)ohook_dbl; break;
        case 'f': h.kind=2; h.dval=atof(val); tramp=(IMP)ohook_flt; break;
        case 'v': h.kind=3; tramp=(IMP)ohook_void; break;
        default: return -3;
    }
    for(int i = 0; i < g_ohooks_n; i++) {
        if((__bridge Class)g_ohooks[i].cls == cls && g_ohooks[i].sel == sel) {
            g_ohooks[i].mode = h.mode; g_ohooks[i].ival = h.ival; g_ohooks[i].dval = h.dval;
            return h.kind == 3 ? (h.mode==1 ? 3 : 2) : 1;
        }
    }
    h.orig = swizzle_instance(cls, sel, tramp);
    if(!h.orig) return -2;
    g_ohooks[g_ohooks_n++] = h;
    return h.kind == 3 ? (h.mode==1 ? 3 : 2) : 1;
}

static void objc_hook_clear_all(void) {
    for(int i = 0; i < g_ohooks_n; i++) {
        Method m = class_getInstanceMethod((__bridge Class)g_ohooks[i].cls, g_ohooks[i].sel);
        if(m && g_ohooks[i].orig) method_setImplementation(m, g_ohooks[i].orig);
    }
    g_ohooks_n = 0;
}

static BOOL objc_hook_remove(const char *cn, const char *sn) {
    Class cls = resolve_class(cn, nil, NULL);
    if(!cls) return NO;
    SEL sel = sel_registerName(sn);
    for(int i = 0; i < g_ohooks_n; i++) {
        if((__bridge Class)g_ohooks[i].cls == cls && g_ohooks[i].sel == sel) {
            Method m = class_getInstanceMethod(cls, sel);
            if(m && g_ohooks[i].orig) method_setImplementation(m, g_ohooks[i].orig);
            for(int j = i; j < g_ohooks_n-1; j++) g_ohooks[j] = g_ohooks[j+1];
            g_ohooks_n--;
            return YES;
        }
    }
    return NO;
}

static BOOL force0_remove(const char *name) {
    for(int i = 0; i < g_force_n; i++) {
        if(strcmp(g_force[i].name, name)==0) {
            got_unhook(g_force[i].slot, g_force[i].orig);
            for(int j = i; j < g_force_n-1; j++) g_force[j] = g_force[j+1];
            g_force_n--;
            return YES;
        }
    }
    return NO;
}

static void hooks_list(void) {
    LOGH([NSString stringWithFormat:@"── activos: %d ObjC · %d GOT ──", g_ohooks_n, g_force_n]);
    for(int i = 0; i < g_ohooks_n; i++) {
        NSString *desc = g_ohooks[i].mode==1 ? @"LOG"
            : g_ohooks[i].kind==3 ? @"BLOCK"
            : g_ohooks[i].kind==0 ? [NSString stringWithFormat:@"→ %lld",g_ohooks[i].ival]
            : [NSString stringWithFormat:@"→ %g",g_ohooks[i].dval];
        LOGH([NSString stringWithFormat:@"  objc -[%s %s]  %@",
            class_getName((__bridge Class)g_ohooks[i].cls),
            sel_getName(g_ohooks[i].sel), desc]);
    }
    for(int i = 0; i < g_force_n; i++)
        LOGH([NSString stringWithFormat:@"  GOT  %s -> 0", g_force[i].name]);
}

static void dump_class_methods(const char *clsname) {
    if(!clsname||!clsname[0]) { LOGD(@"[DUMP] nombre vacío"); return; }
    Class cls = resolve_class_log(clsname, LOGD);
    if(!cls) return;
    LOGD([NSString stringWithFormat:@"═══ MÉTODOS %s ═══", class_getName(cls)]);
    unsigned int n = 0;
    Method *ml = class_copyMethodList(cls, &n);
    LOGD([NSString stringWithFormat:@"── instancia: %u ──", n]);
    for(unsigned int i = 0; i < n; i++)
        LOGD([NSString stringWithFormat:@"  -%s  %s",
            sel_getName(method_getName(ml[i])), method_getTypeEncoding(ml[i]) ?: ""]);
    if(ml) free(ml);
    Class meta = object_getClass((id)cls);
    n = 0;
    ml = class_copyMethodList(meta, &n);
    LOGD([NSString stringWithFormat:@"── clase: %u ──", n]);
    for(unsigned int i = 0; i < n; i++)
        LOGD([NSString stringWithFormat:@"  +%s  %s",
            sel_getName(method_getName(ml[i])), method_getTypeEncoding(ml[i]) ?: ""]);
    if(ml) free(ml);
}

static void dump_class_ivars(const char *clsname) {
    if(!clsname||!clsname[0]) { LOGD(@"[IVARS] nombre vacío"); return; }
    Class cls = resolve_class_log(clsname, LOGD);
    if(!cls) return;
    unsigned int n = 0;
    Ivar *iv = class_copyIvarList(cls, &n);
    LOGD([NSString stringWithFormat:@"═══ IVARS %s (%u) ═══", class_getName(cls), n]);
    for(unsigned int i = 0; i < n; i++)
        LOGD([NSString stringWithFormat:@"  +0x%lx %s  %s",
            (long)ivar_getOffset(iv[i]), ivar_getName(iv[i])?:"?",
            ivar_getTypeEncoding(iv[i])?:""]);
    if(iv) free(iv);
}

static void inspect_view(UIView *v) {
    LOGD(@"═══════ PICK ═══════");
    LOGD([NSString stringWithFormat:@"TOCASTE: %s", object_getClassName(v)]);
    NSMutableString *chain = [NSMutableString string];
    for(Class c = object_getClass(v); c; c = class_getSuperclass(c)) {
        [chain appendFormat:@"%s", class_getName(c)];
        if(class_getSuperclass(c)) [chain appendString:@" -> "];
    }
    LOGD([NSString stringWithFormat:@"  clase: %@", chain]);
    NSMutableString *sup = [NSMutableString string];
    UIView *p = v.superview; int n = 0;
    while(p && n < 4) {
        [sup appendFormat:@"%s", object_getClassName(p)];
        p = p.superview; n++;
        if(p && n < 4) [sup appendString:@" > "];
    }
    if(sup.length) LOGD([NSString stringWithFormat:@"  super: %@", sup]);
    LOGD(@"  BOOL directos:");
    unsigned int mc = 0;
    Method *ml = class_copyMethodList(object_getClass(v), &mc);
    int shown = 0;
    for(unsigned int i = 0; i < mc; i++) {
        const char *enc = method_getTypeEncoding(ml[i]);
        if(enc && enc[0]=='B') {
            LOGD([NSString stringWithFormat:@"    -%s", sel_getName(method_getName(ml[i]))]);
            shown++;
        }
    }
    if(ml) free(ml);
    if(!shown) LOGD(@"    (ninguno directo)");
    LOGD(@"════════════════════");
}

static int g_tree_count = 0;
static void dump_view_tree(UIView *v, int depth) {
    if(g_tree_count >= 400) return;
    g_tree_count++;
    NSMutableString *ind = [NSMutableString string];
    for(int i = 0; i < depth && i < 20; i++) [ind appendString:@"· "];
    NSString *flags = [NSString stringWithFormat:@"%@%@",
        v.hidden ? @" [HIDDEN]" : @"",
        v.alpha < 0.99 ? [NSString stringWithFormat:@" α=%.2f", v.alpha] : @""];
    CGRect f = v.frame;
    LOGD([NSString stringWithFormat:@"%@%s%@  {%.0f,%.0f %.0fx%.0f}",
        ind, object_getClassName(v), flags, f.origin.x, f.origin.y, f.size.width, f.size.height]);
    for(UIView *sub in v.subviews) dump_view_tree(sub, depth+1);
}

// ── Recorder ──
static IMP g_orig_sendAction_rec = NULL;
static void rec_install_once(void);
static void (*g_orig_vda)(id,SEL,id) = NULL;

static void hooked_vda(id self, SEL _cmd, id sender) {
    if(g_recording)
        LOGL([NSString stringWithFormat:@"[REC] viewDidAppear: %s",
            object_getClassName(self)]);
    if(g_orig_vda) g_orig_vda(self, _cmd, sender);
}

static void rec_install_once(void) {
    static BOOL done = NO;
    if(done) return; done = YES;
    Class vc = [UIViewController class];
    Method m = class_getInstanceMethod(vc, @selector(viewDidAppear:));
    if(m) g_orig_vda = (void(*)(id,SEL,id))method_setImplementation(m, (IMP)hooked_vda);
}

// ── Tracer ──
static void *tracer_thread(void *arg) {
    g_self_thread = pthread_self();
    while(atomic_load(&g_running)) {
        if(g_tracing) {
            thread_array_t threads;
            mach_msg_type_number_t count;
            kern_return_t kr = task_threads(mach_task_self(), &threads, &count);
            if(kr != KERN_SUCCESS) { usleep(SAMPLE_MS*1000); continue; }
            NSMutableString *entry = [NSMutableString new];
            for(uint32_t t = 0; t < count; t++) {
                pthread_t pt = pthread_from_mach_thread_np(threads[t]);
                if(pt == g_self_thread) continue;
                arm_thread_state64_t state;
                mach_msg_type_number_t sc = ARM_THREAD_STATE64_COUNT;
                kr = thread_get_state(threads[t], ARM_THREAD_STATE64, (thread_state_t)&state, &sc);
                if(kr != KERN_SUCCESS) continue;
                uint64_t pc = arm_thread_state64_get_pc(state);
                if(pc == 0) continue;
                Dl_info info;
                if(!dladdr((void*)pc, &info)) continue;
                const char *fname = info.dli_fname ?: "";
                if(strstr(fname,"/System/")||strstr(fname,"/usr/lib/")||
                   strstr(fname,"LiveProcess")||strstr(fname,"LiveContainer")) continue;
                NSString *sym = info.dli_sname ? demangle(info.dli_sname)
                    : [NSString stringWithFormat:@"+0x%llx", g_base ? pc-g_base : pc];
                [entry appendFormat:@"  %@ [t%u] %@\n", categorize(sym), t, sym];
            }
            if(entry.length > 0) {
                NSDateFormatter *df = [NSDateFormatter new];
                df.dateFormat = @"HH:mm:ss.SSS";
                add_log([NSString stringWithFormat:@"─ %@", [df stringFromDate:[NSDate date]]]);
                add_log(entry);
            }
            vm_deallocate(mach_task_self(), (vm_address_t)threads, count*sizeof(thread_act_t));
        }
        usleep(SAMPLE_MS*1000);
    }
    return NULL;
}

// ── PassthroughWindow ──
@interface PassthroughWindow : UIWindow
@end
@implementation PassthroughWindow
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    if(self.rootViewController.presentedViewController)
        return [super hitTest:point withEvent:event];
    if(g_fab && !g_fab.hidden) {
        CGPoint p = [self convertPoint:point toView:g_fab];
        if([g_fab pointInside:p withEvent:event]) return g_fab;
    }
    if(g_pick_mode && g_pickCatcher && !g_pickCatcher.hidden) {
        if(g_panel && g_expanded && !g_panel.hidden) {
            CGPoint p = [self convertPoint:point toView:g_panel];
            if([g_panel pointInside:p withEvent:event])
                return [g_panel hitTest:p withEvent:event] ?: g_panel;
        }
        return g_pickCatcher;
    }
    if(g_panel && g_expanded && !g_panel.hidden) {
        CGPoint p = [self convertPoint:point toView:g_panel];
        if([g_panel pointInside:p withEvent:event])
            return [g_panel hitTest:p withEvent:event] ?: g_panel;
        dispatch_async(dispatch_get_main_queue(), ^{
            if(g_expanded) {
                [g_panel endEditing:YES];
                g_expanded = NO;
                [UIView animateWithDuration:0.2 animations:^{ g_panel.alpha=0; }
                    completion:^(BOOL done){ g_panel.hidden=YES; }];
                [g_fab setTitle:@"=" forState:UIControlStateNormal];
            }
        });
    }
    return nil;
}
@end

// ── DisasmController ──
@interface DisasmController : NSObject
@end
@implementation DisasmController

+ (void)repositionPanel {
    if(!g_panel||!g_fab) return;
    CGFloat H  = g_window.bounds.size.height;
    CGFloat ph = g_panel.frame.size.height;
    CGFloat pw = g_panel.frame.size.width;
    CGFloat px = g_panel.frame.origin.x;
    CGRect  fab = g_fab.frame;
    CGFloat py = (g_fab.center.y < H/2)
        ? CGRectGetMaxY(fab)+10
        : CGRectGetMinY(fab)-ph-10;
    CGFloat topSafe = 50, botSafe = H-10;
    if(py+ph > botSafe) py = botSafe-ph;
    if(py < topSafe)    py = topSafe;
    g_panel.transform = CGAffineTransformIdentity;
    g_panel.frame = CGRectMake(px, py, pw, ph);
}

+ (void)togglePanel {
    g_expanded = !g_expanded;
    if(g_expanded) {
        [self repositionPanel];
        g_panel.hidden = NO; g_panel.alpha = 0;
        [UIView animateWithDuration:0.2 animations:^{ g_panel.alpha=1; }];
        [g_fab setTitle:@"✕" forState:UIControlStateNormal];
    } else {
        [g_panel endEditing:YES];
        [UIView animateWithDuration:0.2 animations:^{ g_panel.alpha=0; }
            completion:^(BOOL done){ g_panel.hidden=YES; }];
        [g_fab setTitle:@"=" forState:UIControlStateNormal];
    }
}

// ← MODIFICADO: ahora soporta 4 pestañas
+ (void)switchTab:(UISegmentedControl*)seg {
    g_tab = (int)seg.selectedSegmentIndex;
    g_ctlL.hidden  = (g_tab != 0);
    g_ctlH.hidden  = (g_tab != 1);
    g_ctlD.hidden  = (g_tab != 2);
    g_ctlC.hidden  = (g_tab != 3);
    g_termL.hidden = (g_tab != 0);
    g_termH.hidden = (g_tab != 1);
    g_termD.hidden = (g_tab != 2);
    g_termC.hidden = (g_tab != 3);
    if(g_tab != 1 && g_tab != 2) [g_panel endEditing:YES];
}

// ── Pestaña L ──
+ (void)toggleTrace {
    g_tracing = !g_tracing;
    UIButton *btn = (UIButton*)[g_panel viewWithTag:200];
    [btn setTitle:(g_tracing ? @"PAUSE" : @"TRACE") forState:UIControlStateNormal];
    btn.backgroundColor = g_tracing
        ? [UIColor colorWithRed:0.7 green:0.1 blue:0.1 alpha:1]
        : [UIColor colorWithRed:0.1 green:0.5 blue:0.1 alpha:1];
    LOGL(g_tracing ? @"── TRACE INICIADO ──" : @"── PAUSADO ──");
}
+ (void)clearL { [g_termL clearAll]; }
+ (void)saveL {
    NSString *text = [g_termL text];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,NSUserDomainMask,YES).firstObject;
    NSString *path = [docs stringByAppendingPathComponent:@"live_trace.txt"];
    [text writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *a = [UIAlertController
            alertControllerWithTitle:@"Guardado" message:path
            preferredStyle:UIAlertControllerStyleAlert];
        [a addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        UIViewController *root = g_window.rootViewController;
        while(root.presentedViewController) root = root.presentedViewController;
        [root presentViewController:a animated:YES completion:nil];
    });
}
+ (void)copyL { UIPasteboard.generalPasteboard.string = [g_termL text]; LOGL(@"[L] copiado"); }
+ (void)recToggle {
    g_recording = !g_recording;
    if(g_recording) rec_install_once();
    UIButton *b = (UIButton*)[g_panel viewWithTag:210];
    [b setTitle:(g_recording ? @"● REC" : @"REC") forState:UIControlStateNormal];
    b.backgroundColor = g_recording
        ? [UIColor colorWithRed:0.85 green:0.1 blue:0.1 alpha:1]
        : [UIColor colorWithRed:0.4 green:0.2 blue:0.2 alpha:1];
    LOGL(g_recording ? @"[REC] grabando" : @"[REC] detenido");
}

// ── Pestaña H ──
+ (void)hookRun {
    NSString *c = g_hkCls.text, *s = g_hkSel.text, *v = g_hkVal.text;
    [g_panel endEditing:YES];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        if(!c.length) { LOGH(@"[H] escribí una clase o símbolo"); return; }
        if(s.length) {
            const char *val = v.length ? v.UTF8String : "0";
            int rc = objc_hook_add(c.UTF8String, s.UTF8String, val, LOGH);
            switch(rc) {
                case 1: LOGH([NSString stringWithFormat:@"[H] -[%@ %@] → %@ FORCE ON", c, s, v.length?v:@"0"]); break;
                case 2: LOGH([NSString stringWithFormat:@"[H] -[%@ %@] BLOCK ON", c, s]); break;
                case 3: LOGH([NSString stringWithFormat:@"[H] -[%@ %@] LOG ON", c, s]); break;
                case -1: break;
                case -2: LOGH([NSString stringWithFormat:@"[H] método no encontrado: -[%@ %@]", c, s]); break;
                case -3: LOGH(@"[H] retorno no soportado"); break;
                case -4: LOGH(@"[H] tabla llena"); break;
            }
        } else {
            if(force0_add(c.UTF8String))
                LOGH([NSString stringWithFormat:@"[H] (GOT) %@ -> 0 (activos: %d)", c, g_force_n]);
            else
                LOGH([NSString stringWithFormat:@"[H] %@ no está en el GOT", c]);
        }
    });
}
+ (void)hookStop {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        objc_hook_clear_all(); force0_clear_all(); LOGH(@"[H] todos los hooks quitados");
    });
}
+ (void)hookOff {
    NSString *c = g_hkCls.text, *s = g_hkSel.text;
    [g_panel endEditing:YES];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        if(!c.length) { LOGH(@"[H] escribí clase o símbolo a quitar"); return; }
        BOOL ok = s.length ? objc_hook_remove(c.UTF8String,s.UTF8String) : force0_remove(c.UTF8String);
        LOGH(ok ? [NSString stringWithFormat:@"[H] quitado: %@ %@", c, s.length?s:@"(GOT)"]
                : @"[H] no encontré ese hook activo");
    });
}
+ (void)hookList {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{ hooks_list(); });
}
+ (void)clearH { [g_termH clearAll]; }

// ── Pestaña D ──
+ (void)dDump {
    NSString *n = g_dumpField.text; [g_dumpField resignFirstResponder];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        dump_class_methods(n.UTF8String);
    });
}
+ (void)dIvars {
    NSString *n = g_dumpField.text; [g_dumpField resignFirstResponder];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        dump_class_ivars(n.UTF8String);
    });
}
+ (void)dGot {
    NSString *f = g_dumpField.text; [g_dumpField resignFirstResponder];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        read_got_filtered(f.length ? f.UTF8String : NULL);
    });
}
+ (void)clearD { [g_termD clearAll]; }
+ (void)dTree {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *appwin = nil;
        NSArray *wins = g_window.windowScene.windows;
        for(UIWindow *w in wins) if(w!=g_window && w.isKeyWindow) { appwin=w; break; }
        if(!appwin) for(UIWindow *w in wins) if(w!=g_window && !w.hidden) { appwin=w; break; }
        LOGD(@"═══════ VIEW TREE ═══════");
        if(!appwin) { LOGD(@"[TREE] no encontré ventana"); return; }
        g_tree_count = 0;
        dump_view_tree(appwin, 0);
        LOGD([NSString stringWithFormat:@"── %d vistas ──", g_tree_count]);
    });
}
+ (void)snapToggle {
    NSNotificationCenter *nc = NSNotificationCenter.defaultCenter;
    UIButton *b = (UIButton*)[g_panel viewWithTag:220];
    if(g_snap_token) {
        [nc removeObserver:g_snap_token]; g_snap_token = nil;
        b.backgroundColor = [UIColor colorWithRed:0.2 green:0.4 blue:0.4 alpha:1];
        LOGD(@"[SNAP] apagado"); return;
    }
    g_snap_token = [nc
        addObserverForName:UIApplicationUserDidTakeScreenshotNotification
        object:nil queue:[NSOperationQueue mainQueue]
        usingBlock:^(__unused NSNotification *note){
            LOGD(@"[SNAP] screenshot → dump:");
            [DisasmController dTree];
        }];
    b.backgroundColor = [UIColor colorWithRed:0.1 green:0.65 blue:0.4 alpha:1];
    LOGD(@"[SNAP] activo");
}
+ (void)notifWatch {
    NSString *name = g_dumpField.text; [g_dumpField resignFirstResponder];
    NSNotificationCenter *nc = NSNotificationCenter.defaultCenter;
    if(!g_notif_obs) g_notif_obs = [NSMutableArray array];
    if(!name.length) {
        for(id t in g_notif_obs) [nc removeObserver:t];
        [g_notif_obs removeAllObjects];
        LOGD(@"[NOTIF] watchers borrados"); return;
    }
    id token = [nc addObserverForName:name object:nil queue:[NSOperationQueue mainQueue]
        usingBlock:^(NSNotification *note){
            LOGD([NSString stringWithFormat:@"[NOTIF] %@  obj=%s  userInfo=%@",
                note.name, note.object?object_getClassName(note.object):"nil",
                note.userInfo?:@{}]);
        }];
    [g_notif_obs addObject:token];
    LOGD([NSString stringWithFormat:@"[NOTIF] observando '%@'", name]);
}

// ── Pestaña C — DRM/Crunchyroll ← NUEVOS ──
+ (void)cScanFull  { drm_full_scan(); }
+ (void)cSSMonitor { drm_screenshot_monitor_start(); }
+ (void)cClear     { [g_termC clearAll]; }

// ── Pick ──
+ (void)startPick { g_pick_mode=YES; if(g_pickCatcher) g_pickCatcher.hidden=NO; LOGD(@"[PICK] tocá algo"); }
+ (void)endPick   { g_pick_mode=NO;  if(g_pickCatcher) g_pickCatcher.hidden=YES; }
+ (void)pickToggle { if(g_pick_mode) { [self endPick]; LOGD(@"[PICK] cancelado"); } else [self startPick]; }
+ (void)pickTapped:(UITapGestureRecognizer*)g {
    CGPoint pt = [g locationInView:g_window];
    UIWindow *appwin = nil;
    for(UIWindow *w in g_window.windowScene.windows) if(w!=g_window) { appwin=w; break; }
    UIView *hit = appwin ? [appwin hitTest:pt withEvent:nil] : nil;
    [self endPick];
    g_seg.selectedSegmentIndex = 2;
    [self switchTab:g_seg];
    if(!hit) { LOGD(@"[PICK] no encontré vista ahí"); return; }
    inspect_view(hit);
    NSString *cn = @(object_getClassName(hit));
    g_hkCls.text = cn;
    UIPasteboard.generalPasteboard.string = cn;
    LOGD([NSString stringWithFormat:@"  → clase en H: %@", cn]);
}

// ── FAB drag ──
+ (void)fabDragged:(UIPanGestureRecognizer*)pan {
    CGPoint t = [pan translationInView:g_window];
    CGPoint c = CGPointMake(g_fab.center.x+t.x, g_fab.center.y+t.y);
    CGFloat r = g_fab.bounds.size.width/2;
    CGRect  b = g_window.bounds;
    c.x = MAX(r, MIN(b.size.width-r, c.x));
    c.y = MAX(r+44, MIN(b.size.height-r, c.y));
    g_fab.center = c;
    [pan setTranslation:CGPointZero inView:g_window];
    if(g_expanded) [self repositionPanel];
}

// ── Keyboard ──
+ (void)kbShow:(NSNotification*)n {
    CGRect kb = [n.userInfo[UIKeyboardFrameEndUserInfoKey] CGRectValue];
    CGFloat overlap = CGRectGetMaxY(g_panel.frame) - kb.origin.y + 8;
    if(overlap > 0)
        [UIView animateWithDuration:0.25 animations:^{
            g_panel.transform = CGAffineTransformMakeTranslation(0,-overlap);
        }];
}
+ (void)kbHide:(NSNotification*)n {
    [UIView animateWithDuration:0.25 animations:^{ g_panel.transform=CGAffineTransformIdentity; }];
}
@end

// ── UI Helpers ──
static UIButton *mkbtn(NSString *title, SEL sel, CGRect frame, UIColor *color) {
    UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
    b.frame = frame; b.backgroundColor = color; b.layer.cornerRadius = 6;
    [b setTitle:title forState:UIControlStateNormal];
    [b setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    b.titleLabel.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightBold];
    [b addTarget:DisasmController.class action:sel forControlEvents:UIControlEventTouchUpInside];
    return b;
}
static UITextField *mkfield(NSString *ph, CGRect frame) {
    UITextField *tf = [[UITextField alloc] initWithFrame:frame];
    tf.placeholder = ph;
    tf.backgroundColor = [UIColor colorWithWhite:0.12 alpha:1];
    tf.textColor = UIColor.whiteColor;
    tf.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightRegular];
    tf.layer.cornerRadius = 6;
    tf.autocorrectionType = UITextAutocorrectionTypeNo;
    tf.autocapitalizationType = UITextAutocapitalizationTypeNone;
    tf.clearButtonMode = UITextFieldViewModeWhileEditing;
    UIView *pad = [[UIView alloc] initWithFrame:CGRectMake(0,0,10,1)];
    tf.leftView = pad; tf.leftViewMode = UITextFieldViewModeAlways;
    return tf;
}

// ── Build UI ──
static void build_ui(void) {
    UIWindowScene *scene = nil;
    for(UIScene *s in UIApplication.sharedApplication.connectedScenes) {
        if([s isKindOfClass:UIWindowScene.class] &&
           s.activationState == UISceneActivationStateForegroundActive) {
            scene = (UIWindowScene *)s; break;
        }
    }
    if(!scene) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1*NSEC_PER_SEC)),
            dispatch_get_main_queue(), ^{ build_ui(); });
        return;
    }

    CGRect screen = scene.coordinateSpace.bounds;
    CGFloat W = screen.size.width, H = screen.size.height;

    g_window = [[PassthroughWindow alloc] initWithWindowScene:scene];
    g_window.frame = screen;
    g_window.windowLevel = UIWindowLevelNormal + 1;
    g_window.backgroundColor = UIColor.clearColor;
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = UIColor.clearColor;
    g_window.rootViewController = vc;

    // FAB
    CGFloat fab_sz = 52;
    g_fab = [[UIButton alloc] initWithFrame:CGRectMake(W-fab_sz-12, H*0.38, fab_sz, fab_sz)];
    g_fab.backgroundColor = [UIColor colorWithRed:0 green:0.85 blue:0.45 alpha:0.93];
    g_fab.layer.cornerRadius = fab_sz/2;
    g_fab.layer.shadowColor = UIColor.blackColor.CGColor;
    g_fab.layer.shadowOpacity = 0.5;
    g_fab.layer.shadowRadius = 8;
    g_fab.layer.shadowOffset = CGSizeMake(0,4);
    [g_fab setTitle:@"=" forState:UIControlStateNormal];
    g_fab.titleLabel.font = [UIFont systemFontOfSize:22 weight:UIFontWeightBold];
    [g_fab setTitleColor:UIColor.blackColor forState:UIControlStateNormal];
    [g_fab addTarget:DisasmController.class action:@selector(togglePanel)
        forControlEvents:UIControlEventTouchUpInside];
    [g_fab addGestureRecognizer:[[UIPanGestureRecognizer alloc]
        initWithTarget:DisasmController.class action:@selector(fabDragged:)]];
    [g_window addSubview:g_fab];

    // Panel
    CGFloat pw = W-24, ph = H*0.74;
    g_panel = [[UIView alloc] initWithFrame:CGRectMake(12, H-ph-20, pw, ph)];
    g_panel.backgroundColor = [UIColor colorWithWhite:0.04 alpha:0.97];
    g_panel.layer.cornerRadius = 14;
    g_panel.layer.borderWidth = 1;
    g_panel.layer.borderColor = [UIColor colorWithRed:0 green:0.85 blue:0.45 alpha:0.4].CGColor;
    g_panel.hidden = YES; g_panel.alpha = 0;

    // Header
    UILabel *hdr = [UILabel new];
    hdr.frame = CGRectMake(12, 10, pw-24, 20);
    hdr.text = [NSString stringWithFormat:@"◈ FLEXING v3 — %@", g_appname ?: @"app"];
    hdr.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightBold];
    hdr.textColor = [UIColor colorWithRed:0 green:0.85 blue:0.45 alpha:1];
    [g_panel addSubview:hdr];

    // ← MODIFICADO: 4 pestañas L/H/D/C
    UISegmentedControl *seg = [[UISegmentedControl alloc]
        initWithItems:@[@"L", @"H", @"D", @"C"]];
    seg.frame = CGRectMake(10, 36, pw-20, 30);
    seg.selectedSegmentIndex = 0;
    [seg addTarget:DisasmController.class action:@selector(switchTab:)
        forControlEvents:UIControlEventValueChanged];
    [g_panel addSubview:seg];
    g_seg = seg;

    CGFloat ctl_y = 74, term_y = 146, term_h = ph-term_y-8;
    CGFloat b3 = (pw-28)/3.0;

    UIColor *cGreen  = [UIColor colorWithRed:0.1 green:0.5 blue:0.1 alpha:1];
    UIColor *cGray   = [UIColor colorWithWhite:0.3 alpha:1];
    UIColor *cBlue   = [UIColor colorWithRed:0.1 green:0.2 blue:0.6 alpha:1];
    UIColor *cSlate  = [UIColor colorWithRed:0.35 green:0.35 blue:0.4 alpha:1];
    UIColor *cOrange = [UIColor colorWithRed:0.7 green:0.4 blue:0.05 alpha:1];
    UIColor *cRed    = [UIColor colorWithRed:0.6 green:0.12 blue:0.12 alpha:1];
    UIColor *cTeal   = [UIColor colorWithRed:0.05 green:0.5 blue:0.5 alpha:1];
    UIColor *cOlive  = [UIColor colorWithRed:0.35 green:0.35 blue:0.15 alpha:1];
    UIColor *cPurple = [UIColor colorWithRed:0.4 green:0.1 blue:0.5 alpha:1];
    UIColor *cCyan   = [UIColor colorWithRed:0.05 green:0.55 blue:0.65 alpha:1];

    // ── Controles L ──
    g_ctlL = [[UIView alloc] initWithFrame:CGRectMake(0, ctl_y, pw, 40)];
    { CGFloat w = (pw-36)/5.0;
      UIButton *bt = mkbtn(@"TRACE", @selector(toggleTrace), CGRectMake(10,0,w,32), cGreen); bt.tag=200; [g_ctlL addSubview:bt];
      UIButton *rb = mkbtn(@"REC", @selector(recToggle), CGRectMake(10+(w+4),0,w,32), [UIColor colorWithRed:0.4 green:0.2 blue:0.2 alpha:1]); rb.tag=210; [g_ctlL addSubview:rb];
      [g_ctlL addSubview:mkbtn(@"CLEAR", @selector(clearL), CGRectMake(10+2*(w+4),0,w,32), cGray)];
      [g_ctlL addSubview:mkbtn(@"SAVE",  @selector(saveL),  CGRectMake(10+3*(w+4),0,w,32), cBlue)];
      [g_ctlL addSubview:mkbtn(@"COPY",  @selector(copyL),  CGRectMake(10+4*(w+4),0,w,32), cSlate)]; }
    [g_panel addSubview:g_ctlL];

    // ── Controles H ──
    g_ctlH = [[UIView alloc] initWithFrame:CGRectMake(0, ctl_y, pw, 190)];
    g_hkCls = mkfield(@"Clase  ·  o símbolo C para GOT", CGRectMake(10,0,pw-20,32));
    g_hkSel = mkfield(@"selector  ·  vacío = GOT",       CGRectMake(10,38,pw-20,32));
    g_hkVal = mkfield(@"retorno (0·1·3.14·log)",          CGRectMake(10,76,pw-20,32));
    [g_ctlH addSubview:g_hkCls]; [g_ctlH addSubview:g_hkSel]; [g_ctlH addSubview:g_hkVal];
    [g_ctlH addSubview:mkbtn(@"RUN",  @selector(hookRun),  CGRectMake(10,116,b3,30), cOrange)];
    [g_ctlH addSubview:mkbtn(@"OFF",  @selector(hookOff),  CGRectMake(10+(b3+4),116,b3,30), cSlate)];
    [g_ctlH addSubview:mkbtn(@"STOP", @selector(hookStop), CGRectMake(10+2*(b3+4),116,b3,30), cRed)];
    [g_ctlH addSubview:mkbtn(@"LIST", @selector(hookList), CGRectMake(10,150,b3,30), cGreen)];
    [g_ctlH addSubview:mkbtn(@"CLEAR",@selector(clearH),   CGRectMake(10+(b3+4),150,b3,30), cGray)];
    g_ctlH.hidden = YES;
    [g_panel addSubview:g_ctlH];

    // ── Controles D ──
    g_ctlD = [[UIView alloc] initWithFrame:CGRectMake(0, ctl_y, pw, 108)];
    g_dumpField = mkfield(@"clase · filtro GOT · nombre de notif", CGRectMake(10,0,pw-20,32));
    [g_ctlD addSubview:g_dumpField];
    { CGFloat w = (pw-36)/5.0;
      [g_ctlD addSubview:mkbtn(@"DUMP",  @selector(dDump),    CGRectMake(10,38,w,30), cTeal)];
      [g_ctlD addSubview:mkbtn(@"IVARS", @selector(dIvars),   CGRectMake(10+(w+4),38,w,30), cOlive)];
      [g_ctlD addSubview:mkbtn(@"GOT",   @selector(dGot),     CGRectMake(10+2*(w+4),38,w,30), cPurple)];
      [g_ctlD addSubview:mkbtn(@"PICK",  @selector(pickToggle),CGRectMake(10+3*(w+4),38,w,30), [UIColor colorWithRed:0.1 green:0.6 blue:0.3 alpha:1])];
      [g_ctlD addSubview:mkbtn(@"TREE",  @selector(dTree),    CGRectMake(10+4*(w+4),38,w,30), [UIColor colorWithRed:0.2 green:0.45 blue:0.55 alpha:1])];
      CGFloat hw = (pw-24)/2.0;
      UIButton *sb = mkbtn(@"SNAP (screenshot→árbol)", @selector(snapToggle), CGRectMake(10,72,hw,30), [UIColor colorWithRed:0.2 green:0.4 blue:0.4 alpha:1]); sb.tag=220;
      [g_ctlD addSubview:sb];
      [g_ctlD addSubview:mkbtn(@"NOTIF", @selector(notifWatch), CGRectMake(10+(hw+4),72,hw,30), [UIColor colorWithRed:0.45 green:0.3 blue:0.5 alpha:1])]; }
    g_ctlD.hidden = YES;
    [g_panel addSubview:g_ctlD];

    // ── Controles C (DRM/Crunchyroll) ← NUEVO ──
    g_ctlC = [[UIView alloc] initWithFrame:CGRectMake(0, ctl_y, pw, 40)];
    [g_ctlC addSubview:mkbtn(@"SCAN FULL",  @selector(cScanFull),  CGRectMake(10,0,b3,32), cCyan)];
    [g_ctlC addSubview:mkbtn(@"SS MONITOR", @selector(cSSMonitor), CGRectMake(10+(b3+4),0,b3,32), cOrange)];
    [g_ctlC addSubview:mkbtn(@"CLEAR",      @selector(cClear),     CGRectMake(10+2*(b3+4),0,b3,32), cGray)];
    g_ctlC.hidden = YES;
    [g_panel addSubview:g_ctlC];

    // ── Terminales ──
    g_termL = [[TermView alloc] initWithFrame:CGRectMake(6, term_y, pw-12, term_h)];
    CGFloat hterm_y = ctl_y+196;
    g_termH = [[TermView alloc] initWithFrame:CGRectMake(6, hterm_y, pw-12, ph-hterm_y-8)];
    CGFloat dterm_y = ctl_y+114;
    g_termD = [[TermView alloc] initWithFrame:CGRectMake(6, dterm_y, pw-12, ph-dterm_y-8)];
    // Terminal C: misma altura que L
    g_termC = [[TermView alloc] initWithFrame:CGRectMake(6, term_y, pw-12, term_h)];
    g_termH.hidden = g_termD.hidden = g_termC.hidden = YES;
    [g_panel addSubview:g_termL];
    [g_panel addSubview:g_termH];
    [g_panel addSubview:g_termD];
    [g_panel addSubview:g_termC];

    // Pick catcher
    g_pickCatcher = [[UIView alloc] initWithFrame:g_window.bounds];
    g_pickCatcher.backgroundColor = UIColor.clearColor;
    g_pickCatcher.hidden = YES;
    [g_pickCatcher addGestureRecognizer:[[UITapGestureRecognizer alloc]
        initWithTarget:DisasmController.class action:@selector(pickTapped:)]];
    [g_window addSubview:g_pickCatcher];
    [g_window addSubview:g_panel];
    [g_window makeKeyAndVisible];

    [[NSNotificationCenter defaultCenter]
        addObserver:DisasmController.class selector:@selector(kbShow:)
                name:UIKeyboardWillShowNotification object:nil];
    [[NSNotificationCenter defaultCenter]
        addObserver:DisasmController.class selector:@selector(kbHide:)
                name:UIKeyboardWillHideNotification object:nil];

    LOGL([NSString stringWithFormat:@"App:  %@", g_appname ?: @"?"]);
    LOGL([NSString stringWithFormat:@"Base: 0x%llx", g_base]);
    LOGL(@"─────────────────────────");
    LOGL(@"L=Log  H=Hook  D=Dump  C=DRM. Toca TRACE.");
    LOGC(@"C=DRM/Screenshot scanner.");
    LOGC(@"→ Pulsa SCAN FULL para escanear Crunchyroll.");
    LOGC(@"→ Pulsa SS MONITOR y luego toma una captura.");
}

// ── CTOR ──
%ctor {
    find_base();
    atomic_store(&g_running, true);
    pthread_create(&g_thread, NULL, tracer_thread, NULL);
    pthread_detach(g_thread);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3*NSEC_PER_SEC)),
        dispatch_get_main_queue(), ^{ build_ui(); });
}

