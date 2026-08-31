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

@class TermView;
static TermView    *g_termL = nil;
static TermView    *g_termH = nil;
static TermView    *g_termD = nil;
static TermView    *g_termC = nil;   // ← NEW: terminal Crunchyroll/DRM
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

// ════════════════════════════════════════════
//  NUEVO: DRM / SCREENSHOT DETECTOR
//  Terminal C — auto-scan de protecciones
// ════════════════════════════════════════════

static void LOGC(NSString *s);  // fwd decl

// ── 1. Observer de screenshot + timer para medir latencia ──
// Cuando llega UIApplicationUserDidTakeScreenshotNotification,
// medimos cuánto tarda la app en reaccionar (→ qué handler corre).
static NSDate *g_snap_t0 = nil;
static id      g_drm_snap_token = nil;

static void drm_screenshot_monitor_start(void) {
    if(g_drm_snap_token) return;
    NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];

    // Antes del screenshot: timestamp
    [nc addObserverForName:UIApplicationWillResignActiveNotification
        object:nil queue:[NSOperationQueue mainQueue]
        usingBlock:^(NSNotification *n) {
            // app pierde foco → podría ser la pantalla de captura
            LOGC(@"[SS] UIApplication → willResignActive (posible screenshot)");
        }];

    g_drm_snap_token = [nc
        addObserverForName:UIApplicationUserDidTakeScreenshotNotification
        object:nil queue:[NSOperationQueue mainQueue]
        usingBlock:^(NSNotification *note) {
            g_snap_t0 = [NSDate date];
            LOGC(@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            LOGC(@"[SS] UIApplicationUserDidTakeScreenshotNotification");
            LOGC(@"     ↳ Quién más escucha esto?:");

            // Listar todos los observers de esa notificación
            // via _observersForObject:name: (API privada, disponible)
            @try {
                id obsArray = [nc
                    performSelector:@selector(_observersForObject:name:)
                    withObject:nil
                    withObject:UIApplicationUserDidTakeScreenshotNotification];
                if([obsArray respondsToSelector:@selector(count)]) {
                    LOGC([NSString stringWithFormat:
                        @"     total observers: %lu",
                        (unsigned long)[obsArray count]]);
                    for(id obs in obsArray) {
                        LOGC([NSString stringWithFormat:
                            @"     obs: %@", obs]);
                    }
                }
            } @catch(NSException *e) {
                LOGC(@"     (no pude listar observers vía API privada)");
            }
        }];
    LOGC(@"[DRM] Screenshot monitor activo");
}

// ── 2. Scan de clases con nombres DRM/License/Playback protection ──
static NSArray *g_drm_keywords = nil;

static void drm_scan_classes(void) {
    if(!g_drm_keywords)
        g_drm_keywords = @[
            @"drm", @"DRM",
            @"widevine", @"Widevine",
            @"license", @"License",
            @"secure", @"Secure",
            @"playready", @"PlayReady",
            @"decr", @"Decr",           // decrypt
            @"crypto", @"Crypto",
            @"screenshot", @"Screenshot",
            @"protect", @"Protect",
            @"content", @"Content",     // ContentProtection
            @"restrict", @"Restrict",
            @"hdcp", @"HDCP",
            @"airplay", @"AirPlay",
            @"fairplay", @"FairPlay",
            @"fps", @"FPS",             // FairPlay Streaming
            @"AVPl",                    // AVPlayer-related
            @"token", @"Token",
        ];

    LOGC(@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    LOGC(@"[SCAN] Buscando clases relacionadas con DRM/Screenshot...");

    unsigned int total = 0;
    Class *all = objc_copyClassList(&total);
    NSMutableArray *hits = [NSMutableArray array];

    for(unsigned int i = 0; i < total; i++) {
        const char *imgname = class_getImageName(all[i]);
        if(!imgname) continue;
        // Solo clases de la app (no sistema)
        if(strstr(imgname, "/System/")) continue;
        if(strstr(imgname, "/usr/lib/")) continue;

        NSString *cn = @(class_getName(all[i]));
        for(NSString *kw in g_drm_keywords) {
            if([cn rangeOfString:kw
                    options:NSCaseInsensitiveSearch].location != NSNotFound) {
                [hits addObject:cn];
                break;
            }
        }
    }
    if(all) free(all);

    [hits sortUsingSelector:@selector(compare:)];
    LOGC([NSString stringWithFormat:
        @"[SCAN] %lu clases encontradas:", (unsigned long)hits.count]);
    for(NSString *cn in hits)
        LOGC([NSString stringWithFormat:@"  • %@", cn]);
    LOGC(@"     ↳ En H: escribe la clase para hookear sus métodos");
    LOGC(@"       En D: escribe la clase para ver DUMP/IVARS");
}

// ── 3. Scan de métodos clave en AVPlayerLayer / AVPlayer ──
static void drm_scan_avplayer(void) {
    LOGC(@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    LOGC(@"[AVPlayer] Scaneando métodos de protección...");

    // Métodos de AVPlayerLayer relacionados con output restriction
    NSArray *targets = @[
        @"AVPlayerLayer",
        @"AVPlayer",
        @"AVAsset",
        @"AVPlayerItem",
        @"AVContentKeySession",  // FairPlay
        @"AVContentKeyRequest",
        @"AVPersistableContentKeyRequest",
    ];

    NSArray *keywords = @[
        @"secure", @"protect", @"restrict",
        @"airplay", @"output", @"Output",
        @"screenshot", @"capture", @"screen",
        @"prevent", @"Prevent", @"disable",
        @"privacy", @"drm", @"license",
        @"fairplay", @"encrypted", @"Encrypt",
        @"hdcp", @"copy", @"Copy",
    ];

    for(NSString *tname in targets) {
        Class cls = NSClassFromString(tname);
        if(!cls) continue;

        unsigned int mc = 0;
        Method *ml = class_copyMethodList(cls, &mc);
        NSMutableArray *found = [NSMutableArray array];

        for(unsigned int i = 0; i < mc; i++) {
            NSString *sel = @(sel_getName(method_getName(ml[i])));
            for(NSString *kw in keywords) {
                if([sel rangeOfString:kw
                        options:NSCaseInsensitiveSearch].location != NSNotFound) {
                    const char *enc = method_getTypeEncoding(ml[i]);
                    [found addObject:[NSString stringWithFormat:
                        @"  -%@  [%s]", sel, enc ?: "?"]];
                    break;
                }
            }
        }
        if(ml) free(ml);

        // También clase
        Class meta = object_getClass((id)cls);
        ml = class_copyMethodList(meta, &mc);
        for(unsigned int i = 0; i < mc; i++) {
            NSString *sel = @(sel_getName(method_getName(ml[i])));
            for(NSString *kw in keywords) {
                if([sel rangeOfString:kw
                        options:NSCaseInsensitiveSearch].location != NSNotFound) {
                    const char *enc = method_getTypeEncoding(ml[i]);
                    [found addObject:[NSString stringWithFormat:
                        @"  +%@  [%s]", sel, enc ?: "?"]];
                    break;
                }
            }
        }
        if(ml) free(ml);

        if(found.count) {
            LOGC([NSString stringWithFormat:
                @"[%@] %lu métodos:", tname, (unsigned long)found.count]);
            for(NSString *m in found) LOGC(m);
        }
    }
}

// ── 4. Scan del GOT para símbolos DRM/screenshot ──
static void drm_scan_got(void) {
    LOGC(@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    LOGC(@"[GOT] Buscando símbolos DRM/screenshot en el GOT...");

    NSArray *filters = @[
        @"screenshot", @"Screenshot",
        @"secure", @"Secure",
        @"protect", @"Protect",
        @"drm", @"DRM",
        @"restrict", @"Restrict",
        @"airplay", @"AirPlay",
        @"prevent", @"Prevent",
        @"output", @"Output",
        @"disable", @"Disable",
    ];

    uint32_t target_idx = 0;  // se llena en find_base via find_target_image()
    // Buscar el binary de la app
    uint32_t count = _dyld_image_count();
    for(uint32_t i = 0; i < count; i++) {
        const char *path = _dyld_get_image_name(i);
        if(!path) continue;
        if(strstr(path, "/System/")) continue;
        if(strstr(path, "/usr/lib/")) continue;
        if(strstr(path, "LiveContainer")) continue;
        if(strstr(path, ".framework/")) continue;
        const char *base = strrchr(path, '/');
        if(!base) continue;
        base++;
        char needle[512];
        snprintf(needle, sizeof(needle), "/%s.app/", base);
        if(strstr(path, needle)) { target_idx = i; break; }
    }

    const struct mach_header_64 *mh =
        (const struct mach_header_64 *)_dyld_get_image_header(target_idx);
    intptr_t slide = _dyld_get_image_vmaddr_slide(target_idx);
    if(!mh) { LOGC(@"[GOT] no header"); return; }

    int found = 0;
    uint8_t *lc = (uint8_t *)mh + sizeof(struct mach_header_64);
    for(uint32_t i = 0; i < mh->ncmds; i++) {
        struct load_command *cmd = (struct load_command *)lc;
        if(cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg =
                (struct segment_command_64 *)lc;
            struct section_64 *sec =
                (struct section_64 *)(lc + sizeof(struct segment_command_64));
            for(uint32_t j = 0; j < seg->nsects; j++) {
                if(strncmp(sec[j].sectname,"__got",5) != 0 &&
                   strncmp(sec[j].sectname,"__la_symbol_ptr",15) != 0)
                    continue;
                uint64_t *got = (uint64_t *)(uintptr_t)(sec[j].addr + slide);
                uint64_t n = sec[j].size / 8;
                for(uint64_t k = 0; k < n; k++) {
                    if(!got[k]) continue;
                    Dl_info info;
                    if(!dladdr((void*)got[k], &info) || !info.dli_sname) continue;
                    NSString *sym = @(info.dli_sname);
                    for(NSString *f in filters) {
                        if([sym rangeOfString:f
                                options:NSCaseInsensitiveSearch].location != NSNotFound) {
                            LOGC([NSString stringWithFormat:
                                @"  [GOT] 0x%llx  %@",
                                (uint64_t)&got[k], sym]);
                            found++;
                            break;
                        }
                    }
                }
            }
        }
        lc += cmd->cmdsize;
    }
    LOGC([NSString stringWithFormat:@"[GOT] %d símbolos encontrados", found]);
}

// ── 5. Hook de AVPlayerLayer para detectar restricciones de output ──
// AVPlayerLayer.preventsDisplaySleepDuringVideoPlayback
// y el UIView que retorna AVPlayerLayer como layerClass
static IMP g_orig_prevents_display = NULL;
static IMP g_orig_req_video_enc    = NULL;

// Detecta qué vistas de la app usan AVPlayerLayer (DRM player)
static void drm_find_player_views(void) {
    LOGC(@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    LOGC(@"[PLAYER] Buscando clases con layerClass = AVPlayerLayer...");

    unsigned int total = 0;
    Class *all = objc_copyClassList(&total);

    for(unsigned int i = 0; i < total; i++) {
        const char *img = class_getImageName(all[i]);
        if(!img) continue;
        if(strstr(img, "/System/")) continue;
        if(strstr(img, "/usr/lib/")) continue;

        // ¿tiene +layerClass?
        Method m = class_getClassMethod(all[i], @selector(layerClass));
        if(!m) continue;

        // Llamar +layerClass y ver si retorna AVPlayerLayer
        @try {
            Class lc = (Class)[(__bridge id)all[i]
                performSelector:@selector(layerClass)];
            if(lc == [AVPlayerLayer class] ||
               [NSStringFromClass(lc) containsString:@"AVPlayer"]) {
                LOGC([NSString stringWithFormat:
                    @"  ✓ %s → layerClass = %@",
                    class_getName(all[i]), NSStringFromClass(lc)]);

                // Mostrar sus métodos relacionados con el player
                unsigned int mc = 0;
                Method *ml = class_copyMethodList(all[i], &mc);
                for(unsigned int j = 0; j < mc; j++) {
                    NSString *sn = @(sel_getName(method_getName(ml[j])));
                    if([sn containsString:@"player"] ||
                       [sn containsString:@"Player"] ||
                       [sn containsString:@"layer"] ||
                       [sn containsString:@"Layer"]) {
                        LOGC([NSString stringWithFormat:
                            @"    -%@", sn]);
                    }
                }
                if(ml) free(ml);
            }
        } @catch(NSException *e) { continue; }
    }
    if(all) free(all);
}

// ── 6. Hooking automático para bypassear la protección ──
// Intenta forzar AVPlayerLayer.videoGravity y busca
// el método que oculta el contenido al screenshot
static void drm_auto_hook_screenshot(void) {
    LOGC(@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    LOGC(@"[HOOK] Intentando hookear protecciones de screenshot...");

    // AVPlayerLayer: buscar métodos que se llaman durante screenshot
    Class avpl = [AVPlayerLayer class];
    if(avpl) {
        // Log: qué pasa con el player al screenshot
        unsigned int mc = 0;
        Method *ml = class_copyMethodList(avpl, &mc);
        LOGC([NSString stringWithFormat:
            @"[AVPlayerLayer] %u métodos de instancia", mc]);
        for(unsigned int i = 0; i < mc; i++) {
            NSString *sn = @(sel_getName(method_getName(ml[i])));
            // Mostrar todos (interesantes para DRM)
            if([sn containsString:@"secure"] ||
               [sn containsString:@"prevent"] ||
               [sn containsString:@"output"] ||
               [sn containsString:@"Output"] ||
               [sn containsString:@"restrict"] ||
               [sn containsString:@"copy"] ||
               [sn containsString:@"screen"] ||
               [sn containsString:@"privacy"]) {
                const char *enc = method_getTypeEncoding(ml[i]);
                LOGC([NSString stringWithFormat:
                    @"  → -%@  %s", sn, enc ?: "?"]);
                LOGC([NSString stringWithFormat:
                    @"    Hookear: Clase=AVPlayerLayer  Sel=%@  Val=0",
                    sn]);
            }
        }
        if(ml) free(ml);
    }

    // Buscar en clases de Crunchyroll qué observa screenshot
    LOGC(@"");
    LOGC(@"[HOOK] Clases que observan UIApplicationUserDidTakeScreenshot:");
    unsigned int total = 0;
    Class *all = objc_copyClassList(&total);
    for(unsigned int i = 0; i < total; i++) {
        const char *img = class_getImageName(all[i]);
        if(!img || strstr(img, "/System/") || strstr(img, "/usr/lib/")) continue;
        // Buscar si tiene un método que menciona screenshot en el sel name
        unsigned int mc = 0;
        Method *ml = class_copyMethodList(all[i], &mc);
        for(unsigned int j = 0; j < mc; j++) {
            NSString *sn = @(sel_getName(method_getName(ml[j])));
            if([sn containsString:@"screenshot"] ||
               [sn containsString:@"Screenshot"] ||
               [sn containsString:@"didTakeScreenshot"] ||
               [sn containsString:@"screenshotDetect"]) {
                LOGC([NSString stringWithFormat:
                    @"  %s → -%@", class_getName(all[i]), sn]);
                LOGC([NSString stringWithFormat:
                    @"    → Para hookear: Clase=%s  Sel=%@  Val=void/log",
                    class_getName(all[i]), sn]);
            }
        }
        if(ml) free(ml);
    }
    if(all) free(all);
}

// ── 7. Scan completo — el que llama a todo ──
static void drm_full_scan(void) {
    dispatch_async(dispatch_get_global_queue(
        DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        LOGC(@"╔══════════════════════════════════════╗");
        LOGC(@"║   CRUNCHYROLL DRM SCANNER  v1        ║");
        LOGC(@"╚══════════════════════════════════════╝");
        drm_screenshot_monitor_start();
        drm_scan_classes();
        drm_scan_avplayer();
        drm_find_player_views();
        drm_scan_got();
        drm_auto_hook_screenshot();
        LOGC(@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        LOGC(@"[DONE] Scan completo.");
        LOGC(@"Próximos pasos:");
        LOGC(@" 1. Ir a H y hookear clases encontradas");
        LOGC(@" 2. Abrir un video en Crunchyroll");
        LOGC(@" 3. Tomar screenshot → ver qué se llama");
        LOGC(@" 4. Hook el método que oculta el video");
    });
}

// ── Logger C ──
static void LOGC(NSString *s){ if(g_termC) [g_termC append:s]; }

// ════════════════════════════════════════════
//  (todo el código base original sigue igual)
//  solo se agregan las terminales y controles
//  de la pestaña C
// ════════════════════════════════════════════

// ─── [Acá va TODO el código original de flexing.m sin cambios] ───
// Solo cambia lo siguiente:
//
// 1. g_seg → 4 items:  @[@"L", @"H", @"D", @"C"]
// 2. switchTab: agregar g_tab==3 para mostrar g_ctlC y g_termC
// 3. buildUI: crear g_termC y g_ctlC con 3 botones:
//      [SCAN] → drm_full_scan()
//      [SS]   → drm_screenshot_monitor_start()
//      [CLEAR]→ [g_termC clearAll]
// 4. LOGC ya definido arriba

/*
 En build_ui(), REEMPLAZAR el UISegmentedControl así:
 
   UISegmentedControl *seg = [[UISegmentedControl alloc]
       initWithItems:@[@"L", @"H", @"D", @"C"]];   // ← añadir "C"

 En switchTab:, añadir al final:
   g_ctlC.hidden  = (g_tab != 3);
   g_termC.hidden = (g_tab != 3);

 En build_ui, AÑADIR los controles C:
   g_ctlC = [[UIView alloc] initWithFrame:CGRectMake(0, ctl_y, pw, 40)];
   CGFloat cw = (pw - 28) / 3.0;
   [g_ctlC addSubview:mkbtn(@"SCAN FULL",
       @selector(cScanFull), CGRectMake(10, 0, cw, 32), cTeal)];
   [g_ctlC addSubview:mkbtn(@"SS MONITOR",
       @selector(cSSMonitor), CGRectMake(10+(cw+4), 0, cw, 32), cOrange)];
   [g_ctlC addSubview:mkbtn(@"CLEAR",
       @selector(cClear), CGRectMake(10+2*(cw+4), 0, cw, 32), cGray)];
   g_ctlC.hidden = YES;
   [g_panel addSubview:g_ctlC];

   CGFloat cterm_y = ctl_y + 48;
   g_termC = [[TermView alloc] initWithFrame:
       CGRectMake(6, cterm_y, pw-12, ph - cterm_y - 8)];
   g_termC.hidden = YES;
   [g_panel addSubview:g_termC];

 En DisasmController, AÑADIR:
   + (void)cScanFull  { drm_full_scan(); }
   + (void)cSSMonitor { drm_screenshot_monitor_start(); }
   + (void)cClear     { [g_termC clearAll]; }

 En el intro de build_ui, al final:
   LOGC(@"C=DRM/Screenshot scanner. Pulsa SCAN FULL.");
*/

// ─── FIN DE CAMBIOS ───
// El resto del archivo es idéntico al flexing original


