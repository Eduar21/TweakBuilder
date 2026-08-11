#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#include <mach/mach.h>
#include <mach/thread_act.h>
#include <mach-o/dyld.h>
#include <dlfcn.h>
#include <stdatomic.h>
#include <pthread.h>
#include <mach-o/loader.h>

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

// ── Demangle C++ symbols ──
static NSString *demangle(const char *sym) {
    if(!sym) return @"?";
    if(sym[0] != '_' || sym[1] != 'Z')
        return [NSString stringWithUTF8String:sym];

    // Obtener __cxa_demangle via dlsym
    // en runtime sin necesitar el header C++
    typedef char* (*demangle_fn)(
        const char*, char*, size_t*, int*);
    static demangle_fn fn = NULL;
    if(!fn) {
        fn = (demangle_fn)dlsym(
            RTLD_DEFAULT, "__cxa_demangle");
    }

    if(fn) {
        int status = 0;
        char *d = fn(sym, NULL, NULL, &status);
        if(status == 0 && d) {
            NSString *r =
                [NSString stringWithUTF8String:d];
            free(d);
            if(r.length > 80)
                r = [[r substringToIndex:77]
                    stringByAppendingString:@"..."];
            return r;
        }
    }

    // Fallback
    NSString *orig =
        [NSString stringWithUTF8String:sym];
    return orig.length > 80 ?
        [[orig substringToIndex:77]
            stringByAppendingString:@"..."] :
        orig;
}

// ── Categorizar símbolo ──
static NSString *categorize(NSString *sym) {
    if([sym containsString:@"quic"] ||
       [sym containsString:@"QUIC"] ||
       [sym containsString:@"socket"] ||
       [sym containsString:@"Socket"] ||
       [sym containsString:@"Network"] ||
       [sym containsString:@"network"] ||
       [sym containsString:@"tigon"] ||
       [sym containsString:@"IOBuf"] ||
       [sym containsString:@"http"] ||
       [sym containsString:@"HTTP"])
        return @"[NET]";

    if([sym containsString:@"IG"] ||
       [sym containsString:@"Instagram"])
        return @"[IG ]";

    if([sym containsString:@"UI"] ||
       [sym containsString:@"View"] ||
       [sym containsString:@"Layout"] ||
       [sym containsString:@"render"] ||
       [sym containsString:@"Render"])
        return @"[UI ]";

    if([sym containsString:@"facebook"] ||
       [sym containsString:@"Facebook"] ||
       [sym containsString:@"folly"] ||
       [sym containsString:@"Folly"] ||
       [sym containsString:@"MCF"] ||
       [sym containsString:@"XPlugin"])
        return @"[FB ]";

    if([sym containsString:@"swift"] ||
       [sym containsString:@"Swift"])
        return @"[SW ]";

    return @"[ . ]";
}

// ── Leer GOT de la app target ──
static void read_got(void) {
    add_log(@"═══ GOT READER ═══");

    // Encontrar el índice de la imagen target
    uint32_t target_idx = 0;
    uint32_t count = _dyld_image_count();
    for(uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if(!name) continue;
        if(strstr(name,"LiveProcess")) continue;
        if(strstr(name,"usr/lib"))    continue;
        if(strstr(name,"System"))     continue;
        if(strstr(name,"framework") &&
           !strstr(name,"Instagram")) continue;
        target_idx = i;
        break;
    }

    const struct mach_header_64 *mh =
        (const struct mach_header_64 *)
        _dyld_get_image_header(target_idx);
    intptr_t slide =
        _dyld_get_image_vmaddr_slide(target_idx);

    if(!mh) {
        add_log(@"ERROR: no encontré header");
        return;
    }

    add_log([NSString stringWithFormat:
        @"Header: 0x%llx slide: 0x%llx",
        (uint64_t)mh, (uint64_t)slide]);

    // Iterar load commands buscando __got
    uint8_t *lc = (uint8_t *)mh +
        sizeof(struct mach_header_64);

    int got_count = 0;

    for(uint32_t i = 0; i < mh->ncmds; i++) {
        struct load_command *cmd =
            (struct load_command *)lc;

        if(cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg =
                (struct segment_command_64 *)lc;
            struct section_64 *sec =
                (struct section_64 *)(lc +
                sizeof(struct segment_command_64));

            for(uint32_t j = 0;
                j < seg->nsects; j++) {

                // Buscar __got y __la_symbol_ptr
                BOOL is_got =
                    strncmp(sec[j].sectname,
                            "__got", 5) == 0;
                BOOL is_stubs =
                    strncmp(sec[j].sectname,
                            "__la_symbol_ptr",
                            15) == 0;

                if(!is_got && !is_stubs) {
                    sec++;
                    continue;
                }

                add_log([NSString stringWithFormat:
                    @"\n[%s] addr=0x%llx "
                    @"size=%llu entries=%llu",
                    sec[j].sectname,
                    sec[j].addr + slide,
                    sec[j].size,
                    sec[j].size / 8]);

                // Leer primeras 20 entradas
                uint64_t *got_ptr =
                    (uint64_t *)(uintptr_t)
                    (sec[j].addr + slide);
                uint64_t n_entries =
                    sec[j].size / 8;
                if(n_entries > 20)
                    n_entries = 20;

                for(uint64_t k = 0;
                    k < n_entries; k++) {
                    uint64_t ptr_val = got_ptr[k];
                    if(ptr_val == 0) {
                        sec++;
                        continue;
                    }

                    // Resolver a qué apunta
                    Dl_info info;
                    NSString *sym = @"?";
                    if(dladdr((void*)ptr_val,
                               &info)) {
                        if(info.dli_sname) {
                            sym = demangle(
                                info.dli_sname);
                        } else if(info.dli_fname) {
                            } else if(info.dli_fname) {
                                NSString *fn = [NSString
        stringWithUTF8String:
        info.dli_fname];
    NSString *base =
        fn.lastPathComponent;
    uint64_t off = ptr_val -
        (uint64_t)info.dli_fbase;
    sym = [NSString
        stringWithFormat:
        @"(%@)+0x%llx",
        base, off];
}

                    }

                    add_log([NSString
                        stringWithFormat:
                        @"  [%02llu] 0x%llx"
                        @" → %@",
                        k,
                        (uint64_t)
                        &got_ptr[k],
                        sym]);
                    got_count++;
                }
                sec++;
            }
        }
        lc += cmd->cmdsize;
    }

    add_log([NSString stringWithFormat:
        @"\nTotal entradas mostradas: %d",
        got_count]);
    add_log(@"═══════════════════");
}


// ════════════════════════════════════════════
//  HOOK POR REDIRECCIÓN DE GOT
// ════════════════════════════════════════════

// Núcleo: sobrescribe un slot del GOT y devuelve el original.
static bool got_hook(void **slot, void *replacement,
                     void **out_original) {
    if(!slot) return false;
    if(out_original) *out_original = *slot;   // guarda el real

    mach_port_t task = mach_task_self();
    // En Apple Silicon la página es de 16KB: usa vm_page_size.
    vm_address_t page = (vm_address_t)slot &
        ~((vm_address_t)vm_page_size - 1);

    // __got vive en __DATA_CONST (RO tras los fixups de dyld).
    // VM_PROT_COPY fuerza una copia privada -> el write no faulta.
    // Es el mismo truco que fishhook para __DATA_CONST.
    kern_return_t kr = vm_protect(task, page, vm_page_size,
        false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if(kr != KERN_SUCCESS) return false;

    *slot = replacement;                      // pisa el slot

    // Restaura RO (opcional; los reads siguen permitidos).
    vm_protect(task, page, vm_page_size, false, VM_PROT_READ);
    return true;
}

// Hook demo: NSStringFromClass (firma CONOCIDA -> PoC seguro).
//   NSString *NSStringFromClass(Class aClass);
typedef id (*NSStringFromClass_t)(Class);
static NSStringFromClass_t orig_NSStringFromClass = NULL;

static id my_NSStringFromClass(Class aClass) {
    static __thread int reent = 0;            // anti-recursión
    if(!reent) {
        reent = 1;
        const char *n = aClass ?
            class_getName(aClass) : "(null)";
        add_log([NSString stringWithFormat:
            @"  [HOOK] NSStringFromClass(%s)", n]);
        reent = 0;
    }
    return orig_NSStringFromClass(aClass);     // llama al real
}

// Busca en el GOT de la app el slot cuyo símbolo resuelto == want.
// Devuelve la dirección del SLOT (void**) o NULL. Sin hardcodear:
// se recalcula en runtime, así resiste el slide de ASLR.
static void **find_got_slot(const char *want) {
    uint32_t target_idx = 0;
    uint32_t count = _dyld_image_count();
    for(uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if(!name) continue;
        if(strstr(name,"LiveProcess")) continue;
        if(strstr(name,"usr/lib"))    continue;
        if(strstr(name,"System"))     continue;
        if(strstr(name,"framework") &&
           !strstr(name,"Instagram")) continue;
        target_idx = i;
        break;
    }

    const struct mach_header_64 *mh =
        (const struct mach_header_64 *)
        _dyld_get_image_header(target_idx);
    intptr_t slide =
        _dyld_get_image_vmaddr_slide(target_idx);
    if(!mh) return NULL;

    uint8_t *lc = (uint8_t *)mh +
        sizeof(struct mach_header_64);
    for(uint32_t i = 0; i < mh->ncmds; i++) {
        struct load_command *cmd =
            (struct load_command *)lc;
        if(cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg =
                (struct segment_command_64 *)lc;
            struct section_64 *sec =
                (struct section_64 *)(lc +
                sizeof(struct segment_command_64));
            for(uint32_t j = 0; j < seg->nsects; j++) {
                BOOL is_got =
                    strncmp(sec[j].sectname,"__got",5)==0;
                BOOL is_stubs =
                    strncmp(sec[j].sectname,
                            "__la_symbol_ptr",15)==0;
                if(is_got || is_stubs) {
                    uint64_t *got = (uint64_t *)(uintptr_t)
                        (sec[j].addr + slide);
                    uint64_t n = sec[j].size / 8;
                    for(uint64_t k = 0; k < n; k++) {
                        uint64_t v = got[k];
                        if(!v) continue;
                        Dl_info info;
                        if(dladdr((void*)v,&info) &&
                           info.dli_sname &&
                           strcmp(info.dli_sname,want)==0)
                            return (void **)&got[k];
                    }
                }
            }
        }
        lc += cmd->cmdsize;
    }
    return NULL;
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
    sym = demangle(info.dli_sname);
} else {
    uint64_t off = g_base ?
        pc - g_base : pc;
    sym = [NSString stringWithFormat:
        @"+0x%llx", off];
}

NSString *cat = categorize(sym);
[entry appendFormat:
    @"  %@ [t%u] %@\n", cat, t, sym];
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
                [g_fab setTitle:@"="
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
        [g_fab setTitle:@"="
               forState:UIControlStateNormal];
    }
}

+ (void)toggleTrace {
    g_tracing = !g_tracing;
    UIButton *btn = (UIButton*)
        [g_panel viewWithTag:200];
    NSString *title = g_tracing ?
        @"PAUSE" : @"TRACE";
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

+ (void)readGOT {
    add_log(@"Leyendo GOT...");
    dispatch_async(
        dispatch_get_global_queue(
            DISPATCH_QUEUE_PRIORITY_DEFAULT, 0),
        ^{ read_got(); });
}

+ (void)installHook {
    add_log(@"── INSTALANDO HOOK ──");
    dispatch_async(
        dispatch_get_global_queue(
            DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        void **slot = find_got_slot("NSStringFromClass");
        if(!slot) {
            add_log(@"[HOOK] slot no encontrado");
            return;
        }
        if(orig_NSStringFromClass) {
            add_log(@"[HOOK] ya estaba instalado");
            return;
        }
        if(got_hook(slot, (void*)my_NSStringFromClass,
                    (void**)&orig_NSStringFromClass)) {
            add_log([NSString stringWithFormat:
                @"[HOOK] NSStringFromClass @ %p OK",
                (void*)slot]);
            add_log(@"[HOOK] navega la app para ver hits");
        } else {
            add_log(@"[HOOK] fallo (vm_protect)");
        }
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
    [g_fab setTitle:@"="
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
    NSArray *titles  = @[@"TRACE",
                         @"GOT",
                         @"CLEAR",
                         @"HOOK"];
    NSArray *sels    = @[@"toggleTrace",
                         @"readGOT",
                         @"clearLog",
                         @"installHook"];
    NSArray *colors  = @[
        [UIColor colorWithRed:0.1 green:0.5
                        blue:0.1 alpha:1],
        [UIColor colorWithRed:0.4 green:0.1
                    blue:0.5 alpha:1],
        [UIColor colorWithRed:0.3 green:0.3
                        blue:0.3 alpha:1],
        [UIColor colorWithRed:0.7 green:0.4
                        blue:0.05 alpha:1],
    ];
    CGFloat bw = (pw - 32) / 4.0;
    for(int i = 0; i < 4; i++) {
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