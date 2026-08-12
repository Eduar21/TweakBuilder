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

// Tres terminales independientes (L=Log/Inspector, H=Hook, D=Dump)
@class TermView;
static TermView    *g_termL = nil;
static TermView    *g_termH = nil;
static TermView    *g_termD = nil;
static int          g_tab   = 0;      // 0=L 1=H 2=D
static UIView      *g_ctlL = nil, *g_ctlH = nil, *g_ctlD = nil;
static UITextField *g_hookField = nil, *g_dumpField = nil;

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

// ── TermView: terminal con auto-scroll inteligente ──
// Cada pestaña tiene la suya, con buffer propio. append: baja
// solo si ya estás pegado al fondo (arregla el "me tira abajo").
@interface TermView : UIView
@property(nonatomic,strong) UITextView *tv;
- (void)append:(NSString*)s;
- (void)clearAll;
- (NSString*)text;
@end

@implementation TermView
- (instancetype)initWithFrame:(CGRect)f {
    if((self = [super initWithFrame:f])) {
        _tv = [[UITextView alloc]
            initWithFrame:self.bounds];
        _tv.autoresizingMask =
            UIViewAutoresizingFlexibleWidth |
            UIViewAutoresizingFlexibleHeight;
        _tv.backgroundColor =
            [UIColor colorWithWhite:0.02 alpha:1];
        _tv.textColor =
            [UIColor colorWithRed:0.3 green:1
                             blue:0.45 alpha:1];
        _tv.font = [UIFont
            monospacedSystemFontOfSize:11
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
        CGFloat dist = tv.contentSize.height -
            tv.contentOffset.y - tv.bounds.size.height;
        BOOL atBottom = dist < 44;   // scroll inteligente
        NSDictionary *attrs = @{
            NSFontAttributeName: tv.font,
            NSForegroundColorAttributeName: tv.textColor
        };
        [tv.textStorage appendAttributedString:
            [[NSAttributedString alloc]
                initWithString:line attributes:attrs]];
        if(tv.textStorage.length > 200000)
            [tv.textStorage deleteCharactersInRange:
                NSMakeRange(0, 80000)];
        if(atBottom)
            [tv scrollRangeToVisible:
                NSMakeRange(tv.textStorage.length, 0)];
    });
}
- (void)clearAll {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.tv.text = @"";
    });
}
- (NSString*)text { return self.tv.text ?: @""; }
@end

// ── Log: enrutado a cada terminal ──
static void LOGL(NSString *s){ if(g_termL) [g_termL append:s]; }
static void LOGH(NSString *s){ if(g_termH) [g_termH append:s]; }
static void LOGD(NSString *s){ if(g_termD) [g_termD append:s]; }
// add_log = terminal L (tracer + general).
static void add_log(NSString *line){ LOGL(line); }

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


// ════════════════════════════════════════════
//  HOOK POR REDIRECCIÓN DE GOT
// ════════════════════════════════════════════

// Núcleo: abre el slot RW, escribe un valor, restaura RO.
static bool got_write(void **slot, void *value) {
    if(!slot) return false;

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

    *slot = value;                            // escribe

    // Restaura RO (opcional; los reads siguen permitidos).
    vm_protect(task, page, vm_page_size, false, VM_PROT_READ);
    return true;
}

// Instala: guarda el original y pisa el slot con replacement.
static bool got_hook(void **slot, void *replacement,
                     void **out_original) {
    if(!slot) return false;
    void *orig = *slot;                       // capturar antes
    if(!got_write(slot, replacement)) return false;
    if(out_original) *out_original = orig;     // solo si el write pegó
    return true;
}

// Quita: restaura el puntero original en el slot.
static bool got_unhook(void **slot, void *original) {
    return got_write(slot, original);
}

// ── Force-0 genérico: neutraliza una función C por GOT ──
// Fuerza el retorno a 0/NO. Sirve para checks anti-tamper que
// devuelven BOOL/int/puntero. NO llama al original: por eso el
// mismatch de firma no importa (nunca leemos args). Caveat: no
// sirve si la función retorna float/double o un struct.
static void **find_got_slot(const char *want);   // fwd decl
static long my_force0(void) { return 0; }

typedef struct {
    void **slot;      // slot del GOT
    void  *orig;      // puntero original (para restaurar)
    char   name[128]; // símbolo
} force_hook_t;

#define MAX_FORCE 16
static force_hook_t g_force[MAX_FORCE];
static int          g_force_n = 0;

// Devuelve YES si instaló, NO si no encontró el slot o está lleno.
static BOOL force0_add(const char *name) {
    if(g_force_n >= MAX_FORCE) return NO;
    void **slot = find_got_slot(name);
    if(!slot) return NO;                 // no está en el GOT (interno)
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
    for(int i = 0; i < g_force_n; i++)
        got_unhook(g_force[i].slot, g_force[i].orig);
    g_force_n = 0;
}

// GOT search: lista entradas cuyo símbolo contiene `filter`
// (case-insensitive). filter NULL/vacío -> primeras 40.
// Recorre las 38k+ entradas: mucho más completo que el sampler
// para cazar checks anti-tamper (Jailbroken, Debug, Tamper...).
static void read_got_filtered(const char *filter) {
    BOOL all = (filter && filter[0]);

    uint32_t target_idx = 0;
    uint32_t count = _dyld_image_count();
    for(uint32_t i = 0; i < count; i++) {
        const char *nm = _dyld_get_image_name(i);
        if(!nm) continue;
        if(strstr(nm,"LiveProcess")) continue;
        if(strstr(nm,"usr/lib"))    continue;
        if(strstr(nm,"System"))     continue;
        if(strstr(nm,"framework") &&
           !strstr(nm,"Instagram")) continue;
        target_idx = i;
        break;
    }
    const struct mach_header_64 *mh =
        (const struct mach_header_64 *)
        _dyld_get_image_header(target_idx);
    intptr_t slide =
        _dyld_get_image_vmaddr_slide(target_idx);
    if(!mh) { LOGD(@"[GOT] no encontré header"); return; }

    LOGD([NSString stringWithFormat:@"═══ GOT: %s ═══",
        all ? filter : "(primeras 40)"]);

    const int CAP = all ? 200 : 40;
    int shown = 0, matched = 0;

    uint8_t *lc = (uint8_t *)mh + sizeof(struct mach_header_64);
    for(uint32_t i = 0; i < mh->ncmds && shown < CAP; i++) {
        struct load_command *cmd = (struct load_command *)lc;
        if(cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg =
                (struct segment_command_64 *)lc;
            struct section_64 *sec =
                (struct section_64 *)(lc +
                sizeof(struct segment_command_64));
            for(uint32_t j = 0;
                j < seg->nsects && shown < CAP; j++) {
                BOOL is_got =
                    strncmp(sec[j].sectname,"__got",5)==0;
                BOOL is_stubs =
                    strncmp(sec[j].sectname,
                            "__la_symbol_ptr",15)==0;
                if(!is_got && !is_stubs) continue;
                uint64_t *got = (uint64_t *)(uintptr_t)
                    (sec[j].addr + slide);
                uint64_t n = sec[j].size / 8;
                for(uint64_t k = 0; k < n && shown < CAP; k++) {
                    uint64_t v = got[k];
                    if(!v) continue;
                    Dl_info info;
                    if(!dladdr((void*)v,&info) || !info.dli_sname)
                        continue;
                    if(all && !strcasestr(info.dli_sname, filter))
                        continue;
                    matched++;
                    LOGD([NSString stringWithFormat:
                        @"  0x%llx -> %@",
                        (uint64_t)&got[k],
                        demangle(info.dli_sname)]);
                    shown++;
                }
            }
        }
        lc += cmd->cmdsize;
    }
    LOGD([NSString stringWithFormat:
        @"── match: %d (mostrados %d / cap %d) ──",
        matched, shown, CAP]);
    LOGD(@"═══════════════════");
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

// ════════════════════════════════════════════
//  MODO 2: SWIZZLING ObjC (métodos de instancia)
// ════════════════════════════════════════════

// Genérico: intercambia la IMP de un método de instancia.
// Devuelve la IMP original (para llamarla desde tu trampolín).
// Si el método es HEREDADO, lo agrega a cls para no pisar al padre.
// (base del futuro hook interactivo ObjC; unused por ahora)
__attribute__((unused))
static IMP swizzle_instance(Class cls, SEL sel, IMP replacement) {
    if(!cls || !sel || !replacement) return NULL;
    Method m = class_getInstanceMethod(cls, sel);
    if(!m) return NULL;
    IMP old = method_getImplementation(m);
    if(!class_addMethod(cls, sel, replacement,
                        method_getTypeEncoding(m))) {
        method_setImplementation(m, replacement); // ya estaba en cls
    }
    return old;
}

// Restaura la IMP original de un método de instancia.
__attribute__((unused))
static void unswizzle_instance(Class cls, SEL sel, IMP original) {
    if(!cls || !sel || !original) return;
    Method m = class_getInstanceMethod(cls, sel);
    if(m) method_setImplementation(m, original);
}

// ════════════════════════════════════════════
//  ENUMERACIÓN: métodos e ivars de una clase
// ════════════════════════════════════════════
// Sirven para elegir objetivos de swizzling. El type encoding
// te da la firma exacta del trampolín. Ej: "v24@0:8B16" =
// retorna void(v); self(@)@0, _cmd(:)@8, BOOL(B)@16.
// OJO Swift: solo aparecen métodos @objc/dynamic. Clases con
// módulo (Modulo.Clase) suelen necesitar el nombre mangled.

static void dump_class_methods(const char *clsname) {
    if(!clsname || !clsname[0]) {
        LOGD(@"[DUMP] nombre vacío"); return;
    }
    Class cls = objc_getClass(clsname);
    if(!cls) {
        LOGD([NSString stringWithFormat:
            @"[DUMP] no encontrada: %s "
            @"(¿Swift con módulo? usa mangled)", clsname]);
        return;
    }
    LOGD([NSString stringWithFormat:
        @"═══ MÉTODOS %s ═══", clsname]);

    unsigned int n = 0;
    Method *ml = class_copyMethodList(cls, &n);
    LOGD([NSString stringWithFormat:
        @"── instancia: %u ──", n]);
    for(unsigned int i = 0; i < n; i++) {
        const char *enc = method_getTypeEncoding(ml[i]);
        LOGD([NSString stringWithFormat:@"  -%s  %s",
            sel_getName(method_getName(ml[i])), enc ?: ""]);
    }
    if(ml) free(ml);

    Class meta = object_getClass((id)cls);
    n = 0;
    ml = class_copyMethodList(meta, &n);
    LOGD([NSString stringWithFormat:
        @"── clase: %u ──", n]);
    for(unsigned int i = 0; i < n; i++) {
        const char *enc = method_getTypeEncoding(ml[i]);
        LOGD([NSString stringWithFormat:@"  +%s  %s",
            sel_getName(method_getName(ml[i])), enc ?: ""]);
    }
    if(ml) free(ml);
    LOGD(@"═══════════════════");
}

static void dump_class_ivars(const char *clsname) {
    if(!clsname || !clsname[0]) {
        LOGD(@"[IVARS] nombre vacío"); return;
    }
    Class cls = objc_getClass(clsname);
    if(!cls) {
        LOGD([NSString stringWithFormat:
            @"[IVARS] no encontrada: %s", clsname]);
        return;
    }
    unsigned int n = 0;
    Ivar *iv = class_copyIvarList(cls, &n);
    LOGD([NSString stringWithFormat:
        @"═══ IVARS %s (%u) ═══", clsname, n]);
    for(unsigned int i = 0; i < n; i++) {
        const char *tp = ivar_getTypeEncoding(iv[i]);
        LOGD([NSString stringWithFormat:@"  +0x%lx %s  %s",
            (long)ivar_getOffset(iv[i]),
            ivar_getName(iv[i]) ?: "?", tp ?: ""]);
    }
    if(iv) free(iv);
    LOGD(@"═══════════════════");
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

// ── Passthrough Window ──
// Nivel bajado a Normal+1: por encima de la app pero por DEBAJO del
// menú de copiar/pegar de iOS (arregla la barra que quedaba detrás).
@interface PassthroughWindow : UIWindow
@end

@implementation PassthroughWindow
- (UIView *)hitTest:(CGPoint)point
          withEvent:(UIEvent *)event {
    // Si hay un VC modal presentado (alert de Guardado), normal.
    if(self.rootViewController.presentedViewController) {
        return [super hitTest:point withEvent:event];
    }
    // FAB
    if(g_fab && !g_fab.hidden) {
        CGPoint p = [self convertPoint:point toView:g_fab];
        if([g_fab pointInside:p withEvent:event])
            return g_fab;
    }
    // Panel abierto
    if(g_panel && g_expanded && !g_panel.hidden) {
        CGPoint p = [self convertPoint:point toView:g_panel];
        if([g_panel pointInside:p withEvent:event])
            return [g_panel hitTest:p withEvent:event] ?: g_panel;
        // Toque fuera del panel: cerrar (salvo si el teclado está)
        dispatch_async(dispatch_get_main_queue(), ^{
            if(g_expanded) {
                [g_panel endEditing:YES];
                g_expanded = NO;
                [UIView animateWithDuration:0.2 animations:^{
                    g_panel.alpha = 0;
                } completion:^(BOOL done){
                    g_panel.hidden = YES;
                }];
                [g_fab setTitle:@"=" forState:UIControlStateNormal];
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

// Coloca el panel pegado al FAB: si el FAB está en la mitad de
// arriba, el panel cae hacia abajo; si está abajo, sube. Clamp a
// pantalla. (Opción A: el menú sigue al botón.)
+ (void)repositionPanel {
    if(!g_panel || !g_fab) return;
    CGFloat H  = g_window.bounds.size.height;
    CGFloat ph = g_panel.frame.size.height;
    CGFloat pw = g_panel.frame.size.width;
    CGFloat px = g_panel.frame.origin.x;
    CGRect  fab = g_fab.frame;
    CGFloat py = (g_fab.center.y < H/2)
        ? CGRectGetMaxY(fab) + 10          // FAB arriba -> panel abajo
        : CGRectGetMinY(fab) - ph - 10;    // FAB abajo  -> panel arriba
    CGFloat topSafe = 50, botSafe = H - 10;
    if(py + ph > botSafe) py = botSafe - ph;
    if(py < topSafe)      py = topSafe;
    g_panel.transform = CGAffineTransformIdentity;
    g_panel.frame = CGRectMake(px, py, pw, ph);
}

+ (void)togglePanel {
    g_expanded = !g_expanded;
    if(g_expanded) {
        [self repositionPanel];            // pegarse al FAB
        g_panel.hidden = NO;
        g_panel.alpha  = 0;
        [UIView animateWithDuration:0.2 animations:^{
            g_panel.alpha = 1;
        }];
        [g_fab setTitle:@"✕" forState:UIControlStateNormal];
    } else {
        [g_panel endEditing:YES];
        [UIView animateWithDuration:0.2 animations:^{
            g_panel.alpha = 0;
        } completion:^(BOOL done){
            g_panel.hidden = YES;
        }];
        [g_fab setTitle:@"=" forState:UIControlStateNormal];
    }
}

// ── Selector de pestaña L / H / D ──
+ (void)switchTab:(UISegmentedControl*)seg {
    g_tab = (int)seg.selectedSegmentIndex;
    g_ctlL.hidden  = (g_tab != 0);
    g_ctlH.hidden  = (g_tab != 1);
    g_ctlD.hidden  = (g_tab != 2);
    g_termL.hidden = (g_tab != 0);
    g_termH.hidden = (g_tab != 1);
    g_termD.hidden = (g_tab != 2);
    if(g_tab != 1 && g_tab != 2) [g_panel endEditing:YES];
}

// ── Pestaña L (Log / Inspector) ──
+ (void)toggleTrace {
    g_tracing = !g_tracing;
    UIButton *btn = (UIButton*)[g_panel viewWithTag:200];
    [btn setTitle:(g_tracing ? @"PAUSE" : @"TRACE")
         forState:UIControlStateNormal];
    btn.backgroundColor = g_tracing ?
        [UIColor colorWithRed:0.7 green:0.1 blue:0.1 alpha:1] :
        [UIColor colorWithRed:0.1 green:0.5 blue:0.1 alpha:1];
    LOGL(g_tracing ? @"── TRACE INICIADO ──" : @"── PAUSADO ──");
}

+ (void)clearL { [g_termL clearAll]; }

+ (void)saveL {
    NSString *text = [g_termL text];
    NSString *docs = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *path = [docs stringByAppendingPathComponent:
        @"live_trace.txt"];
    [text writeToFile:path atomically:YES
             encoding:NSUTF8StringEncoding error:nil];
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *a = [UIAlertController
            alertControllerWithTitle:@"Guardado" message:path
                      preferredStyle:UIAlertControllerStyleAlert];
        [a addAction:[UIAlertAction actionWithTitle:@"OK"
            style:UIAlertActionStyleDefault handler:nil]];
        UIViewController *root = g_window.rootViewController;
        while(root.presentedViewController)
            root = root.presentedViewController;
        [root presentViewController:a animated:YES completion:nil];
    });
}

+ (void)copyL {
    UIPasteboard.generalPasteboard.string = [g_termL text];
    LOGL(@"[L] copiado al portapapeles");
}

// ── Pestaña H (Hook) ──  Run = force-0 por nombre, Stop = quita todos
+ (void)hookRun {
    NSString *nm = g_hookField.text;
    [g_hookField resignFirstResponder];
    dispatch_async(dispatch_get_global_queue(
        DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        if(!nm.length) { LOGH(@"[H] escribí un símbolo"); return; }
        if(force0_add(nm.UTF8String))
            LOGH([NSString stringWithFormat:
                @"[H] %@ -> 0  (activos: %d)", nm, g_force_n]);
        else
            LOGH([NSString stringWithFormat:
                @"[H] %@ no está en el GOT (interno o mal escrito)",
                nm]);
    });
}

+ (void)hookStop {
    dispatch_async(dispatch_get_global_queue(
        DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        force0_clear_all();
        LOGH(@"[H] hooks quitados");
    });
}

+ (void)clearH { [g_termH clearAll]; }

// ── Pestaña D (Dump) ──  Dump / Ivars / GOT sobre el campo de texto
+ (void)dDump {
    NSString *n = g_dumpField.text;
    [g_dumpField resignFirstResponder];
    dispatch_async(dispatch_get_global_queue(
        DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        dump_class_methods(n.UTF8String);
    });
}

+ (void)dIvars {
    NSString *n = g_dumpField.text;
    [g_dumpField resignFirstResponder];
    dispatch_async(dispatch_get_global_queue(
        DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        dump_class_ivars(n.UTF8String);
    });
}

+ (void)dGot {
    NSString *f = g_dumpField.text;
    [g_dumpField resignFirstResponder];
    dispatch_async(dispatch_get_global_queue(
        DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        read_got_filtered(f.length ? f.UTF8String : NULL);
    });
}

+ (void)clearD { [g_termD clearAll]; }

// ── FAB arrastrable ──
+ (void)fabDragged:(UIPanGestureRecognizer*)pan {
    CGPoint t = [pan translationInView:g_window];
    CGPoint c = CGPointMake(g_fab.center.x + t.x,
                            g_fab.center.y + t.y);
    CGFloat r = g_fab.bounds.size.width / 2;
    CGRect  b = g_window.bounds;
    c.x = MAX(r, MIN(b.size.width-r, c.x));
    c.y = MAX(r+44, MIN(b.size.height-r, c.y));
    g_fab.center = c;
    [pan setTranslation:CGPointZero inView:g_window];
    if(g_expanded) [self repositionPanel];   // el panel sigue al FAB
}

// ── Teclado: subir el panel si el campo queda tapado ──
+ (void)kbShow:(NSNotification*)n {
    CGRect kb = [n.userInfo[UIKeyboardFrameEndUserInfoKey]
        CGRectValue];
    CGFloat overlap =
        CGRectGetMaxY(g_panel.frame) - kb.origin.y + 8;
    if(overlap > 0)
        [UIView animateWithDuration:0.25 animations:^{
            g_panel.transform =
                CGAffineTransformMakeTranslation(0, -overlap);
        }];
}
+ (void)kbHide:(NSNotification*)n {
    [UIView animateWithDuration:0.25 animations:^{
        g_panel.transform = CGAffineTransformIdentity;
    }];
}

@end

// ── Helpers de construcción de UI ──
static UIButton *mkbtn(NSString *title, SEL sel,
                       CGRect frame, UIColor *color) {
    UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
    b.frame = frame;
    b.backgroundColor = color;
    b.layer.cornerRadius = 6;
    [b setTitle:title forState:UIControlStateNormal];
    [b setTitleColor:UIColor.whiteColor
            forState:UIControlStateNormal];
    b.titleLabel.font = [UIFont
        monospacedSystemFontOfSize:11 weight:UIFontWeightBold];
    [b addTarget:DisasmController.class action:sel
    forControlEvents:UIControlEventTouchUpInside];
    return b;
}

static UITextField *mkfield(NSString *ph, CGRect frame) {
    UITextField *tf = [[UITextField alloc] initWithFrame:frame];
    tf.placeholder = ph;
    tf.backgroundColor = [UIColor colorWithWhite:0.12 alpha:1];
    tf.textColor = UIColor.whiteColor;
    tf.font = [UIFont monospacedSystemFontOfSize:12
                                          weight:UIFontWeightRegular];
    tf.layer.cornerRadius = 6;
    tf.autocorrectionType = UITextAutocorrectionTypeNo;
    tf.autocapitalizationType = UITextAutocapitalizationTypeNone;
    tf.clearButtonMode = UITextFieldViewModeWhileEditing;
    UIView *pad = [[UIView alloc]
        initWithFrame:CGRectMake(0,0,10,1)];
    tf.leftView = pad; tf.leftViewMode = UITextFieldViewModeAlways;
    return tf;
}

// ── Build UI ──
static void build_ui(void) {
    // Atar a la escena activa (si no, la ventana puede no pintarse).
    UIWindowScene *scene = nil;
    for(UIScene *s in
        UIApplication.sharedApplication.connectedScenes) {
        if([s isKindOfClass:UIWindowScene.class] &&
           s.activationState ==
               UISceneActivationStateForegroundActive) {
            scene = (UIWindowScene *)s; break;
        }
    }
    if(!scene) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
            (int64_t)(1 * NSEC_PER_SEC)),
            dispatch_get_main_queue(), ^{ build_ui(); });
        return;
    }

    CGRect screen = scene.coordinateSpace.bounds;
    CGFloat W = screen.size.width;
    CGFloat H = screen.size.height;

    g_window = [[PassthroughWindow alloc]
        initWithWindowScene:scene];
    g_window.frame = screen;
    g_window.windowLevel = UIWindowLevelNormal + 1;
    g_window.backgroundColor = UIColor.clearColor;

    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = UIColor.clearColor;
    g_window.rootViewController = vc;

    // ── FAB ──
    CGFloat fab_sz = 52;
    g_fab = [[UIButton alloc] initWithFrame:CGRectMake(
        W - fab_sz - 12, H * 0.38, fab_sz, fab_sz)];
    g_fab.backgroundColor =
        [UIColor colorWithRed:0 green:0.85 blue:0.45 alpha:0.93];
    g_fab.layer.cornerRadius = fab_sz / 2;
    g_fab.layer.shadowColor = UIColor.blackColor.CGColor;
    g_fab.layer.shadowOpacity = 0.5;
    g_fab.layer.shadowRadius = 8;
    g_fab.layer.shadowOffset = CGSizeMake(0, 4);
    [g_fab setTitle:@"=" forState:UIControlStateNormal];
    g_fab.titleLabel.font =
        [UIFont systemFontOfSize:22 weight:UIFontWeightBold];
    [g_fab setTitleColor:UIColor.blackColor
                forState:UIControlStateNormal];
    [g_fab addTarget:DisasmController.class
              action:@selector(togglePanel)
    forControlEvents:UIControlEventTouchUpInside];
    [g_fab addGestureRecognizer:[[UIPanGestureRecognizer alloc]
        initWithTarget:DisasmController.class
                action:@selector(fabDragged:)]];
    [g_window addSubview:g_fab];

    // ── Panel ──
    CGFloat pw = W - 24;
    CGFloat ph = H * 0.72;
    g_panel = [[UIView alloc] initWithFrame:CGRectMake(
        12, H - ph - 20, pw, ph)];
    g_panel.backgroundColor =
        [UIColor colorWithWhite:0.04 alpha:0.97];
    g_panel.layer.cornerRadius = 14;
    g_panel.layer.borderWidth = 1;
    g_panel.layer.borderColor =
        [UIColor colorWithRed:0 green:0.85 blue:0.45 alpha:0.4].CGColor;
    g_panel.hidden = YES;
    g_panel.alpha = 0;

    // Header
    UILabel *hdr = [UILabel new];
    hdr.frame = CGRectMake(12, 10, pw-24, 20);
    hdr.text = [NSString stringWithFormat:
        @"◈ FLEXING — %@", g_appname ?: @"app"];
    hdr.font = [UIFont monospacedSystemFontOfSize:11
                                           weight:UIFontWeightBold];
    hdr.textColor =
        [UIColor colorWithRed:0 green:0.85 blue:0.45 alpha:1];
    [g_panel addSubview:hdr];

    // Selector L / H / D
    UISegmentedControl *seg = [[UISegmentedControl alloc]
        initWithItems:@[@"L", @"H", @"D"]];
    seg.frame = CGRectMake(10, 36, pw-20, 30);
    seg.selectedSegmentIndex = 0;
    [seg addTarget:DisasmController.class
            action:@selector(switchTab:)
  forControlEvents:UIControlEventValueChanged];
    [g_panel addSubview:seg];

    // Geometría común
    CGFloat ctl_y = 74;                 // fila de controles
    CGFloat term_y = 146;               // terminal
    CGFloat term_h = ph - term_y - 8;
    CGFloat b3 = (pw - 28) / 3.0;       // ancho de 3 botones

    UIColor *cGreen  = [UIColor colorWithRed:0.1 green:0.5 blue:0.1 alpha:1];
    UIColor *cGray   = [UIColor colorWithWhite:0.3 alpha:1];
    UIColor *cBlue   = [UIColor colorWithRed:0.1 green:0.2 blue:0.6 alpha:1];
    UIColor *cSlate  = [UIColor colorWithRed:0.35 green:0.35 blue:0.4 alpha:1];
    UIColor *cOrange = [UIColor colorWithRed:0.7 green:0.4 blue:0.05 alpha:1];
    UIColor *cRed    = [UIColor colorWithRed:0.6 green:0.12 blue:0.12 alpha:1];
    UIColor *cTeal   = [UIColor colorWithRed:0.05 green:0.5 blue:0.5 alpha:1];
    UIColor *cOlive  = [UIColor colorWithRed:0.35 green:0.35 blue:0.15 alpha:1];
    UIColor *cPurple = [UIColor colorWithRed:0.4 green:0.1 blue:0.5 alpha:1];

    // ── Controles L: TRACE / CLEAR / SAVE / COPY ──
    g_ctlL = [[UIView alloc] initWithFrame:
        CGRectMake(0, ctl_y, pw, 40)];
    {
        CGFloat w = (pw - 32) / 4.0;
        UIButton *bt = mkbtn(@"TRACE", @selector(toggleTrace),
            CGRectMake(10, 0, w, 32), cGreen);
        bt.tag = 200;
        [g_ctlL addSubview:bt];
        [g_ctlL addSubview:mkbtn(@"CLEAR", @selector(clearL),
            CGRectMake(10+(w+4), 0, w, 32), cGray)];
        [g_ctlL addSubview:mkbtn(@"SAVE", @selector(saveL),
            CGRectMake(10+2*(w+4), 0, w, 32), cBlue)];
        [g_ctlL addSubview:mkbtn(@"COPY", @selector(copyL),
            CGRectMake(10+3*(w+4), 0, w, 32), cSlate)];
    }
    [g_panel addSubview:g_ctlL];

    // ── Controles H: campo + RUN / STOP / CLEAR ──
    g_ctlH = [[UIView alloc] initWithFrame:
        CGRectMake(0, ctl_y, pw, 72)];
    g_hookField = mkfield(@"símbolo C (ej: METADeviceIsJailbroken)",
        CGRectMake(10, 0, pw-20, 32));
    [g_ctlH addSubview:g_hookField];
    [g_ctlH addSubview:mkbtn(@"RUN", @selector(hookRun),
        CGRectMake(10, 38, b3, 30), cOrange)];
    [g_ctlH addSubview:mkbtn(@"STOP", @selector(hookStop),
        CGRectMake(10+(b3+4), 38, b3, 30), cRed)];
    [g_ctlH addSubview:mkbtn(@"CLEAR", @selector(clearH),
        CGRectMake(10+2*(b3+4), 38, b3, 30), cGray)];
    g_ctlH.hidden = YES;
    [g_panel addSubview:g_ctlH];

    // ── Controles D: campo + DUMP / IVARS / GOT (+CLEAR) ──
    g_ctlD = [[UIView alloc] initWithFrame:
        CGRectMake(0, ctl_y, pw, 72)];
    g_dumpField = mkfield(@"clase (IGMedia) o filtro GOT (Jailbroken)",
        CGRectMake(10, 0, pw-20, 32));
    [g_ctlD addSubview:g_dumpField];
    [g_ctlD addSubview:mkbtn(@"DUMP", @selector(dDump),
        CGRectMake(10, 38, b3, 30), cTeal)];
    [g_ctlD addSubview:mkbtn(@"IVARS", @selector(dIvars),
        CGRectMake(10+(b3+4), 38, b3, 30), cOlive)];
    [g_ctlD addSubview:mkbtn(@"GOT", @selector(dGot),
        CGRectMake(10+2*(b3+4), 38, b3, 30), cPurple)];
    g_ctlD.hidden = YES;
    [g_panel addSubview:g_ctlD];

    // ── Tres terminales (misma zona, se muestra la activa) ──
    CGRect tf = CGRectMake(6, term_y, pw-12, term_h);
    g_termL = [[TermView alloc] initWithFrame:tf];
    g_termH = [[TermView alloc] initWithFrame:tf];
    g_termD = [[TermView alloc] initWithFrame:tf];
    g_termH.hidden = YES;
    g_termD.hidden = YES;
    [g_panel addSubview:g_termL];
    [g_panel addSubview:g_termH];
    [g_panel addSubview:g_termD];

    [g_window addSubview:g_panel];
    [g_window makeKeyAndVisible];

    // Teclado
    [[NSNotificationCenter defaultCenter]
        addObserver:DisasmController.class
           selector:@selector(kbShow:)
               name:UIKeyboardWillShowNotification object:nil];
    [[NSNotificationCenter defaultCenter]
        addObserver:DisasmController.class
           selector:@selector(kbHide:)
               name:UIKeyboardWillHideNotification object:nil];

    // Intro en L
    LOGL([NSString stringWithFormat:@"App:  %@", g_appname ?: @"?"]);
    LOGL([NSString stringWithFormat:@"Base: 0x%llx", g_base]);
    LOGL(@"─────────────────────────");
    LOGL(@"L=Log  H=Hook  D=Dump. Toca TRACE.");
}

// ── CTOR ──
%ctor {
    find_base();
    atomic_store(&g_running, true);
    pthread_create(&g_thread, NULL, tracer_thread, NULL);
    pthread_detach(g_thread);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
        (int64_t)(3 * NSEC_PER_SEC)),
        dispatch_get_main_queue(), ^{ build_ui(); });
}

