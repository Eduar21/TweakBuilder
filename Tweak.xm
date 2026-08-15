// AiSTweak — filtro de canales AI (AiSList) para YouTube iOS
// Fase 1 = RECON. Poné AIS_PROBE en 1, mirá el log, y recién ahí activá el filtro.

// El Makefile lo genera TweakBuilder, así que los flags de warnings van acá.
// Sin esto, -Werror rompe el build por las funciones que quedan sin usar
// según el valor de AIS_PROBE.
#pragma clang diagnostic ignored "-Wunused-function"

#import <UIKit/UIKit.h>
#import <objc/runtime.h>

#define AIS_PROBE 1   // 1 = solo loguea, no oculta nada

#pragma mark - Log a archivo

// Queda en <contenedor de YouTube>/Documents/ais.log
// LiveContainer -> mantener pulsada la app -> datos/archivos -> compartir a Files.
static NSString *AiSLogPath(void) {
    static NSString *path = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSString *dir = NSSearchPathForDirectoriesInDomains(
            NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        path = [[dir stringByAppendingPathComponent:@"ais.log"] copy];
    });
    return path;
}

// Cola serial: los hooks disparan desde varios hilos y el completion de
// NSURLSession desde otro. Sin esto el archivo sale intercalado.
static dispatch_queue_t AiSLogQueue(void) {
    static dispatch_queue_t q = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        q = dispatch_queue_create("com.ais.log", DISPATCH_QUEUE_SERIAL);
    });
    return q;
}

static void AiSWrite(NSString *line) {
    if (!line) return;
    NSString *stamp = [NSString stringWithFormat:@"%.3f  %@\n",
                       [NSDate timeIntervalSinceReferenceDate], line];
    dispatch_async(AiSLogQueue(), ^{
        @autoreleasepool {
            NSString *path = AiSLogPath();
            NSData *d = [stamp dataUsingEncoding:NSUTF8StringEncoding];
            NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
            if (!fh) {
                [[NSFileManager defaultManager] createFileAtPath:path
                                                        contents:d
                                                      attributes:nil];
                return;
            }
            @try {
                [fh seekToEndOfFile];
                [fh writeData:d];
            } @catch (__unused NSException *e) {}
            [fh closeFile];
        }
    });
}

// Borra el log si pasó de 2 MB, para que no crezca sin control entre sesiones.
static void AiSRotateLog(void) {
    NSString *path = AiSLogPath();
    NSDictionary *attrs = [[NSFileManager defaultManager]
                           attributesOfItemAtPath:path error:nil];
    if (attrs && [attrs fileSize] > 2 * 1024 * 1024)
        [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
}

#define AISLog(fmt, ...) do { \
    NSString *_aisline = [NSString stringWithFormat:(fmt), ##__VA_ARGS__]; \
    NSLog(@"[AiS] %@", _aisline); \
    AiSWrite(_aisline); \
} while (0)

static NSString *const kAiSBlockURL =
    @"https://raw.githubusercontent.com/Override92/AiSList/main/AiSList/aislist_blocklist.txt";
static NSString *const kAiSWarnURL =
    @"https://raw.githubusercontent.com/Override92/AiSList/main/AiSList/aislist_warnlist.txt";

#pragma mark - Store

@interface AiSStore : NSObject
@property (nonatomic, strong) NSSet<NSString *> *handles;   // sin '@', minúsculas
@property (nonatomic, assign) NSUInteger hits;
+ (instancetype)shared;
- (void)load;
- (BOOL)dataMatches:(NSData *)data matched:(NSString **)out;
@end

@implementation AiSStore

+ (instancetype)shared {
    static AiSStore *s = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [AiSStore new]; });
    return s;
}

- (NSString *)cachePath {
    NSString *dir = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES).firstObject;
    return [dir stringByAppendingPathComponent:@"aislist_blocklist.txt"];
}

- (void)parseText:(NSString *)text {
    NSMutableSet *set = [NSMutableSet setWithCapacity:24000];
    [text enumerateLinesUsingBlock:^(NSString *line, BOOL *stop) {
        (void)stop;
        NSString *l = [line stringByTrimmingCharactersInSet:
                       [NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (l.length < 2 || [l hasPrefix:@"!"]) return;
        if ([l hasPrefix:@"@"]) l = [l substringFromIndex:1];
        [set addObject:[l lowercaseString]];
    }];
    self.handles = set;
    AISLog(@"lista cargada: %lu handles", (unsigned long)set.count);
}

- (void)load {
    NSString *path = [self cachePath];
    NSString *cached = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil];
    if (cached.length) [self parseText:cached];

    // refresco en background (cada arranque; si querés, chequeá mtime < 24h antes)
    NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    NSURLSession *ses = [NSURLSession sessionWithConfiguration:cfg];
    [[ses dataTaskWithURL:[NSURL URLWithString:kAiSBlockURL]
        completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
            (void)resp;
            if (err || data.length < 1000) { AISLog(@"refresh falló: %@", err); return; }
            NSString *txt = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            if (!txt) return;
            [txt writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
            [self parseText:txt];
        }] resume];
}

// Escanea el blob buscando candidatos "@handle" y los resuelve por hash.
// O(n) sobre los bytes: no itera los 20k handles.
- (BOOL)dataMatches:(NSData *)data matched:(NSString **)out {
    NSSet *set = self.handles;
    if (!set.count || data.length == 0) return NO;

    const unsigned char *b = (const unsigned char *)data.bytes;
    NSUInteger len = data.length;
    char buf[80];

    for (NSUInteger i = 0; i + 3 < len; i++) {
        if (b[i] != '@') continue;
        NSUInteger j = 0;
        NSUInteger k = i + 1;
        while (k < len && j < sizeof(buf) - 1) {
            unsigned char c = b[k];
            BOOL ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                      (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
            if (!ok) break;
            buf[j++] = (char)(c >= 'A' && c <= 'Z' ? c + 32 : c);
            k++;
        }
        if (j < 3) continue;
        buf[j] = '\0';
        NSString *cand = [[NSString alloc] initWithBytes:buf length:j encoding:NSASCIIStringEncoding];
        if (cand && [set containsObject:cand]) {
            if (out) *out = cand;
            return YES;
        }
        i = k - 1;
    }
    return NO;
}

@end

#pragma mark - Recon: encontrar de dónde sacar el protobuf

// Loguea todos los métodos sin argumentos de una clase que devuelven objetos,
// para descubrir cuál te da el NSData del elemento.
static void AiSDumpClass(const char *name) {
    Class cls = objc_getClass(name);
    if (!cls) { AISLog(@"clase %s NO existe en este build", name); return; }
    unsigned int n = 0;
    Method *m = class_copyMethodList(cls, &n);
    AISLog(@"=== %s (%u métodos)", name, n);
    for (unsigned int i = 0; i < n; i++) {
        SEL sel = method_getName(m[i]);
        if (method_getNumberOfArguments(m[i]) != 2) continue;
        char ret[16];
        method_getReturnType(m[i], ret, sizeof(ret));
        if (ret[0] == '@') AISLog(@"   -[%s %@]", name, NSStringFromSelector(sel));
    }
    free(m);
}

// Dado cualquier objeto, busca ivars de tipo NSData y reporta si traen handles.
static void AiSProbeObject(id obj) {
    if (!obj) return;
    Class cls = object_getClass(obj);
    unsigned int n = 0;
    Ivar *ivars = class_copyIvarList(cls, &n);
    for (unsigned int i = 0; i < n; i++) {
        const char *type = ivar_getTypeEncoding(ivars[i]);
        if (!type || type[0] != '@') continue;
        id val = object_getIvar(obj, ivars[i]);
        if (![val isKindOfClass:[NSData class]]) continue;
        NSData *d = (NSData *)val;
        NSString *hit = nil;
        BOOL m = [[AiSStore shared] dataMatches:d matched:&hit];
        AISLog(@"%s.%s -> NSData %lu bytes | match=%@ (%@)",
               class_getName(cls), ivar_getName(ivars[i]),
               (unsigned long)d.length, m ? @"SI" : @"no", hit ?: @"-");
    }
    free(ivars);
}

#pragma mark - Hooks

// Ajustá el nombre real después del recon. En builds recientes de YouTube iOS
// los elementos del feed viven en el framework "Elements" (clases ELM*)
// y el protobuf serializado en YTIElementRenderer.
%hook YTIElementRenderer

- (NSData *)elementData {
    NSData *d = %orig;
#if AIS_PROBE
    static NSUInteger seen = 0;
    if (d.length && seen < 30) {
        seen++;
        NSString *hit = nil;
        BOOL m = [[AiSStore shared] dataMatches:d matched:&hit];
        AISLog(@"elementData #%lu %lu bytes match=%@ (%@)",
               (unsigned long)seen, (unsigned long)d.length, m ? @"SI" : @"no", hit ?: @"-");
    }
#endif
    return d;
}

%end

// Ocultado: se marca el nodo/celda con altura 0.
// ELMCellNode hereda de ASCellNode (Texture), así que usamos KVC para no
// depender de headers de AsyncDisplayKit.
static void AiSHideNode(id node) {
    if ([node respondsToSelector:@selector(setHidden:)])
        [node setValue:@YES forKey:@"hidden"];
    @try {
        id style = [node valueForKey:@"style"];
        if (style) {
            [style setValue:@0 forKey:@"height"];   // puede requerir ASDimension real
            [style setValue:@0 forKey:@"minHeight"];
            [style setValue:@0 forKey:@"maxHeight"];
        }
    } @catch (__unused NSException *e) {}
}

%hook ELMCellNode

- (void)didLoad {
    %orig;
#if AIS_PROBE
    static NSUInteger seen = 0;
    if (seen < 10) { seen++; AiSProbeObject(self); }
#else
    // Buscá el renderer asociado y compará. Ajustar tras el recon:
    @try {
        id ctrl = [self valueForKey:@"nodeController"];
        id renderer = ctrl ? [ctrl valueForKey:@"renderer"] : nil;
        NSData *d = renderer ? [renderer valueForKey:@"elementData"] : nil;
        NSString *hit = nil;
        if ([d isKindOfClass:[NSData class]] &&
            [[AiSStore shared] dataMatches:d matched:&hit]) {
            [AiSStore shared].hits++;
            AISLog(@"bloqueado @%@ (total %lu)", hit, (unsigned long)[AiSStore shared].hits);
            AiSHideNode(self);
        }
    } @catch (__unused NSException *e) {}
#endif
}

%end

#pragma mark - Init

%ctor {
    @autoreleasepool {
        AiSRotateLog();
        AISLog(@"===== sesión nueva =====");
        AISLog(@"log: %@", AiSLogPath());
        [[AiSStore shared] load];
        AISLog(@"AiSTweak cargado en %@", [[NSBundle mainBundle] bundleIdentifier]);
#if AIS_PROBE
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(8 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            AiSDumpClass("YTIElementRenderer");
            AiSDumpClass("ELMCellNode");
            AiSDumpClass("ELMNodeController");
        });
#endif
    }
}



