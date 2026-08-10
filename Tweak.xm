
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/dyld.h>

// FAT structs
struct fat_header_t { uint32_t magic; uint32_t nfat_arch; };
struct fat_arch_t {
    int32_t cputype; int32_t cpusubtype;
    uint32_t offset; uint32_t size; uint32_t align;
};

#define MAX_SYM 4096
#define OUT_MAX (1024*512)
typedef struct { uint64_t addr; char name[256]; } Sym;

static char  *g_out = NULL;
static size_t g_len = 0;

static void out(const char *fmt, ...) {
    va_list a; char tmp[1024];
    va_start(a, fmt); vsnprintf(tmp,sizeof(tmp),fmt,a); va_end(a);
    size_t l = strlen(tmp);
    if (g_out && g_len+l+1 < OUT_MAX) {
        memcpy(g_out+g_len,tmp,l);
        g_len+=l; g_out[g_len]='\0';
    }
}

void decode_arm64(uint32_t e, uint64_t addr,
                  char *mn, char *ops) {
    mn[0]=ops[0]='\0';
    if (e==0xD503237F){strcpy(mn,"PACIBSP");return;}
    if (e==0xD65F0FFF){strcpy(mn,"RETAB");return;}
    if (e==0xD503201F){strcpy(mn,"NOP");return;}
    if (e==0xD65F03C0){strcpy(mn,"RET");strcpy(ops,"x30");return;}
    if ((e&0xFFE0001F)==0xD4000001){
        strcpy(mn,"SVC");sprintf(ops,"#%u",(e>>5)&0xFFFF);return;}
    if ((e&0xFC000000)==0x94000000){
        int32_t off=(int32_t)((e&0x03FFFFFF)<<6)>>4;
        strcpy(mn,"BL");sprintf(ops,"0x%llx",addr+(int64_t)off);return;}
    if ((e&0xFC000000)==0x14000000){
        int32_t off=(int32_t)((e&0x03FFFFFF)<<6)>>4;
        strcpy(mn,"B");sprintf(ops,"0x%llx",addr+(int64_t)off);return;}
    if ((e&0xFFFFFC1F)==0xD63F0000){
        strcpy(mn,"BLR");sprintf(ops,"x%u",(e>>5)&0x1F);return;}
    if ((e&0x9F000000)==0x90000000){
        uint32_t rd=e&0x1F;
        int64_t immlo=(e>>29)&0x3,immhi=(int64_t)((e>>5)&0x7FFFF);
        int64_t imm=((immhi<<2)|immlo)<<12;
        if(imm&(1LL<<32))imm|=~((1LL<<33)-1);
        strcpy(mn,"ADRP");
        sprintf(ops,"x%u, 0x%llx",rd,(addr&~0xFFFULL)+imm);return;}
    if ((e&0x7F000000)==0x11000000){
        strcpy(mn,"ADD");
        sprintf(ops,"x%u, x%u, #%u",e&0x1F,(e>>5)&0x1F,(e>>10)&0xFFF);return;}
    if ((e&0x7F000000)==0xD1000000||
        (e&0x7F000000)==0x51000000){
        strcpy(mn,"SUB");
        sprintf(ops,"x%u, x%u, #%u",e&0x1F,(e>>5)&0x1F,(e>>10)&0xFFF);return;}
    if ((e&0xFFC00000)==0xF9400000){
        strcpy(mn,"LDR");
        sprintf(ops,"x%u, [x%u, #%u]",e&0x1F,(e>>5)&0x1F,((e>>10)&0xFFF)*8);return;}
    if ((e&0xFFC00000)==0xF9000000){
        strcpy(mn,"STR");
        sprintf(ops,"x%u, [x%u, #%u]",e&0x1F,(e>>5)&0x1F,((e>>10)&0xFFF)*8);return;}
    if ((e&0xFF000010)==0x54000000){
        const char*cc[]={"EQ","NE","CS","CC","MI","PL","VS","VC",
                         "HI","LS","GE","LT","GT","LE","AL","NV"};
        int32_t off=(int32_t)((e>>5)&0x7FFFF);
        if(off&0x40000)off|=~0x7FFFF; off<<=2;
        sprintf(mn,"B.%s",cc[e&0xF]);
        sprintf(ops,"0x%llx",addr+(int64_t)off);return;}
    if ((e&0x7F000000)==0x34000000){
        int32_t off=(int32_t)((e&0x00FFFFE0)>>3);
        strcpy(mn,"CBZ");
        sprintf(ops,"x%u, 0x%llx",e&0x1F,addr+(int64_t)off);return;}
    if ((e&0x7F000000)==0x35000000){
        int32_t off=(int32_t)((e&0x00FFFFE0)>>3);
        strcpy(mn,"CBNZ");
        sprintf(ops,"x%u, 0x%llx",e&0x1F,addr+(int64_t)off);return;}
    if ((e&0x1F800000)==0x52800000||
        (e&0x1F800000)==0xD2800000){
        uint32_t rd=e&0x1F,imm=(e>>5)&0xFFFF,sh=((e>>21)&0x3)*16;
        strcpy(mn,"MOV");
        if(sh)sprintf(ops,"x%u, #0x%x lsl #%u",rd,imm,sh);
        else  sprintf(ops,"x%u, #0x%x",rd,imm);return;}
    strcpy(mn,"???"); sprintf(ops,"%08x",e);
}

int parse_syms(uint8_t *data, struct symtab_command *sc,
               Sym *syms, int max) {
    if (!sc) return 0;
    struct nlist_64 *nl=(struct nlist_64*)(data+sc->symoff);
    char *st=(char*)(data+sc->stroff);
    int n=0;
    for (uint32_t i=0;i<sc->nsyms&&n<max;i++) {
        if (!nl[i].n_value||!nl[i].n_un.n_strx) continue;
        const char *nm=st+nl[i].n_un.n_strx;
        if (!strlen(nm)) continue;
        syms[n].addr=nl[i].n_value;
        strncpy(syms[n].name,nm,255);
        syms[n].name[255]='\0'; n++;
    }
    return n;
}

static void run_analysis(void) {
    g_out=(char*)malloc(OUT_MAX);
    if(!g_out) return;
    g_out[0]='\0'; g_len=0;

    out("╔══════════════════════════════════╗\n");
    out("║  PANDORA DISASSEMBLER v1.0       ║\n");
    out("╚══════════════════════════════════╝\n\n");

    // Info del proceso
    out("Bundle: %s\n",
        [NSBundle mainBundle].bundleIdentifier.UTF8String?:"?");
    out("PID: %d\n\n", getpid());

    const char *binpath = _dyld_get_image_name(0);
    out("Binario: %s\n\n", binpath);

    // Leer desde disco
    FILE *f = fopen(binpath, "rb");
    uint8_t *data = NULL;
    size_t fsize = 0;

    if (!f) {
        // Fallback: analizar desde memoria
        out("Disco bloqueado — analizando desde memoria\n\n");
        const struct mach_header_64 *mh =
            (const struct mach_header_64*)_dyld_get_image_header(0);
        intptr_t slide = _dyld_get_image_vmaddr_slide(0);

        out("Header: 0x%llx\n", (uint64_t)mh);
        out("Slide:  0x%llx\n\n", (uint64_t)slide);

        uint8_t *lc = (uint8_t*)mh + sizeof(struct mach_header_64);
        uint64_t tv=0, ts=0;
        for (uint32_t i=0;i<mh->ncmds;i++) {
            struct load_command *cmd=(struct load_command*)lc;
            if (cmd->cmd==LC_SEGMENT_64) {
                struct segment_command_64 *seg=
                    (struct segment_command_64*)lc;
                struct section_64 *sec=
                    (struct section_64*)(lc+sizeof(*seg));
                for (uint32_t j=0;j<seg->nsects;j++) {
                    if (!strncmp(sec[j].sectname,"__text",6)&&
                        !strncmp(seg->segname,"__TEXT",6)){
                        tv=sec[j].addr; ts=sec[j].size;
                    }
                }
            }
            lc+=cmd->cmdsize;
        }
        if (tv && ts) {
            uint64_t real=tv+(uint64_t)slide;
            out("=== DISASSEMBLY desde memoria ===\n");
            out("addr: 0x%llx | %llu instrs\n\n",real,ts/4);
            uint32_t *code=(uint32_t*)(uintptr_t)real;
            size_t n=ts/4; if(n>120)n=120;
            int bl=0,svc=0,byp=0;
            for (size_t i=0;i<n;i++) {
                uint32_t enc=code[i];
                uint64_t ia=real+i*4;
                char mn[64],ops[128];
                decode_arm64(enc,ia,mn,ops);
                if (!strcmp(mn,"BL")||!strcmp(mn,"BLR")||
                    !strcmp(mn,"SVC"))
                    out(">>> 0x%llx  %-8s  %s\n",ia,mn,ops);
                else if (!strcmp(mn,"RET")||!strcmp(mn,"RETAB"))
                    out("<<< 0x%llx  %-8s  %s\n",ia,mn,ops);
                else
                    out("    0x%llx  %-8s  %s\n",ia,mn,ops);
                if((enc&0xFC000000)==0x94000000) bl++;
                if((enc&0xFFE0001F)==0xD4000001) svc++;
                if(i+1<n&&(enc==0x52800020||enc==0xD2800020)&&
                   code[i+1]==0xD65F03C0){
                    byp++;
                    if(byp<=5)out("\nBYPASS 0x%llx\n",ia);
                }
            }
            out("\nBL:%d SVC:%d Bypasses:%d\n",bl,svc,byp);
        }
        out("\n=== FIN (modo memoria) ===\n");
        return;
    }

    // Modo disco
    fseek(f,0,SEEK_END); fsize=(size_t)ftell(f); fseek(f,0,SEEK_SET);
    data=(uint8_t*)malloc(fsize);
    if(!data){fclose(f);return;}
    fread(data,1,fsize,f); fclose(f);
    out("Archivo: %zu MB\n\n",fsize/1024/1024);

    // FAT
    uint32_t magic=*(uint32_t*)data;
    uint8_t *macho=data;
    if (magic==0xCAFEBABE||magic==0xBEBAFECA) {
        struct fat_header_t *fh=(struct fat_header_t*)data;
        uint32_t na=__builtin_bswap32(fh->nfat_arch);
        struct fat_arch_t *fa=(struct fat_arch_t*)
            (data+sizeof(struct fat_header_t));
        for (uint32_t i=0;i<na;i++) {
            if (__builtin_bswap32(fa[i].cputype)==0x0100000C) {
                macho=data+__builtin_bswap32(fa[i].offset);
                out("FAT → ARM64\n\n"); break;
            }
        }
    }

    // Header
    struct mach_header_64 *hdr=(struct mach_header_64*)macho;
    out("=== MACH-O HEADER ===\n");
    out("Type:  %s\n",hdr->filetype==2?"EXECUTE":
        hdr->filetype==6?"DYLIB":"OTHER");
    out("Cmds:  %u\n",hdr->ncmds);
    out("Flags: 0x%x%s\n\n",hdr->flags,
        (hdr->flags&0x200000)?" [PIE]":"");

    uint64_t tv=0,to=0,ts=0;
    struct symtab_command *symtab=NULL;
    uint8_t *lc=macho+sizeof(struct mach_header_64);
    out("=== SECCIONES ===\n");
    for (uint32_t i=0;i<hdr->ncmds;i++) {
        struct load_command *cmd=(struct load_command*)lc;
        if (cmd->cmd==LC_SEGMENT_64) {
            struct segment_command_64 *seg=
                (struct segment_command_64*)lc;
            struct section_64 *sec=
                (struct section_64*)(lc+sizeof(*seg));
            for (uint32_t j=0;j<seg->nsects;j++) {
                out("  %-20s 0x%llx (%llu)\n",
                    sec[j].sectname,sec[j].addr,sec[j].size);
                if (!strncmp(sec[j].sectname,"__text",6)&&
                    !strncmp(seg->segname,"__TEXT",6)){
                    tv=sec[j].addr;
                    to=sec[j].offset;
                    ts=sec[j].size;
                }
            }
        } else if (cmd->cmd==LC_SYMTAB)
            symtab=(struct symtab_command*)lc;
        lc+=cmd->cmdsize;
    }

    Sym *syms=(Sym*)malloc(MAX_SYM*sizeof(Sym));
    int nsyms=0;
    if (syms&&symtab) {
        nsyms=parse_syms(macho,symtab,syms,MAX_SYM);
        out("\nSimbolos: %d\n",nsyms);
        for (int s=0;s<nsyms&&s<15;s++)
            out("  0x%llx  %s\n",syms[s].addr,syms[s].name);
    }

    if (tv&&ts) {
        out("\n=== DISASSEMBLY __text ===\n");
        out("vmaddr: 0x%llx | %llu instrs\n\n",tv,ts/4);
        uint32_t *code=(uint32_t*)(macho+to);
        size_t n=ts/4; if(n>120)n=120;
        int bl=0,ret=0,svc=0,pac=0,byp=0;
        for (size_t i=0;i<n;i++) {
            uint32_t enc=code[i];
            uint64_t ia=tv+i*4;
            if (syms) for(int s=0;s<nsyms;s++)
                if(syms[s].addr==ia)
                    out("\n<%s>:\n",syms[s].name);
            char mn[64],ops[128];
            decode_arm64(enc,ia,mn,ops);
            if (!strcmp(mn,"BL")||!strcmp(mn,"BLR")||
                !strcmp(mn,"SVC"))
                out(">>> 0x%llx  %-8s  %s\n",ia,mn,ops);
            else if (!strcmp(mn,"RET")||!strcmp(mn,"RETAB"))
                out("<<< 0x%llx  %-8s  %s\n",ia,mn,ops);
            else
                out("    0x%llx  %-8s  %s\n",ia,mn,ops);
        }
        // Stats
        uint32_t *full=(uint32_t*)(macho+to);
        size_t fn=ts/4;
        for (size_t i=0;i<fn;i++) {
            uint32_t e=full[i];
            if((e&0xFC000000)==0x94000000)bl++;
            if(e==0xD65F03C0||e==0xD65F0FFF)ret++;
            if((e&0xFFE0001F)==0xD4000001)svc++;
            if(e==0xD503237F||e==0xD65F0FFF)pac++;
            if(i+1<fn&&(e==0x52800020||e==0xD2800020)&&
               full[i+1]==0xD65F03C0){
                byp++;
                uint64_t ba=tv+i*4;
                uint64_t best=0; const char*bn="???";
                if(syms)for(int s=0;s<nsyms;s++)
                    if(syms[s].addr<=ba&&syms[s].addr>best){
                        best=syms[s].addr;bn=syms[s].name;}
                if(byp<=8)out("\nBYPASS 0x%llx → %s\n",ba,bn);
            }
        }
        out("\n=== STATS ===\n");
        out("BL:%d RET:%d SVC:%d PAC:%s Bypasses:%d\n",
            bl,ret,svc,pac>0?"SI":"NO",byp);
    }
    if(syms)free(syms);
    free(data);
    out("\n=== FIN ===\n");
}

static void show_overlay(NSString *text) {
    dispatch_async(dispatch_get_main_queue(), ^{
        CGRect screen = [UIScreen mainScreen].bounds;
        UIWindow *win = [[UIWindow alloc]
            initWithFrame:screen];
        win.windowLevel = UIWindowLevelAlert + 100;
        win.backgroundColor =
            [UIColor colorWithRed:0 green:0 blue:0 alpha:0.93];

        UITextView *tv = [[UITextView alloc]
            initWithFrame:CGRectMake(0,50,
                screen.size.width,
                screen.size.height-90)];
        tv.text = text;
        tv.editable = NO;
        tv.backgroundColor = [UIColor clearColor];
        tv.textColor = [UIColor colorWithRed:0
                                       green:1
                                        blue:0.53
                                       alpha:1];
        tv.font = [UIFont fontWithName:@"Courier New"
                                  size:9.5];
        [win addSubview:tv];

        UIButton *btn = [UIButton
            buttonWithType:UIButtonTypeSystem];
        btn.frame = CGRectMake(
            screen.size.width/2-50,
            screen.size.height-48,
            100, 38);
        [btn setTitle:@"CERRAR"
             forState:UIControlStateNormal];
        [btn setTitleColor:[UIColor whiteColor]
                  forState:UIControlStateNormal];

        // Guardar referencia a window para cerrar
        objc_setAssociatedObject(btn, "win",
            win, OBJC_ASSOCIATION_RETAIN);
        [btn addTarget:btn
                action:@selector(win_close)
      forControlEvents:UIControlEventTouchUpInside];
        [win addSubview:btn];
        [win makeKeyAndVisible];

        // Guardar log
        NSString *docs =
            NSSearchPathForDirectoriesInDomains(
                NSDocumentDirectory,
                NSUserDomainMask, YES).firstObject;
        NSString *path = [docs
            stringByAppendingPathComponent:
            @"pandora_disasm.txt"];
        [text writeToFile:path
               atomically:YES
                 encoding:NSUTF8StringEncoding
                    error:nil];
        NSLog(@"[Disasm] Log: %@", path);
    });
}

static void *analysis_thread(void *arg) {
    sleep(3);
    run_analysis();
    if (g_out && g_len > 0) {
        NSString *result = [NSString
            stringWithUTF8String:g_out];
        show_overlay(result);
    }
    return NULL;
}

%ctor {
    pthread_t t;
    pthread_create(&t, NULL, analysis_thread, NULL);
    pthread_detach(t);
}
