---
title: "Hyperjump" 
date: 2025-10-25
tags: ["Rev"]
description: ""
summary: " "
showToc: true
disableAnchoredHeadings: true

---

---

A ELF binary named `Hyperjump` was given, it is a flag checker binary that will ask for the flag upon running the program

![alt binary](Screenshot_1.png)

Loading the binary into IDA and opening the main function will quickly tell how the algorithm works, but first of all there is a important function named `sub_4350` which need to be looked into first.

```C
__syscall_slong_t sub_4350()
{
  __syscall_slong_t result; // rax
  __int64 v1; // r14
  int *v2; // rax
  int *v3; // rbx
  int v4; // r15d
  FILE *v5; // r12
  int i; // eax
  char v7; // cl
  int v8; // edx
  unsigned int v9; // r14d
  __int64 v10; // [rsp-160h] [rbp-160h]
  unsigned int j; // [rsp-14Ch] [rbp-14Ch]
  struct timespec v12; // [rsp-148h] [rbp-148h] BYREF
  struct timespec v13[19]; // [rsp-138h] [rbp-138h] BYREF

  result = (unsigned int)dword_807C;
  if ( !dword_807C )
  {
    v1 = prctl(4, 0LL) != 0;
    v2 = __errno_location();
    *v2 = 0;
    v3 = v2;
    v10 = syscall(101LL, 0LL, 0LL, 0LL, 0LL);
    if ( v10 == -1 )
    {
      v4 = 424276754;
      if ( *v3 != 1 )
      {
        LODWORD(v1) = v1 | 2;
        v4 = 1834637003;
      }
    }
    else
    {
      v4 = 1834637003;
      syscall(101LL, 17LL, 0LL, 0LL, 0LL);
    }
    v5 = fopen("/proc/self/status", "r");
    if ( v5 )
    {
      while ( fgets((char *)v13, 256, v5) )
      {
        if ( v13[0].tv_sec == 0x6950726563617254LL && LOWORD(v13[0].tv_nsec) == 14948 )
        {
          LODWORD(v1) = (4 * (__isoc23_strtol((char *)&v13[0].tv_nsec + 2, 0LL, 10LL) != 0 && v10 == -1)) | v1;
          break;
        }
      }
      fclose(v5);
    }
    else
    {
      LODWORD(v1) = v1 | 8;
    }
    v12 = 0LL;
    v13[0] = 0LL;
    if ( clock_gettime(1, &v12) )
      LODWORD(v1) = v1 | 0x10;
    for ( i = 0; i != 500000; ++i )
    {
      v7 = i & 7;
      v8 = i ^ v4;
      v4 = __ROL4__(v8, v7 + 1);
    }
    if ( clock_gettime(1, v13) )
    {
      LODWORD(v1) = v1 | 0x20;
      dword_807C = v4 | 1;
      goto LABEL_17;
    }
    if ( (v1 & 0x30) == 0 )
    {
      result = v13[0].tv_nsec + 1000000000 * (v13[0].tv_sec - v12.tv_sec) - v12.tv_nsec;
      if ( result < 0 || (v4 ^= result, result <= 80000000) )
      {
        dword_807C = v4 | 1;
        if ( !(_DWORD)v1 )
          return result;
LABEL_17:
        v9 = (_DWORD)v1 << 11;
        for ( j = 0; j < v9; ++j )
          ;
        _exit(133);
      }
      LODWORD(v1) = v1 | 0x40;
    }
    dword_807C = v4 | 1;
    goto LABEL_17;
  }
  return result;
}
```

this function can be identified as anti-debugging function, as there will be syscall to the ptrace function, there is also some kind of timing algorithm to catch debugger.

in this case I bypassed the whole function to not interfere with the later analysis process, I bypassed the whole checking process by modifying the `jz` function in this part

![alt jump_initial](Screenshot_2.png)

to become `nop` which will always return in any circumstances

![alt jump_after](Screenshot_3.png)

this will make the program to never jump to loc_435B and bypass the anti-debugger check.

Now going back into the main function, the algorithm will first check if our input have length `24`, after that one byte of our input will be processed (index based on `v5`) into 3 variable which will be used in the later process which is `v29`, `v11`, and `v28`.

After that there will be a bunch more process which will be done, but i don't think its important because all of those operations will only be operated on 1 byte every iteration and 24 iteration in total will be done, the only important part is this one

```
    if ( byte_5420[v5] != ((unsigned __int8)(v29.m128i_i8[12] ^ __ROR4__(v19 + v20, (v21 >> 3) & 0x1E | 1)) ^ (unsigned __int8)(v21 ^ v20 ^ v19)) )
    break;
    ++v5;
    v25 += 7LL;
    v27 += 69;
    v26 -= 1640531527;
    if ( v23 == 23 )
    {
        puts("Correct flag, congratulations!");
        return 0LL;
    }
```

so basically in this part, our input which has been processed will be compared into constants which are stored in `byte_5420`, this is how it will looks like in assembly

```
.text:00000000000013CF                 xor     eax, edx
.text:00000000000013D1                 rol     edi, cl
.text:00000000000013D3                 xor     r8d, edi
.text:00000000000013D6                 lea     rdi, byte_5420
.text:00000000000013DD                 mov     ecx, r8d
.text:00000000000013E0                 xor     eax, r8d
.text:00000000000013E3                 shr     ecx, 3
.text:00000000000013E6                 and     ecx, 1Eh
.text:00000000000013E9                 or      ecx, 1
.text:00000000000013EC                 ror     esi, cl
.text:00000000000013EE                 xor     esi, r9d
.text:00000000000013F1                 xor     eax, esi
.text:00000000000013F3                 cmp     [rdi+r15], al
```

so I can actually break on `00000000000013F3` and then check the compared value, if it's correct then my input on current index is correct and I can proceed to find the correct value for the next character. 

This brute force approach can be solved by using some GDB script, in which I'm having some skill issues with, I ended up asking my teammate to create a script and then I modify it a bit so it will run correctly, below is the script

```
import gdb
import string
import os

class FlagBruteForce(gdb.Command):
    def __init__(self):
        super(FlagBruteForce, self).__init__("brute", gdb.COMMAND_USER)
        self.flag = list('A' * 24)
        
    
    def invoke(self, arg, from_tty):
        gdb.execute("set confirm off")
        gdb.execute("starti")

        bp = gdb.Breakpoint(f"*0x5555555553F3")
        pipe_path = '/tmp/gdb_pipe'
        if os.path.exists(pipe_path):
            os.remove(pipe_path)
        os.mkfifo(pipe_path)
        
        for pos in range(24):
            found = False
            print(f"\nskrg di idx {pos}...")
            for c in string.printable:
                self.flag[pos] = c
                test_input = ''.join(self.flag)
                
                with open('/tmp/gdb_input.txt', 'w') as f:
                    f.write(test_input + '\n')
                
                try:
                    gdb.execute("kill", to_string=True)
                except:
                    pass
                
                try:
                    gdb.execute("run < /tmp/gdb_input.txt", to_string=True)
                    temp = pos
                    while temp>0:
                        temp-=1
                        gdb.execute("continue", to_string=True)

                    rdi = int(gdb.parse_and_eval("$rdi"))
                    r15 = int(gdb.parse_and_eval("$r15"))
                    al = int(gdb.parse_and_eval("$al")) & 0xFF

                    expected = int(gdb.parse_and_eval(f"*(unsigned char*)({rdi} + {r15})")) & 0xFF
                    if al == expected:
                        print("="*25)
                        print(f"Idx {pos}: '{c}' (0x{ord(c):02x})")
                        found = True
                        break
                        
                except Exception as e:
                    print(e)
                    continue
            
            if not found:
                print("g ad euy")
                self.flag[pos] = 'A'
            
            print(f"skrg -> {''.join(self.flag)}")
        
        print(f"\nflag: {''.join(self.flag)}")
        bp.delete()
        
        if os.path.exists(pipe_path):
            os.remove(pipe_path)

FlagBruteForce()
```

so basically this script will brute each character, everytime the `cmp` instruction in `0x5555555553F3` (GDB offset) is correct, then it will proceed to brute the character for the next index.

loading the script into GDB will finally return this as output

![alt gdb](Screenshot_4.png)

well that's not right... the flag came out as `flagAm4i3d_vm_jump5__42}`, well luckily the author of this chall noticed that there will be multiple solution, the author is kind enough to give the md5 hash of the real flag, i ended up using this script to find the real flag

```
import hashlib
import string
target="91b713899496c938c4930d6194929ebc"

now=b'flag{m4i3d_vm_jump5__42}'

for j in string.printable:
    for i in string.printable:
        now = b'flag{m4'+j.encode()+b'3d_vm_jump5_'+i.encode()+b'42}'
        if hashlib.md5(now).hexdigest()==target:
            print("FOUND")
            print(now)
```

this will return the flag as `flag{m4z3d_vm_jump5__42}`.

For this challenge I don't think my solution is the intended way and I may have cheezed it as I do not look much into the other function that will be used to process my input, but it is also a great example of how to use the fact that each byte will be compared individually with some constant and use that to create a bruteforce script.

---