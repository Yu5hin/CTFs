# Reverse Me

>Don’t complain if you can’t see me, because I have to be reversed to make me run 🙃

---

![image](https://github.com/user-attachments/assets/72b06e63-8415-4b57-9fd8-c7b65863e089)


I receive a jpg file but in that doesn't have any thing.And whwn I check by DiE, I see it is data file type.

```
> xxd img.jpg
00003800: 0000 0000 0000 0318 0000 0000 0000 0318  ................
00003810: 0000 0004 0000 0003 0000 0000 0000 0008  ................
00003820: 0000 0000 0000 02d8 0000 0000 0000 02d8  ................
00003830: 0000 0000 0000 0040 0000 0000 0000 0040  .......@.......@
00003840: 0000 0000 0000 0040 0000 0004 0000 0006  .......@........
00003850: 001c 001d 0040 000d 0038 0040 0000 0000  .....@...8.@....
00003860: 0000 0000 0000 3148 0000 0000 0000 0040  ......1H.......@
00003870: 0000 0000 0000 1310 0000 0001 003e 0003  .............>..
00003880: 0000 0000 0000 0000 0001 0102 464c 457f  ............FLE.
```
At the end of the hexdump value I noticed on a word `FLE` I look like reverse form of `ELF` so I thing this is a reversed file. 

So I will reverse all the bytes to make this file to ELF file type

```python
input_file = "c:\\Users\\phong\\Downloads\\img.jpg"
output_file = "img.exe"

with open (input_file, 'rb') as file:
    reverse_byte = file.read()[::-1]

with open (output_file, 'wb') as reverse_file:
    reverse_file.write(reverse_byte)
    
print('Done')
```

Ok now I can decompile it in IDA

```
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  int v3; // ebp
  int v4; // r12d
  int v5; // r13d
  int v6; // ebx
  __int64 v7; // rax
  __int64 v8; // rax
  __int64 v9; // r9
  __int64 v10; // r8
  char *v11; // rbp
  __int64 v12; // [rsp-8h] [rbp-C0h]
  _BYTE src[32]; // [rsp+20h] [rbp-98h] BYREF
  _BYTE v14[56]; // [rsp+40h] [rbp-78h] BYREF
  unsigned __int64 v15; // [rsp+78h] [rbp-40h]

  v15 = __readfsqword(0x28u);
  if ( a1 == 5 )
  {
    v3 = strtol(a2[1], 0LL, 10);
    v4 = strtol(a2[2], 0LL, 10);
    v5 = strtol(a2[3], 0LL, 10);
    v6 = strtol(a2[4], 0LL, 10);
    if ( (unsigned __int8)sub_1460((unsigned int)v3, (unsigned int)v4, (unsigned int)v5, (unsigned int)v6) )
    {
      v7 = (unsigned int)-v6;
      if ( v6 > 0 )
        v7 = (unsigned int)v6;
      v12 = v7;
      v8 = (unsigned int)-v5;
      if ( v5 > 0 )
        v8 = (unsigned int)v5;
      v9 = (unsigned int)-v4;
      if ( v4 > 0 )
        v9 = (unsigned int)v4;
      v10 = (unsigned int)-v3;
      if ( v3 > 0 )
        v10 = (unsigned int)v3;
      __sprintf_chk(v14, 1LL, 42LL, "%d%d%d%d", v10, v9, v8, v12);
      qmemcpy(src, &unk_2016, 0x19uLL);
      v11 = (char *)sub_1A50(src, 0x18uLL);
      puts(v11);
      free(v11);
      exit(0);
    }
  }
  exit(-1);
}
```

At main fuction,
