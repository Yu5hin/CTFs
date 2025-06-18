# Static Analysis
---

```
// positive sp value has been detected, the output may be wrong!
char mainCRTStartup_0()
{
  int v0; // eax
  unsigned __int64 v1; // rax
  int v2; // ebx
  unsigned __int64 v3; // rax
  int (__cdecl *v4)(int, const char **, const char **); // eax

  LOBYTE(v0) = NtCurrentPeb()->BeingDebugged;
  if ( !(_BYTE)v0 )
  {
    LOBYTE(v0) = NtCurrentPeb()->UnicodeCaseTableData;
    if ( !(_BYTE)v0 )
    {
      v1 = __rdtsc();
      v2 = v1;
      v3 = __rdtsc();
      v0 = v3 - v2;
      if ( v0 <= 1000 )
      {
        v4 = main;
        do
        {
          *(_BYTE *)v4 ^= 0x5Cu;
          v4 = (int (__cdecl *)(int, const char **, const char **))((char *)v4 + 1);
        }
        while ( (int)v4 <= (int)sub_401791 );
        mingw_app_type = 0;
        __security_init_cookie();
        LOBYTE(v0) = __tmainCRTStartup();
      }
    }
  }
  return v0;
}
```


In IDA, at mainCRtStartup fuction I see a anti-debug boot section and a self-modifying code:

```
        v4 = main;
        do
        {
          *(_BYTE *)v4 ^= 0x5Cu;
          v4 = (int (__cdecl *)(int, const char **, const char **))((char *)v4 + 1);
        }
        while ( (int)v4 <= (int)sub_401791 );
```

when I pointer into `main` it show me a confusing code and looks like it's missing 

![image](https://github.com/user-attachments/assets/1764bbac-6c5d-46af-a096-659d7d79bb05)


I will analysis it on `x32dbg`, at least I known main fuction address `401620`

$ Dynamic Analysis

When start debugging you shouldn't set breakpoint at main fuction address, you should set it at `Entrypoint` cuz it very likely that program was previously infected with anti-debug.

In x32/64 it is `OptionalHeader/AddressOÈntryPoint`. 

![image](https://github.com/user-attachments/assets/ed61fc44-7f4a-429f-8972-f32d69b17bcb)

At entrypoint the program about to jump to `408904` address. I setted breakpoint at this current address is `4010f9` and step into `408904`

After go into 408904 I will set breakpoint and step into each address to analysis flow of the program

![image](https://github.com/user-attachments/assets/37e42a0a-5172-4545-9d98-0e15b9dd9c4e)

At here the program is compare eax with 3E8 if `eax` greater, the program will jump to `408922`.

![image](https://github.com/user-attachments/assets/fe80db87-5496-4784-a799-ff00d86b3c62)

and if it jump to 408922 maybe the program will be break you can see detail in image above. The text `sp-analysis failed` could be a sign that this section is infected with anti-debugg. So i will edit `ZF` (Zeroflag) from 0 to 1 mean that It's always a true condition. And continue step.



