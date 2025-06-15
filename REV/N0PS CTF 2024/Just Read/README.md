# Just Read

> Find a way to break this.
>
>[main](https://github.com/Yu5hin/CTFs/raw/refs/heads/main/REV/N0PS%20CTF%202024/Just%20Read/main)
>
---

```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  bool v3; // bl
  char *s; // [rsp+18h] [rbp-18h]

  s = (char *)argv[1];
  v3 = s[22] == 125
    && s[21] == 116
    && s[20] == 78
    && s[19] == 49
    && s[18] == 95
    && s[17] == 115
    && s[16] == 116
    && s[15] == 105
    && s[14] == 98
    && s[13] == 56
    && s[12] == 95
    && s[11] == 115
    && s[10] == 49
    && s[9] == 95
    && s[8] == 114
    && s[7] == 52
    && s[6] == 72
    && s[5] == 99
    && s[4] == 123
    && s[3] == 83
    && s[2] == 80
    && *s == 78
    && s[1] == 48;
  if ( (v3 & (strlen(s) == 23)) != 0 )
    puts("Well done, you can validate with this flag!");
  else
    puts("Wrong flag!");
  return 0;
}
```

open it in IDA, I can see thuật toán at main fuction, quite clear and easy to understand.

# Solution

```python
ascii_char = [78, 48, 80, 83, 123, 99, 72, 52, 114, 95, 49, 115, 95, 56, 98, 105, 116, 115, 95, 49, 78, 116, 125]

values = [chr(char) for char in ascii_char]
flag = ''.join(values[::-1])

print(flag[::-1])

N0PS{cH4r_1s_8bits_1Nt}
```
