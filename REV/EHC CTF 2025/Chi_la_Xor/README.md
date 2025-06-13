# EHCTF 2025

![image](https://github.com/user-attachments/assets/7536d302-4dfc-4f21-b8cd-4335177d813e)

> [XorCoBan.exe](https://github.com/Yu5hin/CTFs/raw/refs/heads/main/REV/EHC%20CTF%202025/Chi_la_Xor/XorCoBan123.exe)

---

```
$ xxd XorCoBan123.java | head
00000000: 5a4d 0090 0003 0000 0004 0000 ffff 0000  ZM..............
00000010: 00b8 0000 0000 0000 0040 0000 0000 0000  .........@......
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0000 0080 0000  ................
00000040: 1f0e 0eba b400 cd09 b821 4c01 21cd 6854  .........!L.!.hT
00000050: 7369 7020 6f72 7267 6d61 6320 6e61 6f6e  sip orrgmac naon
00000060: 2074 6562 7220 6e75 6920 206e 4f44 2053   tebr nui  nOD S
00000070: 6f6d 6564 0d2e 0a0d 0024 0000 0000 0000  omed.....$......
00000080: 4550 0000 8664 0011 608c 67b2 8400 0001  EP...d..`.g.....
00000090: 05c5 0000 00f0 0027 020b 1802 1e00 0000  .......'........
```

Mình nhận được 1 file java nhưng khi kiểm tra nó lại không phải 1 file java. Với file signature là `ZM` và có 1 chuỗi lạ

```
00000040: 1f0e 0eba b400 cd09 b821 4c01 21cd 6854  .........!L.!.hT
00000050: 7369 7020 6f72 7267 6d61 6320 6e61 6f6e  sip orrgmac naon
00000060: 2074 6562 7220 6e75 6920 206e 4f44 2053   tebr nui  nOD S
```

với chuỗi này mình biết rằng file đã bị đổi cấu trúc. Có thể chuỗi này là `This is a program cannot be run in DOS` và bị đổi theo phương thức 2 byte cạnh nhau. VD `54: T` vs `68: h`, `69: i` vs `73: s`.Và tương tự với file signature trên kia thì đây chắc chắn là 1 file PE (`MZ`: 4d5a). Mình sẽ viết script để đổi lại cấu trúc file

```python
def Swap_Byte():
    with open("XorCoBan123.java", "rb") as f:
        encrypt = f.read()

    n = len(encrypt)
    data = bytearray(n)

    for i in range(0, n , 2):
        first = encrypt[i]
        second = encrypt[i + 1]
        data[i] = second
        data[i + 1] = first

    with open("justXor.exe", "wb") as f:
        f.write(data)
```
sau khi có được file exe mình mở nó trong IDA. và trong hàm main có

```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  FILE *v3; // rax
  char Buffer[112]; // [rsp+20h] [rbp-80h] BYREF
  __int64 v6; // [rsp+90h] [rbp-10h]
  int v7; // [rsp+9Ch] [rbp-4h]

  sub_402280(argc, argv, envp);
  puts("Wellcome to EHCTF 2025");
  v3 = __iob_func();
  fgets(Buffer, 100, v3);
  v7 = strlen(Buffer);
  if ( Buffer[v7 - 1] == 10 )
    Buffer[--v7] = 0;
  if ( v7 != 36 )
    return 0;
  sub_401530(Buffer, 36LL);
  v6 = sub_4015B3();
  if ( (unsigned int)sub_4015C0(Buffer, v6, 36LL) )
    puts("Correct!");
  return 0;
}
}
```
Doạn mã trong hàm main khá rõ ràng. Đầu tiên, `fgets` đọc chuỗi đầu vào từ chương trình với tối đa 99 kí tự tính cả ký tự `\n`

`v7` sẽ chứa chuỗi được nhập vào và nếu có kí tự newline `\n` thì xóa nó. Tiếp theo sẽ kiểm tra xem v7 có độ dài chính xác bằng 36 hay không nếu không bằng sẽ thoát chương trình

tiếp theo là hàm `sub_401530` ở hàm này mình thấy 1 đoạn mã c có vẻ là đang thực hiện 1 phép xor, nếu i lẻ thì xor với `0x16` và i chẵn thì xor với `0xC `. đây có thể là logic để giải mã bài việc cần tìm là tìm chuỗi bị mã hóa. 
```
__int64 __fastcall sub_401530(__int64 a1, signed int a2)
{
  __int64 result; // rax
  signed int i; // [rsp+Ch] [rbp-4h]

  for ( i = 0; ; ++i )
  {
    result = (unsigned int)i;
    if ( i >= a2 )
      break;
    if ( i % 2 == 1 )
      *(_BYTE *)(i + a1) ^= 0x16u;
    else
      *(_BYTE *)(i + a1) ^= 0xCu;
  }
  return result;
}
```

ở đây `v6 = sub_4015B3` v6 là giá trị trả về từ hàm sub.. và ở dòng dưới thấy `v6` được truyền làm tham số thứ 2 cho hàm `sub4015C0` nên có thể v6 đang chứa key mã hóa từ hàm sub() nó đang gọi . mình kiếm tra và thấy
```
.rdata:0000000000404020 unk_404020      db  49h ; I             ; DATA XREF: sub_4015B3+4↑o
.rdata:0000000000404021                 db  5Eh ; ^
.rdata:0000000000404022                 db  4Fh ; O
.rdata:0000000000404023                 db  42h ; B
.rdata:0000000000404024                 db  4Ah ; J
.rdata:0000000000404025                 db  6Dh ; m
.rdata:0000000000404026                 db  4Eh ; N
.rdata:0000000000404027                 db  77h ; w
.rdata:0000000000404028                 db  65h ; e
.rdata:0000000000404029                 db  78h ; x
.rdata:000000000040402A                 db  6Dh ; m
.rdata:000000000040402B                 db  6Fh ; o
.rdata:000000000040402C                 db  7Dh ; }
.rdata:000000000040402D                 db  63h ; c
.rdata:000000000040402E                 db  6Dh ; m
.rdata:000000000040402F                 db  72h ; r
.rdata:0000000000404030                 db  63h ; c
.rdata:0000000000404031                 db  78h ; x
.rdata:0000000000404032                 db  6Bh ; k
.rdata:0000000000404033                 db  7Fh ; 
.rdata:0000000000404034                 db  6Dh ; m
.rdata:0000000000404035                 db  78h ; x
.rdata:0000000000404036                 db  7Ah ; z
.rdata:0000000000404037                 db  7Fh ; 
.rdata:0000000000404038                 db  62h ; b
.rdata:0000000000404039                 db  79h ; y
.rdata:000000000040403A                 db  6Fh ; o
.rdata:000000000040403B                 db  7Eh ; ~
.rdata:000000000040403C                 db  65h ; e
.rdata:000000000040403D                 db  4Eh ; N
.rdata:000000000040403E                 db  43h ; C
.rdata:000000000040403F                 db  44h ; D
.rdata:0000000000404040                 db  4Ch ; L
.rdata:0000000000404041                 db  56h ; V
.rdata:0000000000404042                 db  4Ch ; L
.rdata:0000000000404043                 db  6Bh ; k
```

dòng cuối cùng Nếu hàm `sub...` có chức năng so sánh 36 ký tự trong chuỗi key v6 với xem có giống nhau hay không  

Mình sẽ viết script dựa trên logic xor và chuỗi mã hóa

```python
def Swap_Byte():
    with open("XorCoBan123.java", "rb") as f:
        enc = f.read()

    n = len(encrypt)
    data = bytearray(n)

    for i in range(0, n , 2):
        first = encrypt[i]
        second = encryp[i + 1]
        data[i] = second
        data[i + 1] = first

    with open("justXor", "wb") as f:
        f.write(data)


def Xor_Hex(data):
    n = len(data)
    result = bytearray(n)
    for i in range(n):
        if (i % 2 == 1):
            result[i] = data[i] ^ 0x16
        else:
            result[i] = data[i] ^ 0xC
    return result

encrypt = bytes.fromhex("49 5E 4F 42 4A 6D 4E 77 65 78 6D 6F 7D 63 6D 72 63 78 6B 7F 6D 78 7A 7F 62 79 6F 7E 65 4E 43 44 4C 56 4C 6B 00 00")
flag = xor(encrypt)
print(flag)
```

```
Wellcome to EHCTF 2025
EHCTF{BainayquadongianvinochiXOR@@@}
Correct!
```
