# bkp-cutie-keygen

Very cutie.

The final checker code skeleton:
```C++
char __thiscall chk_sub_401D50(_DWORD *this, qstr *a2)
{
  _DWORD *v2; // ebx@1
  int v3; // ecx@2
  _DWORD *v4; // eax@2
  __int64 *v5; // edi@3
  __int64 *v6; // eax@5
  char v7; // bl@6
  int v9; // [esp-8h] [ebp-12Ch]@2
  __int64 *v10; // [esp-4h] [ebp-128h]@2
  __int64 v11[16]; // [esp+14h] [ebp-110h]@2
  char v12; // [esp+94h] [ebp-90h]@5
  int v13; // [esp+120h] [ebp-4h]@1
  void *retaddr; // [esp+124h] [ebp+0h]@2

  v2 = this;
  v13 = 0;
  if ( a2->len != 16 )
    goto LABEL_11;
  v10 = (__int64 *)this;
  QString::QString((QString *)&v10, (const struct QString *)&a2);
  v10 = (__int64 *)sub_401EA0(v2, (char)v10);
  QString::operator=(&a2);
  v9 = v3;
  QString::QString((QString *)&v9, (const struct QString *)&retaddr);
  qmemcpy(v11, giant_bitop_sub_402660(v2, (char)v10), sizeof(v11));
  v4 = operator new(0x80u);
  v5 = (__int64 *)(v4 ? sub_401BB0(v4) : 0);
  v10 = (__int64 *)v2[2];
  v6 = batchmul_sub_401A30((__int64 *)&v12, v11, v10);
  qmemcpy(v5, v6, 0x80u);
  qmemcpy(v11, v6, sizeof(v11));
  v10 = (__int64 *)v2[3];
  if ( sub_401C50((_DWORD *)v11, (int)v10) )
LABEL_11:
    v7 = 0;
  else
    v7 = 1;
  v13 = -1;
  QString::~QString((QString *)&a2);
  return v7;
}
```

Actually only two function is critical: `402660` and `401A30`. All other functions are just routine.

The latter function is easier. With IDA it is not very hard to see that the function is a matrix operation (although it is 64 bit)

The former is the critical part. The function is very hard.

In IDA decompiled code, one of the loop reads:
```
  do
  {
    V1 = V2 + (__PAIR__(V3, V4) >> 8);
    V5 = V6 >> 29;
    V3 = const3_ ^ ((__PAIR__(V6, V2) + __PAIR__((V4 << 24) | (V3 >> 8), (unsigned int)(__PAIR__(V3, V4) >> 8))) >> 32);
    V4 = const2 ^ V1;
    initial_0 = V3;
    pin = V3;
    V6 = V3 ^ (__PAIR__(V6, V2) >> 29);
    V7 = V5 | 8 * V2;
    const0_another = const0;
    V2 = const2 ^ V1 ^ V7;
    W1 = __PAIR__(const1_, const0) >> 8;
    W4 = const2 ^ V1;
    pin2 = V6;
    W3 = obferzero ^ (const3_ + __CFADD__(const2, W1) + ((const1_ >> 8) | (const0_another << 24)));
    const0 = i ^ (const2 + W1);
    const1_ = W3;
    v50 = __PAIR__(const3_, const2) >> 29;
    const2 = const0 ^ ((const3_ >> 29) | 8 * const2);
    const3_ = W3 ^ v50;
    ii = i++;
    obferzero = (__PAIR__(obferzero, ii) + 1) >> 32;
  }
  while ( !obferzero && ii + 1 < 0x20 );
```

A pile of unreadable shit, even with some mark of variables, it does not make sense.

How comes the shit code be compiled from?

If you take a look at the assembly code of the loop, you may have some inspirations:

```asm
loc_4029C0:
xor     eax, eax
mov     ecx, edx
shrd    edx, ebp, 8
shl     ecx, 18h
shr     ebp, 8
or      edx, eax
or      ebp, ecx
add     edx, ebx
mov     ecx, esi
adc     ebp, esi
shr     ecx, 1Dh
xor     ebp, [esp+144h+const3_]
xor     edx, edi
shld    esi, ebx, 3
mov     [esp+144h+initial_0], ebp
or      esi, eax
mov     [esp+144h+pin], ebp
xor     esi, ebp
shl     ebx, 3
mov     ebp, [esp+144h+const1_]
or      ebx, ecx
mov     ecx, [esp+144h+const0]
xor     ebx, edx
shrd    [esp+144h+const0], ebp, 8
or      eax, [esp+144h+const0]
shl     ecx, 18h
shr     ebp, 8
or      ecx, ebp
mov     [esp+144h+W4], edx
mov     ebp, [esp+144h+const3_]
add     eax, edi
mov     [esp+144h+pin2], esi
adc     ecx, ebp
xor     eax, dword ptr [esp+144h+i]
xor     ecx, [esp+144h+obferzero]
mov     [esp+144h+const0], eax
xor     eax, eax
mov     [esp+144h+const1_], ecx
mov     ecx, ebp
shld    ebp, edi, 3
shr     ecx, 1Dh
or      eax, ebp
shl     edi, 3
xor     eax, [esp+144h+const1_]
or      edi, ecx
xor     edi, [esp+144h+const0]
mov     ebp, [esp+144h+initial_0]
mov     [esp+144h+const3_], eax
mov     eax, dword ptr [esp+144h+i]
add     eax, 1
mov     dword ptr [esp+144h+i], eax
adc     [esp+144h+obferzero], 0
jnz     short loc_402A6F
```

The assembly code is a huge block, and it is cleaner, with limited instruction set.

Actually when you decompile them by hand (when you decide, you can.), the code is more readable:
```
v1=ebp:edx(0:5)
v2=esi:ebx(4:2)
v3=const1:const0
v4=const3:const2(edi)
v5=zero:i

long long v1,v2,v3,v4,v5;

for(v5=0;v5<0x20;v5++)
{
    v1 ror 8;
    v1+=v2;
    v1^=v4;
    v2 rol 3;
    v2^=v1;
    v3 ror 8;
    v3+=v4;
    v3^=v5;
    v4 rol 3;
    v4^=v3;    
}
```

By reordering the assembly code (compiler optimize by reordering assembly lines in order to make better use of parallelity inside CPU), we can recover that the operand being played with is actually 64-bit integer, and they are operated by 32-bit code!

`long long` along with compiler optimization generates unreadable code!

Knowing that, the solving algorithm is easy.