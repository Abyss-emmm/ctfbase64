# ctfbase64
1.实现base64的编码与解码，可指定自定义的编码表，通过指定参数`table`。

2.可以根据已知明文与密文生成编码表，不确定的位置由`ctfbase64.NONE_CHAR`暂存，默认为`*`

3.实现base64隐写的读取，b64_decode调用时传入指定参数`pad_list`(PS:列表类型)，会将隐写的二进制数据返回，是01的字符序列。

## 使用自定义编码表
比如url传输时+/有特殊含义，更换为-_。
```python
    from ctfbase64 import b64_decode
    table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    data = '\xf3\xef\x7f'
    print(b64_encode(data))
    print(b64_encode(data,table=table))
```
输出结果
```
8+9/
8-9_
```

## 根据已知明文与编码值生成相应编码表
以一道题为例，已知：

明文："ashlkj!@sj1223%^&*Sd4564sd879s5d12f231a46qwjkd12J;DJjl;LjL;KJ8729128713"

编码后："pTjMwJ9WiQHfvC+eFCFKTBpWQtmgjopgqtmPjfKfjSmdFLpeFf/Aj2ud3tN7u2+enC9+nLN8kgdWo29ZnCrOFCDdFCrOFoF="

求："uLdAuO8duojAFLEKjIgdpfGeZoELjJp9kSieuIsAjJ/LpSXDuCGduouz"

需要分步解决,后续代码用到的模块
```python
from ctfbase64 import b64_encode,b64_decode,get_encode_form
import ctfbase64
import re
from binascii import a2b_hex
```
### 1 生成部分编码表
```python
    en_str = "pTjMwJ9WiQHfvC+eFCFKTBpWQtmgjopgqtmPjfKfjSmdFLpeFf/Aj2ud3tN7u2+enC9+nLN8kgdWo29ZnCrOFCDdFCrOFoF="
    de_str = "ashlkj!@sj1223%^&*Sd4564sd879s5d12f231a46qwjkd12J;DJjl;LjL;KJ8729128713"
    en_form = get_encode_form(en_str,de_str)
    print(en_form.to_table_string())
```
获得部分编码表
```
*H*2+/J*i**ZFjk*m*noQ*STpuvwq3**rABCDKL*MNW789***defg*tOP*******
```

### 2 尝试解码
调用b64_decode如果解码成功则直接返回解码的结果（bytes类型），如果未全部解码成功，则分组输出，并输出每一组缺少的字符。
```python
    flag = "uLdAuO8duojAFLEKjIgdpfGeZoELjJp9kSieuIsAjJ/LpSXDuCGduouz"
    print(b64_decode(flag,table=en_form.to_table_string()))
```
输出结果
```
uLdA:b'fla'
uO8d:b'g{1'
uojA:b'e3a'
FLEK:Can't find key E
jIgd:Can't find key I
pfGe:Can't find key G
ZoEL:Can't find key E
jJp9:b'4f-'
kSie:b'9b2'
uIsA:Can't find key I,s
jJ/L:b'4af'
pSXD:Can't find key X
uCGd:Can't find key G
uouz:Can't find key z
```

### 3 根据flag的形式确定未知key可能在编码表的位置
最后一组`uouz`解码最后一个值应该为`}`,确定z唯一位置为61,en_form.keys()是输出已知字符的的索引（位置），因此需要遍历未知的位置进行尝试。
```python
def get_some_key_z(enstr,en_form):
    table = en_form.to_table_string()
    used_keys = en_form.keys()
    for i in range(0,64):
        if i in used_keys:
            continue
        table_list = list(table)
        table_list[i] = 'z'
        decode_test = b64_decode(enstr,table="".join(table_list))
        if re.search(r'}$',decode_test):
            print("z={},decode:{}".format(i,decode_test))
get_some_key_z("uouz",en_form) # z = 61
```
其他中间的，只能判断flag字符包含`[A-Za-z0-9-]`
```python
def get_one_some_key(enstr,unknown_char,en_form):
    table = en_form.to_table_string()
    used_keys = en_form.keys()
    for i in range(0,64):
        if i in used_keys:
            continue
        table_list = list(table)
        table_list[i] = unknown_char
        decode_test = b64_decode(enstr,table="".join(table_list))
        if re.search(r'[A-Za-z0-9-]{3}',decode_test.decode('ascii','ignore')):
            print("{}={},decode:{}".format(unknown_char,i,decode_test))
get_one_some_key("FLEK","E",en_form) # E = {9,17,21,53,57,61}
get_one_some_key("jIgd","I",en_form) # I  = 2
get_one_some_key("pfGe","G",en_form) # G = {0,9,17,21}
get_one_some_key("ZoEL","E",en_form) # E = {9,17,21}
get_one_some_key("pSXD","X",en_form) # X = {9,17,21,53,57,61}
get_one_some_key("uCGd","G",en_form) # G = {0,9,17,21}
```
剩下的I，s的，由于I确定为2，因此相当于仅s未知
```python
en_form.add(2,'I')                       #ensure I =2  
get_one_some_key("uIsA","s",en_form)      # s = 53
```
闲的无聊写了个遍历两个字符的
```python
def get_two_some_key(enstr,unknown_char,en_form):
    table = en_form.to_table_string()
    used_keys = en_form.keys()
    for i in range(0,64):
        if i in used_keys:
            continue
        table_list = list(table)
        table_list[i] = unknown_char[0]
        for j in range(0,64):
            if j in used_keys or i == j:
                continue
            table_list_2 = table_list.copy()
            table_list_2[j] = unknown_char[1]
            decode_test = b64_decode(enstr,table="".join(table_list_2))
            if re.search(r'[A-Za-z0-9-]{3}',decode_test.decode('ascii','ignore')):
                print("{}={},{}={},decode:{}".format(unknown_char[0],i,unknown_char[1],j,decode_test))
get_two_some_key("uIsA",['I','s'],en_form)
```
输出结果
```
I=2,s=53,decode:b'd-a'
I=7,s=9,decode:b'dra'
I=7,s=17,decode:b'dta'
I=7,s=21,decode:b'dua'
I=21,s=9,decode:b'eRa'
I=21,s=17,decode:b'eTa'
I=39,s=9,decode:b'fra'
I=39,s=17,decode:b'fta'
I=39,s=21,decode:b'fua'
I=53,s=9,decode:b'gRa'
I=53,s=17,decode:b'gTa'
I=53,s=21,decode:b'gUa'
```
最后确定的字符位置再次排除，`E`和`G`求交集，确定的直接通过en_form.add添加，使用如下代码输出所有可能的flag
```python
    en_form.add(61,'z')
    en_form.add(2,'I')
    en_form.add(53,'s')
    E_list = [9,17,21]
    G_list = [0,9,17,21]
    X_list = [9,17,21,57]
    for E in E_list:
        for G in G_list:
            if G == E:
                continue
            for X in X_list:
                if X==G or X==E:
                    continue
                tmp_encode = ctfbase64.EncodeForm()
                tmp_encode.init(en_form.to_table_string())
                tmp_encode.add(E,'E')
                tmp_encode.add(G,'G')
                tmp_encode.add(X,'X')
                decode_test = b64_decode(flag,table = tmp_encode.to_table_string())
                print("{}".format(decode_test))
```
获得可能的flag值
```
b'flag{1e3a2be4-1c02-2f4f-9b2d-a4afaddf01e6}'
b'flag{1e3a2be4-1c02-2f4f-9b2d-a4afaedf01e6}'
b'flag{1e3a2be4-1c02-2f4f-9b2d-a4afandf01e6}'
b'flag{1e3a2be4-1c4r-2f4f-9b2d-a4afaedf4qe6}'
b'flag{1e3a2be4-1c4r-2f4f-9b2d-a4afandf4qe6}'
b'flag{1e3a2be4-1c5r-2f4f-9b2d-a4afaddf5qe6}'
b'flag{1e3a2be4-1c5r-2f4f-9b2d-a4afandf5qe6}'
b'flag{1e3a2de4-1c02-4f4f-9b2d-a4afabdf01e6}'
b'flag{1e3a2de4-1c02-4f4f-9b2d-a4afaedf01e6}'
b'flag{1e3a2de4-1c02-4f4f-9b2d-a4afandf01e6}'
b'flag{1e3a2de4-1c2r-4f4f-9b2d-a4afaedf2qe6}'
b'flag{1e3a2de4-1c2r-4f4f-9b2d-a4afandf2qe6}'
b'flag{1e3a2de4-1c5r-4f4f-9b2d-a4afabdf5qe6}'
b'flag{1e3a2de4-1c5r-4f4f-9b2d-a4afandf5qe6}'
b'flag{1e3a2ee4-1c02-5f4f-9b2d-a4afabdf01e6}'
b'flag{1e3a2ee4-1c02-5f4f-9b2d-a4afaddf01e6}'
b'flag{1e3a2ee4-1c02-5f4f-9b2d-a4afandf01e6}'
b'flag{1e3a2ee4-1c2r-5f4f-9b2d-a4afaddf2qe6}'
b'flag{1e3a2ee4-1c2r-5f4f-9b2d-a4afandf2qe6}'
b'flag{1e3a2ee4-1c4r-5f4f-9b2d-a4afabdf4qe6}'
b'flag{1e3a2ee4-1c4r-5f4f-9b2d-a4afandf4qe6}'
```

## base64隐写读取
调用b64_decode可传入一个列表给`pad_list`形参，用于记录隐藏的二进制字符，最后再自行拼接输出
```python
    encode_strings=[
        "I2luY2x1ZGU8c3RkaW8uaD5=",
        "I2luY2x1ZGUgPHN0ZGxpYi5oPi==",
        "bWFpbigpe2ludCBpLG5bXT17KCgoMSA8PDEpPDwoMTw8MSk8PCgxPDx=",
        "ICAgICAgIDEpPDwoMTw8KDE+PjEpKSkrKCgxPDwxKTw8KDE8PDEpKSksICgoKDE=",
        "ICAgICAgIDw8MSk8PCgxPDwxKTw8KDE8PDEpPDwoMTw8MSkpLSgoMTw8MSk8PCi=",
        "ICAgIAkxPDwxKTw8KDE8PDEpKSsoKDE8PDEpPDwoMTw8KDE+PjEpKSkrKDE8PCgxPj4xKSkpLA==",
        "ICAgICAgICgoKDE8PDEpPDwoMTw8MSk8PCgxPDwxKTw8KDE8PDEpKS0oKDEgPDwxKW==",
        "ICAgICAgIDw8KDE8PDEpIDw8KDE8PCgxPj4xKSkpLSgoMTw8MSk8PCgxPDwoMT4+MSkpKSkgLB==",
        "ICAgICAgICgoKDE8PDEpPDwoMTw8MSk8PCgxPDwxKTw8KCAxPDwxKSktKCgxIDw8MSk8PG==",
        "ICAgICAgICAoMTw8MSk8PCgxIDw8KDE+PjEpKSktKCgxPDwxKTw8KDE8PCgxPj4xKSkpKSAgLN==",
        "ICAgICAgICAoKCgxPDwxKTw8KDE8PDEpPDwoMTw8MSk8PCgxPDwxKSktKCgxPDwxKSA8PC==",
        "ICAgICAgICAoMTw8MSk8PCgxPDwoMT4+MSkpKS0oMTw8KDE+PjEpKSksKCgoMTw8MSk8PA==",
        "ICAgICAgICAoMTw8MSk8PCgxPDwxKSkrKCgxPDwxKTw8KDE8PDEpPDwoMTw8KDE+PjEpKSkgLW==",
        "ICAgICAgICAoKDE8PDEpPDwoMTw8KDE+PjEpKSkpLCgoMTw8MSk8PCgxPDwxKTw8KDE8PDEpKR==",
        "ICAgICAgICwoKCgxPDwxKTw8KDE8PDEpPDwoMTw8MSk8PCgxPDwxKSktKCgxPDwxKTw8KDE8PDEpKS==",
        "ICAgICAgIC0oMTw8KDE+PjEpKSksKCgoMTw8MSk8PCgxPDwxKTw8KDE8PDEpPDwoMTw8MSkpLSgoMQ==",
        "ICAgICAgIDw8MSk8PCgxPDwxKTw8KDE8PCgxPj4xKSkpLSgxPDwoMT4+MSkpKSwgICgoKDE8PDF=",
        "ICAgICAgICk8PCgxPDwxKTw8KDE8PDEpPDwoMTw8MSkpLSgoMTw8MSk8PCAoMQ==",
        "ICAgICAgIDw8MSk8PCgxPDwoMT4+MSkpKSsoMTw8MSkpLCgoKDE8PDEpPDwoMTw8MSAgKd==",
        "ICAgICAgIDw8KDE8PDEpPDwoMTw8MSkpLSgoMTw8MSk8PCgxPDwxKTw8KDE8PCgxPj4xKSkpLV==",
        "ICAgICAgICgoMTw8MSk8PCgxPDwoMT4+MSkpKSksKCgoMTw8MSk8PCgxPDwxKSA8PCgxPDwxKR==",
        "ICAgICAgIDw8KDE8PDEpKS0oKDE8PDEpPDwoMTw8MSk8PCgxPDwxKSkrICgoMR==",
        "ICAgICAgIDw8MSk8PCgxPDwoMT4+MSkpKSksKCgoMTw8MSk8PCgxPDwxKSAgPDwoMZ==",
        "ICAgICAgIDw8MSkpKygxPDwoMT4+MSkpKSwoKCgxPDwxKTw8KDE8PDEpKSAgKygoMZ==",
        "ICAgICAgIDw8MSk8PCAoMTw8KDE+PjEpKSkgKygxPDwgKDE+PjEpKSl9O2Zvcl==",
        "ICAgICAgIChpPSgxPj4xKTtpPCgoKDE8PDEpPDwoMTw8MSkpKygoMSAgPDwxKTw8KM==",
        "ICAgICAgIDE8PCgxPj4xKSkpKygxPDwxKSk7aSsrKSAgIHByaW50ZigiJWMiLG5baV0pO32=",
    ]
    pad_list = []
    for en in encode_strings:
        b64_decode(en,pad_list = pad_list)
    print(pad_list)
    pad = "".join(pad_list)
    pad = int(pad,2)
    print(a2b_hex(hex(pad).replace('0x','')).decode())
```

```
['01', '0010', '01', '00', '10', '0000', '0110', '0001', '0110', '1101', '0010', '0000', '0110', '0001', '0010', '0000', '01', '0000', '1101', '0101', '0001', '0001', '1001', '1001', '0101', '1100', '10']
I am a CTFer
```