---
layout: post
disqus: true
cover: 'assets/images/sctf2018/sctf2018.png'
navigation: True
title: '[Samsung CTF 2018 Quals] - HideInSSL'
tags: ctfs sctf2018
subclass: 'post tag-ctfs'
logo: 'assets/images/smlee.png'
author: smlee
categories: smlee
---




[sslpacket.pcap](https://github.com/sm1ee/ctf/blob/master/sctf2018/HideInSSL/sslpacket.pcap)  //After "Export Specified Packets"
<img src="/assets/images/sctf2018/hideinssl/1.png" width="100%" />

패킷을 분석해보면 아래와 같이 192.168.0.107, 192.168.0.128의 SSL handshake가 제대로 이루어지지 않으며 계속 동일한 패턴의 request, response가 이루어진다.  
<img src="/assets/images/sctf2018/hideinssl/2.png" width="100%" />

SSL handshake가 이루어지지 않았기 때문에 reponse의 내용이 그대로 보이며 client hello requset의 부분을 보면 jpg 매직넘버인 JFIF 값과 다음 패킷에서 데이터 조각을 볼 수 있다.
<img src="/assets/images/sctf2018/hideinssl/3.png" width="100%" />

Client hello request 패킷을 보다 해당 부분의 패킷이 jpg의 데이터 조각인 것을 알 수 있는데 jpg의 매직넘버의 시작은 ff d8로 시작하기 때문에 앞의 4byte를 제외하고 TCP payload에서 볼 때 0x13 ~ 0x2b의 범위가 순수하게 전달하고 하는 payload인 것을 알 수 있다.
<img src="/assets/images/sctf2018/hideinssl/4.png" width="100%" />

Response 부분을 보면 0 또는 1의 응답을 주는 것을 알 수 있는데 0일 때 완전히 동일한 payload를 전송하는 것으로 봐서 정상적인 수신 여부를 sender에게 알려주는 것으로 보인다.
<img src="/assets/images/sctf2018/hideinssl/5.png" width="100%" />

jpg의 끝인 ff d9 payload를 가지는 패킷의 다음 요청에는 Client Hello, Continuation Data를 전송하며 그 후에는 FIN, ACK의 응답이 온다. 이로써 TCP 3way – handshake이후 FIN, ACK까지의 패킷의 payload를 합치면 jpg file 구조가 완성된다.
<img src="/assets/images/sctf2018/hideinssl/6.png" width="100%" />

Client Hello, Continuation Data 패킷의 개수를 보면 총 24개인데 2개의 패킷(247, 250 length)을 보면 흐름 상 끝 맺는 패킷이 아님을 알 수 있다.  
그래서 총 22개의 jpg를 가지고 있다고 보면 된다.
<img src="/assets/images/sctf2018/hideinssl/7.png" width="100%" />

이제 parsing하여 22개의 jpg로 만들기만 하면 된다.  
ip header를 parsing하면 되지만 Export Specified Packets로 두 ip의 패킷으로만 구성된 pcap을 가지고 parsing을 진행하였다.
<img src="/assets/images/sctf2018/hideinssl/8.png" width="100%" />


# Solve code

```python
#!/usr/bin/env python
from pwn import *
from scapy.all import *

def requset(_packet):
    return _packet[TCP].payload.getlayer(Raw).load[0x13:0x2B]

def response(_packet):
    return int(_packet[TCP].payload.getlayer(Raw).load[0]);

jpg_gadget = ""
packets = rdpcap('./sslpacket.pcap') 

log.info("Start")
for i, packet in enumerate(packets):
    packet_len = len(packet)

    if packet_len == 74 and packet[TCP].flags == 0x02:
        f = open("flag_%s.jpg" % i, "wb")
    elif packet_len >= 246 and packet_len <= 250:
        jpg_gadget = requset(packet)
    elif packet_len == 67:
        if response(packet) == True:
            f.write(jpg_gadget)
    elif packet_len == 270:
        log.info("Wrote it in file.")
        EOF = True
        f.close()
log.info("Done !")
f.close()
```