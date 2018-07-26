---
layout: post
disqus: true
cover: 'assets/images/sctf2018/sctf2018.png'
navigation: True
title: '[Samsung CTF 2018 Quals] - BankRobber'
tags: ctfs sctf2018
subclass: 'post tag-ctfs'
logo: 'assets/images/smlee.png'
author: smlee
categories: smlee
---

<img src="/assets/images/sctf2018/bankrobber/1.png" width="100%"/>

스마트 컨트랙트관련 문제인데 처음 접해봐서 좀 헤맸는데 풀고나니 엄청 쉬운 문제였다.  
문제 자체는 **solidity**에서 일어날 수 있는 몇 가지 issue에 관해서 시큐어 코딩을하면 된다.  
처음에는 **solidity**에서 일어났던 보안 issue 들을 찾고 패치하는 식으로 진행하였는데,  
hitcon 2018에서 취약점 점검 도구인 [MyThril](https://github.com/ConsenSys/mythril)를 공개하여 이를 사용하여 진행하였다.  

사용법은 다음과 같다.  

```
$ docker pull mythril/myth
```

```
$ sudo docker run -v SCTFBank.sol:/SCTFBank.sol mythril/myth -x /SCTFBank.sol
```

실행하면 다음과 같이 reporting을 해준다.  
<img src="/assets/images/sctf2018/bankrobber/2.png" width="100%"/>

issue를 모두 패치 한 후 서버에 전달하면 flag를 획득할 수 있다.  

## Solve code:

```python
#!/usr/bin/env python
from pwn import *
import json

addr = "bankrobber.eatpwnnosleep.com"
port = 4567
s = remote(addr, port)

def auth():
    s.recvuntil("API key required : ")
    s.sendline("349b7ec9c6b3caa710b03589aede7a9bcf2c1466307e7f6a3ce3ef1b8c30aa0e")
    s.recv(4096)

def solver():
    f = open("SCTFBank.sol", "r")
    s.send(f.read())
    f.close()

auth()
solver()

s.interactive()
s.close()
```

## SCTFBank.sol

```javascript
pragma solidity ^0.4.18;

contract SCTFBank{
    event LogBalance(address addr, uint256 value);
    mapping (address => uint256) private balance;
    mapping (address => bool) private claimedBonus;
    uint256 private donation_deposit;
    address private owner;

    constructor() public{
        owner = msg.sender;
    }
    
    function showBalance(address addr) public {
        emit LogBalance(addr, balance[addr]);
    }

    function withdraw(uint256 value) public{
        require(balance[msg.sender] >= value);
        balance[msg.sender] -= value;
        msg.sender.transfer(value);

    }
    
    function transfer(address to, uint256 value) public {
        require(balance[msg.sender] >= value && balance[to]+value >= balance[to]);
        balance[msg.sender] -= value;
        balance[to]+=value;
    }

    function multiTransfer(address[] to_list, uint256 value) public {
	uint256 tmp = value*to_list.length;
	require(tmp / value == to_list.length);
        require(balance[msg.sender] >= (value*to_list.length));
        balance[msg.sender] -= (value*to_list.length);
        for(uint i=0; i < to_list.length; i++){
            require(balance[to_list[i]]+value >= balance[to_list[i]]);
            balance[to_list[i]] += value;
        }
    }
    
    function donate(uint256 value) public {
        require(balance[msg.sender] >= value);
        balance[msg.sender] -= value;
        require(donation_deposit+value >= donation_deposit);
        donation_deposit += value;

    }

    function deliver(address to) public {
    require(!claimedBonus[to]);
        require(msg.sender == owner);
        claimedBonus[to] = true;
        to.transfer(donation_deposit);
        donation_deposit = 0;
    }
    
    function () payable public {
        require(balance[msg.sender]+msg.value >= balance[msg.sender]);
        balance[msg.sender]+=msg.value;
    }
}
//END

```

