---
layout: post
disqus: true
cover: 'assets/images/sctf2018/sctf2018.png'
navigation: True
title: '[Samsung CTF 2018 Quals] - dingJMax'
tags: ctfs sctf2018
subclass: 'post tag-ctfs'
logo: 'assets/images/smlee.png'
author: smlee
categories: smlee
---


[dingJMax](https://github.com/sm1ee/ctf/blob/master/sctf2018/dingJMax/dingJMax_e524bb0f4410c9be57cf1c387ab79872dcbbf592)
<img src="/assets/images/sctf2018/dingJMax/1.png" width="100%" />

이 문제는 분석을 대충해서 푸는데 꽤 시간이 걸렸다..  

실행시키면 다음과 같이 게임이 실행되는데 입력 마다 flag값이 바뀌고 판정에 의해 점수를 받는다.   
<img src="/assets/images/sctf2018/dingJMax/2.png" width="100%" />

문제에서 제시한 조건을 만족하고 flag를 횓득하려면 ALL Pertect가 나와야 한다. ~~사실상 손으로는 불가 능하다.~~  

바이너리를 보면 Note의 속도나 순서가 고정되어 있고 판정이나 점수가 flag에 직접적인 영향을 주진 않는다.  
<img src="/assets/images/sctf2018/dingJMax/4.png" width="100%" />

그렇다면 입력 값에 의해 flag가 변경되고 Note가 고정이기 때문에 Note의 순서만 정확하게 입력된다면 flag 획득할 수 있다. ~~그런 줄 알았다~~

Note를 parsing 하여 d,f,j,k 값으로 바꿔서 **pwntools**로 입력을 줬지만 역시 flag는 획득하지 못했다.  
바이너리를 다시보니 flag 값을 변경할 때 i 값에 영향을 받고 있었고 i 값이 20배 수 일 때 노트 위치가 이동된다.  
<img src="/assets/images/sctf2018/dingJMax/3.png" width="100%" />

Perfect 판정의 경우 0x60764C 주소를 기준으로 다음과 같이 각각 1byte씩 판정 라인을 두고 있다.
>d : 0x60764C  
>f : 0x60764D  
>j : 0x60764E  
>k : 0x60764F  

만약 j를 입력했다면 0x60764E 주소에 'o' 값이 존재하는지 확인하고 i 값이 20의 배수일 때 Perfect 판정이 된다.  
<img src="/assets/images/sctf2018/dingJMax/5.png" width="100%" />

결국 꼼수는 없고 DBI나 binary patch 등 여러 방법이 있을 것 같은데, 나 같은 경우 **wgetch** 함수를 hooking하여 해결했다.  

**wgetch** 함수를 후킹한 이유는 다음과 같다.  
- 후킹된 함수에서 input을 control 할 수 있어야 한다.
- 판정라인 이 후 사용되는 함수 hooking 시 이미 늦다.
- 위 조건들을 만족하며 가장 간단하게 hooking 할 수 있다.

## Solve code:

```c
#define _GNU_SOURCE
#include <ncurses.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <stdio.h>


typedef int (*origin_wgetch)(WINDOW*);

int count = 0;

int wgetch(WINDOW *win){
        char *line = 0x0000000000607648;
        char key[] = {'d','f','j','k'};

        for(int i = 0; i < 4; i++){
                if(line[i] == 'o' && ++count >= 20){
                                count = 0;
                                return key[i];
                }
        }

        origin_wgetch _wgetch = (origin_wgetch)dlsym(RTLD_NEXT, "wgetch");
        return _wgetch(win);
}

```