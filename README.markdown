Name
====

GDB utilities for Nginx, ngx_lua, LuaJIT, and etc.

Status
======

This is still under early development.

Synopsis
========

    (gdb) source ngx-lua.gdb
    (gdb) source luajit20.gdb
    (gdb) lreg L &ngx_http_lua_ctx_tables_key
    <tab: 0x412a68c8>
    (gdb) ltab 0x412a68c8
    tab(4097, 0): {[1]=<tab: 0x4095fc78>, [2]=<tab: 0x4095fc80>, [3]=<tab: 0x4095fc88>,
     [4]=<tab: 0x4095fc90>, [5]=<tab: 0x4095fc98>, [6]=<tab: 0x4095fca0>,
     [7]=<tab: 0x4095fca8>, [8]=<tab: 0x4095fcb0>, [9]=<tab: 0x4095fcb8>,
     [10]=<tab: 0x4095fcc0>, [11]=<tab: 0x4095fcc8>, [12]=<tab: 0x4095fcd0>,
     [13]=<tab: 0x4095fcd8>, [14]=<tab: 0x4095fce0>, [15]=<tab: 0x4095fce8>,
     [16]=<tab: 0x4095fcf0>, [17]=<tab: 0x4095fcf8>, [18]=<tab: 0x4095fd00>,
     ...

Authors
=======

* Yichun Zhang (agentzh) <agentzh@gmail.com>, CloudFlare Inc.

Copyright and License
=====================

This module is licensed under the BSD license.

Copyright (C) 2013, by Yichun "agentzh" Zhang (章亦春) <agentzh@gmail.com>, CloudFlare Inc.

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

See Also
========

* [Nginx Systemtap Toolkit](https://github.com/agentzh/nginx-systemtap-toolkit)
