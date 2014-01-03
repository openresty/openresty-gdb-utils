Name
====

GDB utilities for Nginx, ngx_lua, LuaJIT, and etc.

Status
======

This is still under early development.

Synopsis
========

    # add the path of nginx.py and ngxlua.py modules to the PYTHONPATH env
    (gdb) source luajit21.py
    (gdb) lvmst
    current VM state: C code from intperpreted Lua
    (gdb) lbt
    builtin#166
    builtin#195
    builtin#187
    @/home/agentzh/git/lua-resty-core/lib/resty/core/regex.lua:588
    content_by_lua:10

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

Commands
========

The following gdb commands are supported:

lbt
---
**syntax:** *lbt*

**syntax:** *lbt <L>*

**file** *luajit21.py*

Fetch the current backtrace from the current running Lua thread(when no argument is given) or the Lua thread specified by the lua_State pointer.

The backtrace format is the same as the one used by the [ngx-lj-lua-bt](#ngx-lj-lua-bt) tool.

When analyzing ngx_lua's processes, this tool requires the Python module files `nginx.py` and `ngxlua.py` to obtain the global Lua state. You need to add the path of these `.py` files to the `PYTHONPATH` environment variable before starting `gdb`.

Below is an example:

    (gdb) source luajit21.py
    (gdb) lbt
    builtin#166
    builtin#195
    builtin#187
    @/home/agentzh/git/lua-resty-core/lib/resty/core/regex.lua:588
    content_by_lua:10

You can also explicitly specify the Lua thread state you want to analyze, for instance,

    (gdb) lbt 0x169e0e0

Only LuaJIT 2.1 is supported.

lvmst
-----
**syntax:** *lvmst*

**syntax:** *lvmst <L>*

**file** *luajit21.py*

Prints out the current state of the LuaJIT 2.1 VM.

Below is an example,

    (gdb) source luajit21.py
    (gdb) lvmst
    current VM state: C code from intperpreted Lua

You can also explicitly specify the lua VM state you want to analyze, for instance,

    (gdb) lvmst 0x169e0e0
    current VM state: C code from intperpreted Lua

You can specify any Lua thread's state in the VM you want to analyze.

Prerequisites
=============

You need to enable the debuginfo in your LuaJIT build (and Nginx build if Nginx is involved).

To enable debuginfo in your LuaJIT build, pass the `CCDEBUG=-g` command-line argument to the `make` command, as in

    make CCDEBUG=-g

Also, you are required to use gdb 7.6+ with python support enabled.

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
