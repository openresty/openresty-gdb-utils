Name
====

GDB utilities for Nginx, ngx_lua, LuaJIT, and etc.

Table of Contents
=================

* [Name](#name)
* [Status](#status)
* [Synopsis](#synopsis)
* [Description](#description)
* [Commands](#commands)
    * [lbt](#lbt)
    * [lvmst](#lvmst)
    * [lval](#lval)
* [Prerequisites](#prerequisites)
* [Installation](#installation)
* [Authors](#authors)
* [Copyright and License](#copyright-and-license)
* [See Also](#see-also)

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

    (gdb) lfunc regex.lua 444
    Found function (GCfunc*)0x4025e168 at @/home/agentzh/git/lua-resty-core/lib/resty/core/regex.lua:444

    (gdb) lproto regex.lua 444
    Found proto (GCproto*)0x4025f380 at @/home/agentzh/git/lua-resty-core/lib/resty/core/regex.lua:444

    (gdb) luv (GCfunc*)0x4025e168
    0x4025e168
    Found 23 upvalues.
    upvalue "parse_regex_opts": value=(TValue*)0x4025df60 value_type=func closed=1
    upvalue "type": value=(TValue*)0x4025e1e8 value_type=func closed=1
    upvalue "tostring": value=(TValue*)0x4025e208 value_type=func closed=1
    upvalue "band": value=(TValue*)0x4025dd88 value_type=func closed=1
    upvalue "FLAG_COMPILE_ONCE": value=(TValue*)0x41b8daf8 value_type=number closed=1
    upvalue "regex_cache": value=(TValue*)0x4025df80 value_type=table closed=1
    upvalue "get_string_buf": value=(TValue*)0x4025dfa0 value_type=func closed=1
    upvalue "MAX_ERR_MSG_LEN": value=(TValue*)0x4025dfc0 value_type=number closed=1
    upvalue "C": value=(TValue*)0x41b8da38 value_type=userdata closed=1
    ...

    (gdb) lval (TValue*)0x41b8da38
    udata type: ffi clib
          payload len: 16
          payload ptr: 0x41b81df8
          CLibrary handle: (void*)0x0
          CLibrary cache: (GCtab*)0x41b8d188

    (gdb) lval (TValue*)0x41907840
    type cdata
        cdata object: (GCcdata*)0x41aae7f0
        cdata value pointer: (void*)0x41aae7f8
        ctype object: (CType*)0x40268e70
        ctype size: 1 byte(s)
        ctype type: func
        ctype element name: ngx_http_lua_ffi_destroy_regex

Description
===========

This toolkit provides various gdb extension commands for analyzing core dump files for nginx and/or luajit.

[Back to TOC](#table-of-contents)

Commands
========

The following gdb commands are supported:

[Back to TOC](#table-of-contents)

lbt
---
**syntax:** *lbt [L]*

**syntax:** *lbt full [L]*

**file** *luajit21.py*

Fetch the current backtrace from the current running Lua thread (when no `L` argument is given) or the Lua thread specified by the `lua_State` pointer.

The backtrace format is the same as the one used by the [lj-lua-bt](https://github.com/agentzh/stapxx#lj-lua-bt) tool.

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

The `lbt full` command works like `bt full`, which dumps out the names and values of all the local variables (including function parameters) in every Lua function frame. For example,

```text
(gdb) lbt full
C:ngx_http_lua_socket_tcp_receive
@/home/agentzh/git/lua-resty-mysql/lib/resty/mysql.lua:191
    local "self":
        table (0x40f181a8)
    local "sock":
        table (0x40f181b0)
@/home/agentzh/git/lua-resty-mysql/lib/resty/mysql.lua:530
    local "self":
        table (0x40f18148)
    local "opts":
        table (0x40f18150)
    local "sock":
        table (0x40f18158)
    local "max_packet_size":
        int 1048576
    local "ok":
        int 1
    local "err":
        nil
    local "database":
        string: "world" (len 5)
    local "user":
        string: "ngx_test" (len 8)
    local "pool":
        string: "ngx_test:world:127.0.0.1:3306" (len 29)
    local "host":
        string: "127.0.0.1" (len 9)
```

Only LuaJIT 2.1 is supported.

[Back to TOC](#table-of-contents)

lvmst
-----
**syntax:** *lvmst [L]*

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

The following VM states are supported:

* Compiled Lua code (trace #N)
* Interpreted
* C code (from interpreted Lua code)
* Garbage collector (from interpreter)
* Garbage collector (from compiled Lua code)
* Trace exit handler
* Trace recorder
* Optimizer
* Assembler

[Back to TOC](#table-of-contents)

lval
-----
**syntax:** *lval tv*

**file** *luajit21.py*

Prints out the content in a `TValue` or the dereferenced value (like `GCtab` and `GCproto`) from its pointer. By default the argument is assumed to be a `TValue*` pointer value.

Below are some examples:

```text
(gdb) lval (TValue*)0x41f1f450
table (GCtab*)0x41f1f688 (narr=5, nrec=1):
    [1] =
        int 32
    [2] =
        true
    [4] =
        string: "hello" (len 5)
    key:
        string: "dog" (len 3)
    value:
        number 21.5

(gdb) lval (GCtab*)0x41f1f688
table (GCtab*)0x41f1f688 (narr=5, nrec=1):
    [1] =
        int 32
    [2] =
        true
    [4] =
        string: "hello" (len 5)
    key:
        string: "dog" (len 3)
    value:
        number 21.5

(gdb) lval 0x41f1f440
        nil

(gdb) lval 0x41f1f458
        Lua function (GCfunc*)0x4188e018 at @.../regex.lua:418

(gdb) lval 0x41f1f460
        int 1
```

[Back to TOC](#table-of-contents)

Prerequisites
=============

You need to enable the debuginfo in your LuaJIT build (and Nginx build if Nginx is involved).

To enable debuginfo in your LuaJIT build, pass the `CCDEBUG=-g` command-line argument to the `make` command, as in

    make CCDEBUG=-g

Also, you are required to use gdb 7.6+ with python support enabled.

[Back to TOC](#table-of-contents)

Installation
============

See [Prerequisites](#prerequisites) first.

And then

1. check out this project locally.
2. add the following lines to your `~/.gdbinit` (you *must* change the `/path/to` part to the real path):

```gdb
directory /path/to/nginx-gdb-utils

py import sys
py sys.path.append("/path/to/nginx-gdb-utils")

source luajit20.gdb
source ngx-lua.gdb
source luajit21.py
source ngx-raw-req.py
set python print-stack full
```

[Back to TOC](#table-of-contents)

Authors
=======

* Guanlan Dai.

* Yichun Zhang (agentzh) <agentzh@gmail.com>, CloudFlare Inc.

[Back to TOC](#table-of-contents)

Copyright and License
=====================

This module is licensed under the BSD license.

Copyright (C) 2013-2014, by Guanlan Dai.

Copyright (C) 2013-2014, by Yichun "agentzh" Zhang (章亦春) <agentzh@gmail.com>, CloudFlare Inc.

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

[Back to TOC](#table-of-contents)

See Also
========

* [Nginx Systemtap Toolkit](https://github.com/agentzh/nginx-systemtap-toolkit)
* Sample tools in the stap++ project: https://github.com/agentzh/stapxx#samples

[Back to TOC](#table-of-contents)
