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
    * [ltrace](#ltrace)
    * [lir](#lir)
    * [lmainL](#lmainl)
    * [lcurL](#lcurl)
    * [lglobtab](#lglobtab)
    * [ltabgets](#ltabgets)
    * [lpc](#lpc)
    * [lproto](#lproto)
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
**syntax:** *lval tvalue*

**syntax:** *lval gcobj*

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

ltrace
------
**syntax:** *ltrace*

**syntax:** *ltrace traceno*

**file** *luajit21.py*

Dump the contents in a LuaJIT trace object specified by the trace number (starting from 1).

For example,

```text
(gdb) ltrace 658
(GCtrace*)0x40800268
machine code size: 335
machine code start addr: 0x7f2435c85870
machine code end addr: 0x7f2435c859bf
@.../lua/waf-core.lua:1202
```

The starting address and end address of the machine code region in the output can be used to obtain the machine code dump for the trace:

```text
(gdb) disas 0x7f2435c85870, 0x7f2435c859bf
Dump of assembler code from 0x7f2435c85870 to 0x7f2435c859bf:
   0x00007f2435c85870:  mov    DWORD PTR ds:0x40ff1410,0x292
   0x00007f2435c8587b:  cmp    DWORD PTR [rdx-0x8],0x419746c8
   0x00007f2435c85882:  jne    0x7f2435cd0010
   0x00007f2435c85888:  cmp    DWORD PTR [rdx+0x4],0xfffffffb
   0x00007f2435c8588c:  jne    0x7f2435cd0010
   0x00007f2435c85892:  mov    ebp,DWORD PTR [rdx]
   ...
   0x00007f2435c859b4:  mov    r14d,0x40ff1f90
   0x00007f2435c859ba:  jmp    0x7f2444a899fa <lj_vm_exit_interp>
End of assembler dump.
```

When being invoked without any arguments, this command just prints out the total number of traces, for instance,

```text
(gdb) ltrace
Found 253 traces.
```

[Back to TOC](#table-of-contents)

lir
---
**syntax:** *lir traceno*

**file** *luajit21.py*

Dumps out the IR code (with CPU register and snapshot details) for the LuaJIT trace specified by its trace number. The output format is the same as LuaJIT's own `-jdump=+rs` output.

For instance,

```text
(gdb) lir 20
(GCtrace*)0x419ff678
IR count: 16

---- TRACE 20 start 19/? meteor.lua-3.lua:64
---- TRACE 20 IR
0001 rbp      int SLOAD  #13   PI
....              SNAP   #0   [ ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- 0001 ---- ---- 0001 ]
0002 rbx   >  tab SLOAD  #11   T
0003          int FLOAD  0002  tab.asize
0004       >  int ABC    0003  0001
0005 rbx      p32 FLOAD  0002  tab.array
0006          p32 AREF   0005  0001
0007       >  int ALOAD  0006
0008 rsi   >  str SLOAD  #12   T
0009          str TOSTR  0001  INT
0010 rdi      p32 BUFHDR [0x41fe1414]  RESET
0011 rdi      p32 BUFPUT 0010  0008
0012 rdi      p32 BUFPUT 0011  "\,b"
0013 rdi      p32 BUFPUT 0012  0009
0014 rax      str BUFSTR 0013  0010
0015 rbp      int ADD    0001  +1  
....              SNAP   #1   [ ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- 0014 ]
0016       >  int LE     0015  +99 
....              SNAP   #2   [ ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- 0014 0015 ---- ---- 0015 ]
```

[Back to TOC](#table-of-contents)

lmainL
------
**syntax:** *lmainL*

**file** *luajit21.py*

Prints out the `lua_State` pointer value for the main LuaJIT VM state. For example,

```text
(gdb) lmainL
(lua_State*)0x41fe1378
```

[Back to TOC](#table-of-contents)

lcurL
-----
**syntax:** *lcurL*

**file** *luajit21.py*

Prints out the `lua_State` pointer value for current running Lua thread. For example,

```text
(gdb) lcurL
(lua_State*)0x41fe1378
```

[Back to TOC](#table-of-contents)

lglobtab
--------
**syntax:** *lglobtab*

**syntax:** *lglobtab L*

**file** *luajit21.py*

Prints out the global environment table for the specified Lua thread (or the current running Lua thread if the argument is omitted).

For instance,

```text
(gdb) lglobtab
(GCtab*)0x41fe29b0

(gdb) lglobtab (lua_State*)0x41fe1378
(GCtab*)0x41fe29b0
```

[Back to TOC](#table-of-contents)

ltabgets
--------
**syntax:** *ltabgets tab field*

**file** *luajit21.py*

Prints out the value of the specified string field in the Lua table specified by its `TValue` or `GCtab` pointer.

```text
(gdb) ltabgets (GCtab*)0x41fe29b0 dog
Key "dog" not found.

(gdb) ltabgets (GCtab*)0x41fe29b0 assert
(TValue*)0x41fe2a20
        function assert: (GCfunc*)0x41fe3d38

(gdb) ltabgets (TValue*)0x41f1f450 dog
(TValue*)0x41f1f6d8
        number 21.5
```

[Back to TOC](#table-of-contents)

lpc
---
**syntax:** *lpc pc*

**file** *luajit21.py*

Prints out the Lua prototype (`GCproto` object) whose bytecode contains the PC value specified as the `BCIns` pointer value. The Lua source line's location (file name and line number) will also be printed out.

For example,

```text
    (gdb) lpc 0x419eeb4c
    proto: (GCproto*)0x419ee930
    source line: @.../lua/waf-core.lua:1330
    proto first line: 1282
```

[Back to TOC](#table-of-contents)

lproto
------
**syntax:** *lproto file lineno*

**file** *luajit21.py*

Prints out all the Lua prototype objects (in the form of `GCproto` pointer values) filtered by the Lua file name and file line number where the corresponding Lua function is defined.

The file name can be specified as the last part of its path.

Below is an example,

```text
(gdb) lproto regex.lua 273
Found Lua proto (GCproto*)0x41221740 at @.../lua-resty-core/lib/resty/core/regex.lua:273
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
