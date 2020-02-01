Name
====

openresty-gdb-utils - GDB Utilities for OpenResty (including Nginx, ngx\_lua, LuaJIT, and more)

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
    * [ltracebymcode](#ltracebymcode)
    * [lir](#lir)
    * [lmainL](#lmainl)
    * [lcurL](#lcurl)
    * [lg](#lg)
    * [lglobtab](#lglobtab)
    * [ltabgets](#ltabgets)
    * [lpc](#lpc)
    * [lproto](#lproto)
    * [lfunc](#lfunc)
    * [luv](#luv)
    * [lbc](#lbc)
    * [lgc](#lgc)
    * [lgcstat](#lgcstat)
    * [lgcpath](#lgcpath)
    * [lthreadpc](#lthreadpc)
    * [lb](#lb)
    * [lrb](#lrb)
    * [linfob](#linfob)
    * [ldel](#ldel)
    * [ldumpstack](#ldumpstack)
    * [dump-all-timers](#dump-all-timers)
* [Prerequisites](#prerequisites)
* [Installation](#installation)
* [Authors](#authors)
* [Copyright and License](#copyright-and-license)
* [See Also](#see-also)

Status
======

**IMPORTANT!!! This project is no longer maintained and our focus has been shifted to a much better dynamic tracing platform named [OpenResty XRay](https://openresty.com/en/xray). Existing users of the tools here are recommended to switch too.**

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

This toolkit provides various gdb extension commands for analyzing core dump files for OpenResty (including nginx, luajit, ngx\_lua, and many other components).

Many of the gdb extension tools here have been successfully used to track down many weird bugs in OpenResty and LuaJIT cores just by analyzing core dump files.

[Back to TOC](#table-of-contents)

Commands
========

**IMPORTANT!!! The commands below are no longer maintained and our focus has been
shifted to a much better dynamic tracing platform named
[OpenResty XRay](https://openresty.com/en/xray). Existing users of the tools here are recommended to switch too.**

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
(gdb) set disassembly-flavor intel

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

ltracebymcode
-------------

Searches through all the traces for a trace whose machine code contains the specified address (as the only argument).

```
(gdb) ltracebymcode 0x7f0d083a8955
(GCtrace*)0x41479010 (trace #998)
machine code start addr: 0x7f0d083a8955
machine code end addr: 0x7f0d083a8c81
@/opt/app/lua/ip.lua:180
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

lg
--
**syntax:** *lg*

**syntax:** *lg [L]*

**file** *luajit21.py*

Prints out the `global_State` pointer value from the `lua_State` pointer value specified or from the current main VM state automatically discovered.

Below are some examples:

```text
(gdb) lg
(global_State*)0x41fe13b8

(gdb) lg (lua_State*)0x41fe1378
(global_State*)0x41fe13b8
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
This command works by walking through all the GC objects in the LuaJIT VM.

[Back to TOC](#table-of-contents)

lfunc
-----
**syntax:** *lfunc file lineno*

**file** *luajit21.py*

Similar to the [lproto](#lproto) command, but return all the Lua function objects (in `GCfunc` pointer values) instead of the Lua prototype objects.

Below is an example,

```text
(gdb) lfunc base.lua 137
Found Lua function (GCfunc*)0x41b8efd0 at
@/home/agentzh/git/lua-resty-core/lib/resty/core/base.lua:137
```

[Back to TOC](#table-of-contents)

luv
---
**syntax:** *luv func*

**file** *luajit21.py*

Prints out names and values for all the upvalues associated with the `GCfunc` pointer value specified.

Below are some examples:

```text
(gdb) luv (GCfunc*)0x41b8efd0
Found 3 upvalues.
upvalue "str_buf_size": value=(TValue*)0x41b82258 value_type=number closed=1
upvalue "ffi_new": value=(TValue*)0x41b8cc38 value_type=func closed=1
upvalue "str_buf": value=(TValue*)0x41b8cc80 value_type=cdata closed=1

(gdb) luv (GCfunc*)0x4188de10
Found 4 upvalues.
upvalue "C": value=(TValue*)0x41211128 value_type=userdata closed=1
upvalue "ngx_log": value=(TValue*)0x4188de48 value_type=function closed=1
upvalue "ngx_ERR": value=(TValue*)0x4188de68 value_type=number closed=1
upvalue "ffi_gc": value=(TValue*)0x4188de88 value_type=function closed=1
```

You can get the `GCfunc` pointer value via the [lfunc](#lfunc) command.

[Back to TOC](#table-of-contents)

lbc
---

Dumps the bytecode of the specified bytecode address (PC) range.

The bytecode address (or PC) range can be obtained by using the [lval](#lval) command
upon a `GCproto` object. For example:

```
 lval (GCproto*)0x4030b8f8
    proto definition: @/usr/local/openresty-debug/lualib/resty/lrucache.lua:82
    bytecode range: 0x4030b938 0x4030b960
```

And we feed this range into the `lbc` command to get the full bytecode dump for this
GCproto object:

```
(rr) lbc 0x4030b938 0x4030b960
(GCproto*)0x4030b8f8
-- BEGIN BYTECODE -- lrucache.lua:82
0000    FUNCF    4
0001    TGETS    1   0   0  ; "prev"
0002    TGETS    2   0   1  ; "next"
0003    TSETS    1   2   0  ; "prev"
0004    TSETS    2   1   1  ; "next"
0005    UGET     3   0      ; NULL
0006    TSETS    3   0   0  ; "prev"
0007    UGET     3   0      ; NULL
0008    TSETS    3   0   1  ; "next"
0009    RET0     0   1
-- END BYTECODE -- lrucache.lua:92
```

[Back to TOC](#table-of-contents)

lgc
---
**syntax:** *lgc*

**syntax:** *lgc L*

**file** *luajit21.py*

Prints out the current size of the total memory that is allocated by the LuaJIT GC.

This is very useful for checking if the LuaJIT VM takes up too much memory on the Lua land.

Below is an example:

```text
(gdb) lgc
The current memory size (allocated by GC): 898960 bytes
```

[Back to TOC](#table-of-contents)

lgcstat
-------
**syntax:** *lgcstat*

**file** *luajit21.py*

This command prints out a statistics summary for all the GC objects (both live ones and dead ones that are not yet collected).

The output is very similar to the systemtap tool, [lj-gc-objs](https://github.com/agentzh/stapxx#lj-gc-objs).

Below is an example:

```text
(gdb) lgcstat
15172 str        objects: max=2956, avg = 51, min=18, sum=779126
 987 upval      objects: max=24, avg = 24, min=24, sum=23688
 104 thread     objects: max=1648, avg = 1622, min=528, sum=168784
 431 proto      objects: max=226274, avg = 2234, min=78, sum=963196
 952 func       objects: max=144, avg = 30, min=20, sum=28900
 446 trace      objects: max=23400, avg = 1857, min=160, sum=828604
2965 cdata      objects: max=4112, avg = 17, min=12, sum=51576
18961 tab        objects: max=24608, avg = 207, min=32, sum=3943256
   9 udata      objects: max=176095, avg = 39313, min=32, sum=353822

 sizeof strhash 65536
 sizeof g->tmpbuf 512
 sizeof ctype_state 8664
 sizeof jit_state 53792

total sz 7274672
g->strnum 15172, g->gc.total 7274672
```

[Back to TOC](#table-of-contents)

lgcpath
-------
**syntax:** *lgcpath size [type]*

**file** *luajit21.py*

Finds large live LuaJIT GC objects with the size threshold (in bytes) and a type name ("udata", "str", "tab", "thr", "upval", "func", "tr"). The type name argument is optional. Also prints out the full referencing path from the GC roots to the object being matched.

For example, finds all the live Lua tables whose size has exceeded 100KB:

```
(gdb) lgcpath 100000 tab
path 000:[registry] ->Tab["_LOADED"] ->Tab["ffi"] ->Tab["gc"] ->cfunc ->env ->Tab sz:196640 (GCobj*)0x40784f58 ->END
path 001:[registry] ->Tab[tv=0x4132e470] ->Tab sz:524328 (GCobj*)0x40783108 ->END
```

[Back to TOC](#table-of-contents)

lthreadpc
----------
**syntax:** *lthreadpc <L>*

**file** *luajit21.py*

Prints out the next PC to be executed for a yielded Lua thread.

```
(gdb) lthreadpc (lua_State*)0x4169ece0
next PC: (BCIns*)0x40c5d8f0
proto: (GCproto*)0x40c5d898
BC pos: 5
source line: @/opt/app/dummy/lua/exit.lua:131
proto first line: 127
```

[Back to TOC](#table-of-contents)

lb
--

**syntax:** *lb <spec>*

**file** *luajit21.py*

Sets a breakpoint on interpreted Lua function call entries.

The Lua function is specified by the Lua file name and first line's line number of the Lua function (prototype) definition.

For example,

```
(gdb) lb foo.lua:32
```

defines a breakpoint on the entry point of the Lua function defined on the line 32 of the file `foo.lua`. The line 32 may look like this:

```lua
local function do_something()
```

Below is a complete example:

```
(gdb) lb a.lua:1
Searching Lua function at a.lua:1...
Set break point on (GCfunc*)0x40007e08 at @a.lua:1
Breakpoint 2 at 0x4225e6
Breakpoint 3 at 0x422614
Breakpoint 4 at 0x4225b8

(gdb) c
Entry breakpoint hit at
              function @a.lua:1: (GCfunc*)0x40007d20
source line: @a.lua:7
Taking 2 arguments:
              int 1
              number 2.4

Breakpoint 2, 0x00000000004225e6 in lj_BC_CALL ()
```

You can also set breapoints on every interpreted Lua function call entries by specifying `*`:

```
(gdb) lb *
```

If you want to set breakpoints on Lua function call returns, then you
should use the [lrb](#lrb) gdb command instead.

Existing Lua-land breakpoints can be viewed via the [linfob](#linfob) gdb command.

You can remove the breakpoints via the [ldel](#ldel) gdb command.

Right now, only interpreted Lua function calls run by LuaJIT 2.1 are supported.
But we will add support for JIT-compiled Lua function calls in the near future.

[Back to TOC](#table-of-contents)

lrb
---
**syntax:** *lrb <spec>*

**file** *luajit21.py*

Sets a breakpoint on interpreted Lua function call returns.

The Lua function is specified by the Lua file name and first line's line number of the Lua function (prototype) definition.

For example,

```
(gdb) lb foo.lua:32
```

defines a breakpoint on the entry point of the Lua function defined on the line 32 of the file `foo.lua`. The line 32 may look like this:

```lua
local function do_something()
```

Below is a complete example:

```
(gdb) lrb a.lua:1
Searching Lua function at a.lua:1...
Set breakpoint on RET1 (line @a.lua:3)
Set breakpoint on RET1 (line @a.lua:5)
Set breakpoint on RET0 (line @a.lua:7)
Breakpoint 2 at 0x4228b0
Breakpoint 3 at 0x422938
Breakpoint 4 at 0x422994

(gdb) c
Return breakpoint hit at
              line @a.lua:3 of function a.lua:1
Returning 1 value(s):
              string: "hello" (len 5)

Breakpoint 4, 0x0000000000422994 in lj_BC_RET1 ()

(gdb) c
Return breakpoint hit at
              line @a.lua:5 of function a.lua:1
Returning 1 value(s):
              string: "hiya" (len 4)

Breakpoint 4, 0x0000000000422994 in lj_BC_RET1 ()
```

If the Lua function returns via a tail call, then you should set a breakpoint on
the ultimate Lua function at the end of the tail call chain instead. For instance,

```lua
function foo()
    return true;
end

function bar(a)
    return foo()
end
```

In order to set a breakpoint on Lua function `bar` here, you should set a breakpoint on the `foo` function instead because `bar` is returning by a tailcall to `foo`.

Unlike the [lb](#lb) command, the `*` spec is not supported, that is,
setting breakpoints on all the Lua function returns is not supported (yet).

Existing Lua-land breakpoints can be viewed via the [linfob](#linfob) gdb command.

You can remove the breakpoints via the [ldel](#ldel) gdb command.

[Back to TOC](#table-of-contents)

linfob
------

**syntax:** *linfob*

**file** *luajit21.py*

Lists all the existing Lua-land breakpoints.

Below is an example:

```
(gdb) linfob
Type    Address                 What
entry   (GCfunc*)0x40ef8ed0     ownership.lua:190
entry   (GCfunc*)0x40b523d0     shcache.lua:454
return  (BCIns*)0x40eeb130      ownership.lua:190 in func ownership.lua:238
return  (BCIns*)0x40eeb2d8      ownership.lua:190 in func ownership.lua:307
return  (BCIns*)0x40eeb330      ownership.lua:190 in func ownership.lua:328
trace   -       -
```

[Back to TOC](#table-of-contents)

ldel
----

**syntax:** *ldel*

**syntax:** *ldel <spec>*

**file** *luajit21.py*

Removes one or more Lua-land breakpoints.

When running without any arguments, it removes all the existing Lua-land breakpoints.

Alternatively you scan specify a Lua function position (as in the `lb` and `lrb` commands) to remove the entry and return breakpoints on that Lua function only. For example,

```
(gdb) lb a.lua:1
Searching Lua function at a.lua:1...
Set break point on (GCfunc*)0x40007d40 at @a.lua:1
Breakpoint 2 at 0x4225e6
Breakpoint 3 at 0x422614
Breakpoint 4 at 0x4225b8

(gdb) lrb a.lua:1
Searching Lua function at a.lua:1...
Set breakpoint on RET0 (line @a.lua:2)
Breakpoint 5 at 0x4228b0
Breakpoint 6 at 0x422938
Breakpoint 7 at 0x422994

(gdb) lb a.lua:5
Searching Lua function at a.lua:5...
Set break point on (GCfunc*)0x40007e28 at @a.lua:5

(gdb) ldel a.lua:1
Searching Lua function at a.lua:1...
Remove entry breakpoint on (GCfunc*)0x40007d40 at @a.lua:1
Remove return breakpoint on (GCfunc*)0x40007f2c at @a.lua:1

(gdb) ldel a.lua:5
Searching Lua function at a.lua:5...
Remove entry breakpoint on (GCfunc*)0x40007e28 at @a.lua:5

(gdb) linfob
No Lua breakpoints.
```

[Back to TOC](#table-of-contents)

ldumpstack
----------

**syntax:** *ldumpstack <lua_State &ast;>*

**file** *luajit21.py*

Shows the stack content of the given `lua_State` struct.

```
1 argument expected!
usage: ltb <lua_State *>
(gdb) ldumpstack  0x40086c58
index = 1
		function =init_worker_by_lua:2: (GCfunc*)0x40085c30
index = 2
		string: "a" (len 1)
index = 3
		string: "b" (len 1)
index = 4
		string: "c" (len 1)
```

[Back to TOC](#table-of-contents)

dump-all-timers
---------------

**syntax:** *dump-all-timers*

**file** *ngx-lua.gdb*

Dump all timers from the timer tree inside the NGINX worker.
If the timer was created with `ngx.timer.*` Lua API, also dumps the
function that will be executed by the timer with their arguments.

All timestamps are in milliseconds. The "in" value is calculated as
`now - timer's timestamp`. A zero or negative value means the timer should
be fired.

```
(gdb) dump-all-timers
now is 1501052272091

timer node key=1501052274087, is_lua_timer=1, in 1996 msec
coroutine=0x400869e0. stack contents:
index = 1
		function =init_worker_by_lua:6: (GCfunc*)0x40085a68

timer node key=1501052275086, is_lua_timer=1, in 2995 msec
coroutine=0x40086790. stack contents:
index = 1
		function =init_worker_by_lua:10: (GCfunc*)0x40085f78

timer node key=1501052273091, is_lua_timer=1, in 1000 msec
coroutine=0x40086c58. stack contents:
index = 1
		function =init_worker_by_lua:2: (GCfunc*)0x40085c30
index = 2
		string: "a" (len 1)
index = 3
		string: "b" (len 1)
index = 4
		string: "c" (len 1)
```

[Back to TOC](#table-of-contents)

Prerequisites
=============

You need to enable the debuginfo in your LuaJIT build (and Nginx build if Nginx is involved).

To enable debuginfo in your LuaJIT build, pass the `CCDEBUG=-g` command-line argument to the `make` command, as in

    make CCDEBUG=-g

Also, you are required to use gdb 7.6+ with python 2.7+ support enabled.

[Back to TOC](#table-of-contents)

Installation
============

See [Prerequisites](#prerequisites) first.

And then

1. check out this project locally.
2. add the following lines to your `~/.gdbinit` (you *must* change the `/path/to` part to the real path):

```gdb
directory /path/to/openresty-gdb-utils

py import sys
py sys.path.append("/path/to/openresty-gdb-utils")

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

Copyright (C) 2013-2016, by Guanlan Dai.

Copyright (C) 2013-2017, by Yichun "agentzh" Zhang (章亦春) <agentzh@gmail.com>, OpenResty Inc.

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
