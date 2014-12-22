# vi:ft=

use lib 't/lib';
use Cwd qw( cwd );
use Test::GDB;

plan tests => 3 * blocks();

our $CWD = cwd();

run_tests()

__DATA__

=== TEST 1: BC CALL (no args)
--- lua
local function f()
    return
end

collectgarbage()

f()

--- gdb
b lj_cf_collectgarbage
r
del
lb a.lua:1
c

--- err
--- out_like eval
qr/Searching Lua function at a\.lua:1\.\.\.
Set break point on \(GCfunc\*\)0x[0-9a-f]{3,} at \@a\.lua:1
(?:Breakpoint \d+ at 0x[0-9a-f]{3,}[^\n]*
)+Entry breakpoint hit at
\t\tfunction \@a\.lua:1: \(GCfunc\*\)0x[0-9a-f]{3,}
source line: \@a\.lua:7
Taking no arguments\.

Breakpoint \d+, 0x[0-9a-f]{3,} in lj_BC_CALL \(\)
/



=== TEST 2: BC CALL (2 fixed args)
--- lua
local function f(a, b)
    return a + b
end

collectgarbage()

f(1, 2.4)

--- gdb
b lj_cf_collectgarbage
r
del
lb a.lua:1
c

--- err
--- out_like eval
qr/Searching Lua function at a\.lua:1\.\.\.
Set break point on \(GCfunc\*\)0x[0-9a-f]{3,} at \@a\.lua:1
(?:Breakpoint \d+ at 0x[0-9a-f]{3,}[^\n]*
)+Entry breakpoint hit at
\t\tfunction \@a\.lua:1: \(GCfunc\*\)0x[0-9a-f]{3,}
source line: \@a\.lua:7
Taking 2 arguments:
\t\tint 1
\t\tnumber 2\.4

Breakpoint \d+, 0x[0-9a-f]{3,} in lj_BC_CALL \(\)
/



=== TEST 3: BC CALL (no match)
--- lua
local function f()
    return
end

collectgarbage()

f()

--- gdb
b lj_cf_collectgarbage
r
del
lb a.lua:2
c

--- err_like chop
failed to find Lua function matching a\.lua:2
--- out_like chop
Searching Lua function at a\.lua:2\.\.\.



=== TEST 4: BC CALLM (all from MULTRES)
--- lua
local function f(a, b)
    return a + b
end

collectgarbage()

f(unpack{1, 2.4})

--- gdb
b lj_cf_collectgarbage
r
del
lb a.lua:1
c

--- err
--- out_like eval
qr/Searching Lua function at a\.lua:1\.\.\.
Set break point on \(GCfunc\*\)0x[0-9a-f]{3,} at \@a\.lua:1
(?:Breakpoint \d+ at 0x[0-9a-f]{3,}[^\n]*
)+Entry breakpoint hit at
\t\tfunction \@a\.lua:1: \(GCfunc\*\)0x[0-9a-f]{3,}
source line: \@a\.lua:7
Taking 2 arguments:
\t\tint 1
\t\tnumber 2\.4

Breakpoint \d+, 0x[0-9a-f]{3,} in lj_BC_CALLM \(\)
/



=== TEST 5: BC CALLM (just partially from MULTRES)
--- lua
local function f(a, b)
    return a + b
end

collectgarbage()

f(0, -1, unpack{1, 2.4})

--- gdb
b lj_cf_collectgarbage
r
del
lb a.lua:1
c

--- err
--- out_like eval
qr/Searching Lua function at a\.lua:1\.\.\.
Set break point on \(GCfunc\*\)0x[0-9a-f]{3,} at \@a\.lua:1
(?:Breakpoint \d+ at 0x[0-9a-f]{3,}[^\n]*
)+Entry breakpoint hit at
\t\tfunction \@a\.lua:1: \(GCfunc\*\)0x[0-9a-f]{3,}
source line: \@a\.lua:7
Taking 4 arguments:
\t\tint 0
\t\tint -1
\t\tint 1
\t\tnumber 2\.4

Breakpoint \d+, 0x[0-9a-f]{3,} in lj_BC_CALLM \(\)
/



=== TEST 6: BC CALLT
--- lua
local function f(a, b)
    return a + b
end

local function g()
    return f(5, 6)
end

collectgarbage()

g()

--- gdb
b lj_cf_collectgarbage
r
del
lb a.lua:1
c

--- err
--- out_like eval
qr/Searching Lua function at a\.lua:1\.\.\.
Set break point on \(GCfunc\*\)0x[0-9a-f]{3,} at \@a\.lua:1
(?:Breakpoint \d+ at 0x[0-9a-f]{3,}[^\n]*
)+Entry breakpoint hit at
\t\tfunction \@a\.lua:1: \(GCfunc\*\)0x[0-9a-f]{3,}
source line: \@a\.lua:6
Taking 2 arguments:
\t\tint 5
\t\tint 6

Breakpoint \d+, 0x[0-9a-f]{3,} in lj_BC_CALLT \(\)
/



=== TEST 7: BC CALLTM
--- lua
local function f(a, b)
    return a + b
end

local function g()
    return f(unpack{5, 6})
end

collectgarbage()

g()

--- gdb
b lj_cf_collectgarbage
r
del
lb a.lua:1
c

--- err
--- out_like eval
#use re 'debug';
qr/Searching Lua function at a\.lua:1\.\.\.
Set break point on \(GCfunc\*\)0x[0-9a-f]{3,} at \@a\.lua:1
(?:Breakpoint \d+ at 0x[0-9a-f]{3,}[^\n]*
)+Entry breakpoint hit at
\t\tfunction \@a\.lua:1: \(GCfunc\*\)0x[0-9a-f]{3,}
source line: \@a\.lua:6
Taking 2 arguments:
\t\tint 5
\t\tint 6

Breakpoint \d+, 0x[0-9a-f]{3,} in lj_BC_CALLT \(\)
/



=== TEST 8: *
--- lua
local function f()
    return
end

collectgarbage()

f()

--- gdb
b lj_cf_collectgarbage
r
del
lb *
c

--- err
--- out_like eval
qr/(?:Breakpoint \d+ at 0x[0-9a-f]{3,}[^\n]*
)+Entry breakpoint hit at
\t\tfunction \@a\.lua:1: \(GCfunc\*\)0x[0-9a-f]{3,}
source line: \@a\.lua:7
Taking no arguments\.

Breakpoint \d+, 0x[0-9a-f]{3,} in lj_BC_CALL \(\)
/



=== TEST 9: multiple entry breakpoints
--- lua
local function f()
    return
end

local function g()
    return
end

collectgarbage()

f()
g()

--- gdb
b lj_cf_collectgarbage
r
del
lb a.lua:1
lb a.lua:5
c
c

--- err
--- out_like eval
qr/Entry breakpoint hit at
\t\tfunction \@a\.lua:1: \(GCfunc\*\)0x[0-9a-f]{3,}
source line: \@a\.lua:11
.*?
Entry breakpoint hit at
\t\tfunction \@a\.lua:5: \(GCfunc\*\)0x[0-9a-f]{3,}
source line: \@a\.lua:12
/s

