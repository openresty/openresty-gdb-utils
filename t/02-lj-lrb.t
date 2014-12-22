# vi:ft=

use lib 't/lib';
use Cwd qw( cwd );
use Test::GDB;

plan tests => 3 * blocks();

our $CWD = cwd();

run_tests()

__DATA__

=== TEST 1: BC RET0
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
lrb a.lua:1
c

--- err
--- out_like eval
#use re 'debug';
qr/Searching Lua function at a\.lua:1\.\.\.
Set breakpoint on RET0 \(line \@a\.lua:2\)
(?:Breakpoint \d+ at 0x[0-9a-f]{3,}[^\n]*
)+Return breakpoint hit at
\t\tline \@a\.lua:2 of function a\.lua:1
No return values\.

Breakpoint \d+, 0x[0-9a-f]{3,} in lj_BC_RET0 \(\)
/



=== TEST 2: BC RET1
--- lua
local function f()
    return "hello"
end

collectgarbage()

f()

--- gdb
b lj_cf_collectgarbage
r
del
lrb a.lua:1
c

--- err
--- out_like eval
#use re 'debug';
qr/Searching Lua function at a\.lua:1\.\.\.
Set breakpoint on RET1 \(line \@a\.lua:2\)
(?:Breakpoint \d+ at 0x[0-9a-f]{3,}[^\n]*
)+Return breakpoint hit at
\t\tline \@a\.lua:2 of function a\.lua:1
Returning 1 value\(s\):
\t\tstring: "hello" \(len 5\)

Breakpoint \d+, 0x[0-9a-f]{3,} in lj_BC_RET1 \(\)
/



=== TEST 3: BC RET
--- lua
local function f()
    return "hello", true
end

collectgarbage()

f()

--- gdb
b lj_cf_collectgarbage
r
del
lrb a.lua:1
c

--- err
--- out_like eval
#use re 'debug';
qr/Searching Lua function at a\.lua:1\.\.\.
Set breakpoint on RET \(line \@a\.lua:2\)
(?:Breakpoint \d+ at 0x[0-9a-f]{3,}[^\n]*
)+Return breakpoint hit at
\t\tline \@a\.lua:2 of function a\.lua:1
Returning 2 value\(s\):
\t\tstring: "hello" \(len 5\)
\t\ttrue

Breakpoint \d+, 0x[0-9a-f]{3,} in lj_BC_RET \(\)
/



=== TEST 4: BC RETM
--- lua
local function f()
    return 1, unpack{"hello", true}
end

collectgarbage()

f()

--- gdb
b lj_cf_collectgarbage
r
del
lrb a.lua:1
c

--- err
--- out_like eval
#use re 'debug';
qr/Searching Lua function at a\.lua:1\.\.\.
Set breakpoint on RETM \(line \@a\.lua:2\)
(?:Breakpoint \d+ at 0x[0-9a-f]{3,}[^\n]*
)+Return breakpoint hit at
\t\tline \@a\.lua:2 of function a\.lua:1
Returning 3 value\(s\):
\t\tint 1
\t\tstring: "hello" \(len 5\)
\t\ttrue

Breakpoint \d+, 0x[0-9a-f]{3,} in lj_BC_RET \(\)
/



=== TEST 5: tailcall
--- lua
local function f()
    return unpack{"hello", true}
end

collectgarbage()

f()

--- gdb
b lj_cf_collectgarbage
r
del
lrb a.lua:1
c

--- out_like eval
#use re 'debug';
qr/Searching Lua function at a\.lua:1\.\.\.
/
--- err_like eval
qr/failed to find RET\* instructions in the function a\.lua:1/



=== TEST 6: multiple return points in a single function
--- lua
local function f(a)
    if a > 0 then
        return "hello"
    else
        return "hiya"
    end
end

collectgarbage()

f(1)
f(-1)

--- gdb
b lj_cf_collectgarbage
r
del
lrb a.lua:1
c
c

--- err
--- out_like eval
#use re 'debug';
qr/Searching Lua function at a\.lua:1\.\.\.
Set breakpoint on RET1 \(line \@a\.lua:3\)
Set breakpoint on RET1 \(line \@a\.lua:5\)
Set breakpoint on RET0 \(line \@a\.lua:7\)
(?:Breakpoint \d+ at 0x[0-9a-f]{3,}[^\n]*
)+Return breakpoint hit at
\t\tline \@a\.lua:3 of function a\.lua:1
Returning 1 value\(s\):
\t\tstring: "hello" \(len 5\)

Breakpoint \d+, 0x[0-9a-f]{3,} in lj_BC_RET1 \(\)
Return breakpoint hit at
\t\tline \@a\.lua:5 of function a\.lua:1
Returning 1 value\(s\):
\t\tstring: "hiya" \(len 4\)

Breakpoint \d+, 0x[0-9a-f]{3,} in lj_BC_RET1 \(\)
/

