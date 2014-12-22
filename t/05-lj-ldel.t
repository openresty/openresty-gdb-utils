# vi:ft=

use lib 't/lib';
use Cwd qw( cwd );
use Test::GDB;

plan tests => 3 * blocks();

our $CWD = cwd();

run_tests()

__DATA__

=== TEST 1: remove one entry break point frm multiple ones
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
ldel a.lua:1
c

--- err
--- out_like eval
#use re 'debug';
qr/Remove entry breakpoint on \(GCfunc\*\)0x[a-f0-9]{3,} at \@a\.lua:1
Entry breakpoint hit at
\t\tfunction \@a\.lua:5: \(GCfunc\*\)0x[a-f0-9]{3,}
/ms



=== TEST 2: remove one return break point frm multiple ones
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
lrb a.lua:1
lrb a.lua:5
ldel a.lua:1
c

--- err
--- out_like eval
#use re 'debug';
qr/Remove return breakpoint on \(GCfunc\*\)0x[a-f0-9]{3,} at \@a\.lua:1
Return breakpoint hit at
\t\tline \@a\.lua:6 of function a\.lua:5
/ms



=== TEST 3: remove all break points one by one
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
lrb a.lua:1
lb a.lua:5
ldel a.lua:1
ldel a.lua:5
linfob
c

--- err_like
No Lua breakpoints.

--- out_like eval
#use re 'debug';
qr/^Searching Lua function at a\.lua:1\.\.\.
Remove entry breakpoint on \(GCfunc\*\)0x[0-9a-f]{3,} at \@a\.lua:1
Remove return breakpoint on \(GCfunc\*\)0x[0-9a-f]{3,} at \@a\.lua:1
Searching Lua function at a\.lua:5\.\.\.
Remove entry breakpoint on \(GCfunc\*\)0x[0-9a-f]{3,} at \@a\.lua:5
/ms

