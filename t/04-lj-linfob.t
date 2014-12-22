# vi:ft=

use lib 't/lib';
use Cwd qw( cwd );
use Test::GDB;

plan tests => 3 * blocks();

our $CWD = cwd();

run_tests()

__DATA__

=== TEST 1: entry breakpoints only
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
linfob

--- err
--- out_like eval
#use re 'debug';
qr/^Type \s+ Address \s+ What \n
entry \s+ \(GCfunc\*\)0x[0-9a-f]{3,} \s+ a\.lua:1 \n
entry \s+ \(GCfunc\*\)0x[0-9a-f]{3,} \s+ a\.lua:5 \n
/smx



=== TEST 2: return breakpoints only
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
linfob

--- err
--- out_like eval
#use re 'debug';
qr/^Type \s+ Address \s+ What \n
return \s+ \(BCIns\*\)0x[0-9a-f]{3,} \s+ \Qa.lua:5 in func \E\@a\.lua:6 \n
return \s+ \(BCIns\*\)0x[0-9a-f]{3,} \s+ \Qa.lua:1 in func \E\@a\.lua:2 \n
/smx



=== TEST 3: mixing return and entry breakpoints
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
lb a.lua:5
linfob

--- err
--- out_like eval
#use re 'debug';
qr/^Type \s+ Address \s+ What \n
entry \s+ \(GCfunc\*\)0x[0-9a-f]{3,} \s+ a\.lua:5 \n
return \s+ \(BCIns\*\)0x[0-9a-f]{3,} \s+ \Qa.lua:1 in func \E\@a\.lua:2 \n
/smx



=== TEST 4: entry breakpoints on *
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
lb *
linfob

--- err
--- out_like eval
#use re 'debug';
qr/^Type \s+ Address \s+ What \n
entry \s+ - \s+ \* \n
/smx

