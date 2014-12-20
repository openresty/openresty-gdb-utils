# vi:ft=

use lib 't/lib';
use Cwd qw( cwd );
use Test::GDB;

plan tests => 3 * blocks();

our $CWD = cwd();

run_tests()

__DATA__

=== TEST 1: trace recording, entry, and exit
--- lua
jit.opt.start("hotloop=1", "hotexit=1")

local function f()
    local a = 0
    for i = 1, 200 do
        a = a + i
    end
end

f()

collectgarbage()

f()

--- gdb
b lj_cf_collectgarbage
r
del
ltb
c
c
c
c

--- err
--- out_like eval
#use re 'debug';
qr/==> Enter trace \#1: L=0x[a-f0-9]{3,} pc=0x[a-f0-9]{3,}
\tline: \@a\.lua:8
\tfunction: \@a\.lua:3
.*?
\*\*\* Start recording trace \#3: L=0x[a-f0-9]{3,} pc=0x[a-f0-9]{3,}
\tline: \@a\.lua:8
\tfunction: \@a\.lua:3
.*?
<== Normal exit trace \#1: L=0x[a-f0-9]{3,} pc=0x[a-f0-9]{3,}
\texit no: 3
\tline: \@a\.lua:8
\tfunction: \@a\.lua:3
\tbacktrace:
\@a\.lua:5
\tlocal "a":
\t\tint 20100
/s

