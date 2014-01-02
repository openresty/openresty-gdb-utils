import gdb
import re
import collections
import os
import sys
sys.path.append(os.path.expanduser(os.path.dirname(__file__)))
from aggregate import *
class LuaGCHashCollisionStat(gdb.Command):
    """This command calculate and print the hash collision distribution in the lua_State specified.
Usage: lhashstat lua_State"""

    def __init__ (self):
        super (LuaGCHashCollisionStat, self).__init__("lhashstat", gdb.COMMAND_USER)

    def type_lookup(self):
        self.hist_log = {}
        self.collide_count = 0
        self.sum_total = 0
        self.collide_min = float('inf')
        self.collide_max = 0
        self.LJ_TNIL = gdb.parse_and_eval("~0u")
        self.LJ_TFALSE = gdb.parse_and_eval("~1u")
        self.LJ_TTRUE = gdb.parse_and_eval("~2u")
        self.LJ_TLIGHTUD = gdb.parse_and_eval("~3u")
        self.LJ_TSTR = gdb.parse_and_eval("~4u")
        self.LJ_TUPVAL = gdb.parse_and_eval("~5u")
        self.LJ_TTHREAD = gdb.parse_and_eval("~6u")
        self.LJ_TPROTO = gdb.parse_and_eval("~7u")
        self.LJ_TFUNC = gdb.parse_and_eval("~8u")
        self.LJ_TTRACE = gdb.parse_and_eval("~9u")
        self.LJ_TCDATA = gdb.parse_and_eval("~10u")
        self.LJ_TTAB = gdb.parse_and_eval("~11u")
        self.LJ_TUDATA = gdb.parse_and_eval("~12u")
        self.LJ_TNUMX = gdb.parse_and_eval("~13u")
        self.int_type = gdb.lookup_type('uint32_t')

        self.lua_State_pointer_type = gdb.lookup_type('lua_State').pointer()
        self.global_State_pointer_type = gdb.lookup_type('global_State').pointer()
        self.Node_pointer_type = gdb.lookup_type('Node').pointer()
        self.int_pointer_type = gdb.lookup_type('uint32_t').pointer()
        self.char_pointer_type = gdb.lookup_type('char').pointer()
        self.TValue_pointer_type = gdb.lookup_type('TValue').pointer()
        self.GCproto_pointer_type = gdb.lookup_type('GCproto').pointer()
        self.GCObj_pointer_type = gdb.lookup_type('GCobj').pointer()
        self.GCstr_pointer_type = gdb.lookup_type('GCstr').pointer()
        self.uint8_t_pointer_type = gdb.lookup_type('uint8_t').pointer()
        self.uint16_t_pointer_type = gdb.lookup_type('uint16_t').pointer()

        self.sizeof_uint32 = gdb.parse_and_eval("sizeof(uint32_t)")
        self.sizeof_TValue = gdb.parse_and_eval("sizeof(TValue)")
        self.sizeof_BCIns = gdb.parse_and_eval("sizeof(BCIns)")
        self.sizeof_GCproto = gdb.parse_and_eval("sizeof(GCproto)")

    def lj_rol(self, x, n):
        return ((x << n) |(x >> ((8 * self.sizeof_uint32 - n))))

    def hashrot(self, lo, hi):
        lo ^= hi
        hi = self.lj_rol(hi, 14)
        lo -= hi
        hi = self.lj_rol(hi, 5)
        hi ^= lo
        hi -= self.lj_rol(lo, 13)
        return hi;

    def hashidx(self, t, h):
        idx = h & t['hmask']
        return idx;

    def hashlohi(self, t, lo, hi):
        return self.hashidx(t, self.hashrot(lo, hi))

    def hashkey(self, t, key):
        if key['it'] == self.LJ_TSTR:
            string = key['gcr']['gcptr32'].cast(self.GCObj_pointer_type)['str']
            return self.hashidx(t, string['hash'])
        elif key['it'] < self.LJ_TNUMX:
            return self.hashlohi(t, key['u32']['lo'], key['u32']['hi'] << 1)
        elif key['it'] == self.LJ_TFALSE or key['it'] == self.LJ_TTRUE:
            return self.hashidx(t, self.LJ_TFALSE - key['it'])
        else:
            return self.hashlohi(t, key['gcr']['gcptr32'],  key['gcr']['gcptr32'] - 0x04c11db7)

    def dup_num(self, l):
        num = 0
        seen = set()
        for x in l:
            if x in seen:
                num += 1
            seen.add(x)
        return num

    def histogram(self, l):
        d = {}
        for x in l:
            if x in d:
                d[x] += 1
            else:
                d[x] = 1
        return d.values()

    def invoke (self, args, from_tty):
        argv = gdb.string_to_argv(args)
        if len(argv) != 1:
            raise gdb.GdbError("Usage: lgc lua_State")

        self.type_lookup()

        m = re.match('0[xX][0-9a-fA-F]+', argv[0])
        if m:
            L = gdb.Value(int(argv[0], 16)).cast(self.lua_State_pointer_type)

        else:
            L = gdb.parse_and_eval(argv[0])

        if not L:
            print "L empty"
            return
        g = L['glref']['ptr32'].cast(self.global_State_pointer_type)
        root = g['gc']['root']['gcptr32'].cast(self.GCObj_pointer_type)
        u = root
        table_num = 0
        if u:
            u = u['gch']['nextgc']['gcptr32'].cast(self.GCObj_pointer_type)
            agg = Aggregate()
            #print u  == root
            while u != root:
                #print u['gch']['gct']
                if u['gch']['nextgc']['gcptr32'] == 0:
                    break

                u = u['gch']['nextgc']['gcptr32'].cast(self.GCObj_pointer_type)
                if u['gch']['gct'] == 11:
                    table_num  += 1
                    tab = u['tab']
                    #sys.stdout.write("<tab: %s>(%s, %s)\n" % (tab.address, tab['asize'], tab['hmask']))
                    nodes = tab['node']['ptr32'].cast(self.Node_pointer_type)
                    idx_list = []
                    node_num = 0
                    for i in xrange(tab['hmask']+1):
                        if nodes[i]['val']['it'] != self.LJ_TNIL:
                            idx = self.hashkey(tab, nodes[i]['key'])
                            idx_list.append(int(idx.__str__()))
                            node_num += 1
                            #print "node[%s] idx=%s" % (i, idx)
                    #print "list = %s" % idx_list
                    collide_num = self.dup_num(idx_list)
                    if node_num > 0:
                        agg << self.histogram(idx_list)
                        #self.hist_log_calc(self.histogram(idx_list))
            #print "sum, count:%d %d" %(self.sum_total, self.collide_count)
            print "table number: %d" % table_num
            print "collusion distribution:"
            agg.hist_log_print()

LuaGCHashCollisionStat()
