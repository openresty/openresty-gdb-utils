import gdb
import re
class lbt(gdb.Command):
    """This command dumps out the current Lua-land backtrace in the lua_State specified. Only LuaJIT 2.0 interpreted code is supported.
Usage: lbt lua_State"""

    def __init__ (self):
        super (lbt, self).__init__("lbt", gdb.COMMAND_USER)

    def type_lookup(self):
        self.int_type = gdb.lookup_type('uint32_t')

        self.lua_State_pointer_type = gdb.lookup_type('lua_State').pointer()
        self.int_pointer_type = gdb.lookup_type('uint32_t').pointer()
        self.char_pointer_type = gdb.lookup_type('char').pointer()
        self.TValue_pointer_type = gdb.lookup_type('TValue').pointer()
        self.GCproto_pointer_type = gdb.lookup_type('GCproto').pointer()
        self.GCObj_pointer_type = gdb.lookup_type('GCobj').pointer()
        self.GCstr_pointer_type = gdb.lookup_type('GCstr').pointer()
        self.uint8_t_pointer_type = gdb.lookup_type('uint8_t').pointer()
        self.uint16_t_pointer_type = gdb.lookup_type('uint16_t').pointer()

        self.sizeof_TValue = gdb.parse_and_eval("sizeof(TValue)")
        self.sizeof_BCIns = gdb.parse_and_eval("sizeof(BCIns)")
        self.sizeof_GCproto = gdb.parse_and_eval("sizeof(GCproto)")

    def getstack(self, L, level):
        bot = L['stack']['ptr32']
        if bot == 0:
            return -1
        frame = L['base'] - 1
        nextframe = frame
        found_frame = 0

        while frame > bot:
            if frame['fr']['func']['gcptr32'] == L.cast(self.int_type):
                level += 1
            level -=1
            if level+1 == 0:
                size = (nextframe.cast(self.int_type) - frame.cast(self.int_type)) / self.sizeof_TValue
                found_frame = 1
                break

            nextframe = frame

            if frame['fr']['tp']['ftsz']& 3 == 0:
                pc = frame['fr']['tp']['pcr']['ptr32']
                pc = pc.cast(self.int_pointer_type)[-1]
                offset = (1 + ((pc.cast(self.int_type) >> 8) & 0xff))
                frame = frame - offset

            else:
                if frame['fr']['tp']['ftsz'] & 7 == 3:
                    level  += 1
                frame = frame.cast(self.char_pointer_type) - (frame['fr']['tp']['ftsz'] & ~(3|4))
                frame = frame.cast(self.TValue_pointer_type)

        if found_frame == 0:
            size = level
            frame = 0

        if frame != 0:
            i_ci = (size << 16) + (frame.cast(self.int_type) - bot) / self.sizeof_TValue
            return i_ci
        return -1

    def lj_debug_line(self, pt, pc):
        pt = pt.cast(self.GCproto_pointer_type)
        lineinfo = pt['lineinfo']['ptr32']

        if pc <= pt['sizebc'] and lineinfo:
            first = pt['firstline']
            if pc == pt['sizebc']:
                return first + pt['numline']

            pc -= 1
            if pc == -1:
                return first

            if pt['numline'] < 256:
                return first + lineinfo.cast(self.uint8_t_pointer_type)[pc]

            if pt['numline'] < 65536:
                return first + lineinfo.cast(self.uint16_t_pointer_type)[pc]

            return first + lineinfo.cast(self.int_pointer_type)[pc]
        return 0

    def debug_framepc(self, L, fn, nextframe):
        if nextframe == 0:
            return ~0
        nextframe = nextframe.cast(self.TValue_pointer_type)

        if nextframe['fr']['tp']['ftsz'] & 3 == 0:
            #frame is lua
            ins = nextframe['fr']['tp']['pcr']['ptr32']

        elif nextframe['fr']['tp']['ftsz'] & 7 == 2:
            #frame is cont
            ins = nextframe['fr']['tp']['pcr']['ptr32'] - self.sizeof_BCIns

        else:
            #print "frame is cframe\n"
            #raw cframe
            cf = L['cframe'].cast(self.int_type) & ~(1|2)
            if cf == 0:
                return ~0
            f = L['base'] - 1
            while f > nextframe:
                if nextframe['fr']['tp']['ftsz'] & 3 == 0:
                    #frame is lua
                    pc = f['fr']['tp']['pcr']['ptr32']
                    f = f - (1 + ((pc - 4)>>8 & 0xff))

                else:
                    if f['fr']['tp']['ftsz'] & 3 == 1:
                        cframe_prev = cf + 400
                        cf = cframe_prev & ~(1|2)
                    f = f - (f['fr']['tp']['ftsz'] & ~(3|4))

            if (cf + 400) != 0:
                cframe_prev = cf + 400
                cf = cframe_prev & ~(1|2)

            ins = cf + 412

        pt = fn['l']['pc']['ptr32'] - self.sizeof_GCproto
        res = (ins - (pt + self.sizeof_GCproto)) / self.sizeof_BCIns
        return res - 1

    def debug_frameline(self, L, fn, nextframe):
        pc = self.debug_framepc(L, fn, nextframe)
        if pc != ~0:
            pt = fn['l']['pc']['ptr32'] - self.sizeof_GCproto
            return self.lj_debug_line(pt, pc)
        return -1

    def getinfo(self, L, i_ci):
        offset = i_ci & 0xffff
        if offset == 0:
            return ""

        frame = L['stack']['ptr32'] + offset * self.sizeof_TValue
        size = i_ci >> 16
        if size:
            nextframe = frame + size * self.sizeof_TValue

        else:
            nextframe = 0

        maxstack = L['maxstack']['ptr32']

        if not ((frame <= maxstack)
                 and ((nextframe == 0)
                       or (nextframe <= maxstack))):
            return ""

        f = frame.cast(self.TValue_pointer_type).dereference()
        gcr = f['fr']['func']['gcptr32']

        if gcr == 0:
            return ""

        else:
            fn = gcr.cast(self.GCObj_pointer_type).dereference()['fn']

        if fn['c']['gct'] != 8 :
            return ""

        if fn['c']['ffid'] == 0:
            #isluafunc(fn)
            if frame != 0:
                currentline = self.debug_frameline(L, fn, nextframe)

            else:
                currentline = -1
            pt = fn['l']['pc']['ptr32'] - self.sizeof_GCproto
            name = pt.cast(self.GCproto_pointer_type)['chunkname']
            gco = name['gcptr32']
            if gco == 0:
                src = ""

            else:
                string = gco.cast(self.GCObj_pointer_type)['str']
                str_pointer = string.address
                src = str_pointer.cast(self.GCstr_pointer_type) + 1
                src = src.cast(self.char_pointer_type)
            if currentline == -1:
                return src.string()

            return "%s:%s" % (src.string(), currentline)

        #being a C function
        cfunc = fn['c']['f']
        m = re.search('<.*?(\w+)*.*?>', cfunc.__str__())
        if m:
            res = m.group(1)
            return "C:" + res

        return ""

    def invoke (self, args, from_tty):
        argv = gdb.string_to_argv(args)
        if len(argv) != 1:
            raise gdb.GdbError("Usage: lbt lua_State")

        self.type_lookup()

        m = re.match('0[xX][0-9a-fA-F]+', argv[0])
        if m:
            L = gdb.Value(int(argv[0], 16)).cast(self.lua_State_pointer_type)

        else:
            L = gdb.parse_and_eval(argv[0])

        if not L:
            print "L empty"
            return

        stack = ""
        level = 0
        prev_is_tail = 0
        while True:
            i_ci = self.getstack(L, level)
            #print "getstack returned: %d\n" %i_ci
            level += 1

            if i_ci < 0 or level > 100:
                break

            frame = self.getinfo(L, i_ci)

            if frame == "":
                stack = ""
                break

            if frame == "[tail]":
                if prev_is_tail != 0:
                    continue
                prev_is_tail = 1

            else:
                prev_is_tail = 0

            stack += frame + "\n"

        if stack != "":
            print stack
            return

        print "empty backtrace"
        return
lbt()
