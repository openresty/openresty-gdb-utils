import gdb
import re
class ltab(gdb.Command):
    """This command dumps out the all the elems in the lua table specified.
Usage: ltab addr [nil] [r]"""

    def __init__ (self):
        super (ltab, self).__init__("ltab", gdb.COMMAND_USER)

    def type_lookup(self):
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
        self.int32_type = gdb.lookup_type('int32_t')

        self.int_pointer_type = gdb.lookup_type('uint32_t').pointer()
        self.char_pointer_type = gdb.lookup_type('char').pointer()
        self.TValue_pointer_type = gdb.lookup_type('TValue').pointer()
        self.Node_pointer_type = gdb.lookup_type('Node').pointer()
        self.GCObj_pointer_type = gdb.lookup_type('GCobj').pointer()
        self.GCstr_pointer_type = gdb.lookup_type('GCstr').pointer()

    def lvalue(self, val, depth, print_nil, recursive_print):
        if val['it'] == self.LJ_TNIL:
            if print_nil:
                return "nil"
            return ""

        elif val['it'] == self.LJ_TFALSE:
            return "false"

        elif val['it'] == self.LJ_TTRUE:
            return "true"

        elif val['it'] == self.LJ_TLIGHTUD:
            return "<lightudata: 0x%x>" % val.address

        elif (val['it'] >> 15).cast(self.int_type) == -2:
            return "<lightudata: 0x%x>" % val.address

        elif val['it'] == self.LJ_TSTR:
            str_res = val['gcr']['gcptr32'].cast(self.GCObj_pointer_type)['str']
            str_pointer = str_res.address
            src = str_pointer.cast(self.GCstr_pointer_type) + 1
            src = src.cast(self.char_pointer_type).string()
            return "\"%s\"" % src

        elif val['it'] == self.LJ_TUPVAL:
            return "<upval: %s>" % val.address

        elif val['it'] == self.LJ_TTHREAD:
            return "<thread: %s>" % val.address

        elif val['it'] == self.LJ_TPROTO:
            return "<proto: %s>" % val.address

        elif val['it'] == self.LJ_TFUNC:
            return "<func: %s>" % val.address

        elif val['it'] == self.LJ_TTRACE:
            return "<trace: %s>" % val.address

        elif val['it'] == self.LJ_TCDATA:
            return "<cdata: %s>" % val.address

        elif val['it'] == self.LJ_TTAB:
            if not recursive_print:
                return "<tab: %s>" % val.address

            if depth < 3:
                table_addr = val['gcr']['gcptr32']
                table = table_addr.cast(self.GCObj_pointer_type)['tab']
                self.print_table(table, depth + 1 , print_nil, recursive_print)
                return ""
            return "<tab: %s>" % val.address

        elif val['it'] == self.LJ_TUDATA:
            return "<udata: %s>" % val.address

        elif val['it'] < self.LJ_TNUMX:
            num_res = val['n'].cast(self.int32_type)
            return "%s" % num_res

        else:
            return "Value Error!"

    def print_table(self, table, depth, print_nil, recursive_print):
        narray = table['asize']
        nhmask = table['hmask']
        sys.stdout.write("tab(%d, %d): {" % (narray, nhmask))
        array = table['array']['ptr32'].cast(self.TValue_pointer_type)
        for i in xrange(narray):
            if i == 0:
                if array[0]['it'] != self.LJ_TNIL:
                    sys.stdout.write("[%d]=%s, " % (i, self.lvalue(array[0], depth, print_nil, recursive_print)))
                continue

            if array[i]['it'] != self.LJ_TNIL:
                sys.stdout.write("[%d] = " % i)
                res = self.lvalue(array[i], depth, print_nil, recursive_print)
                sys.stdout.write("%s, " % res)

            elif (print_nil):
                sys.stdout.write("[%d] = nil, " % i)

        node = table['node']['ptr32'].cast(self.Node_pointer_type)
        for i in xrange(nhmask+1):
                if node[i]['val']['it'] != self.LJ_TNIL:
                    key_str = self.lvalue(node[i]['key'], depth, print_nil, recursive_print)
                    val_str = self.lvalue(node[i]['val'], depth, print_nil, recursive_print)
                    sys.stdout.write("[%s] = %s, " % (key_str, val_str))

        if narray == 0 and nhmask == 0:
            sys.stdout.write("}")

        else:
            sys.stdout.write("\b\b}")
        return

    def invoke (self, args, from_tty):
        argv = gdb.string_to_argv(args)
        if not (len(argv) == 1 or len(argv) == 2 or len(argv) == 3):
            raise gdb.GdbError("Usage: ltab addr [nil] [r]")

        print_nil = 0
        recursive_print = 0

        if len(argv) == 2:
            if argv[1] == "nil":
                print_nil = 1

            elif argv[1]  == "r":
                recursive_print = 1

            else:
                raise gdb.GdbError("Usage: ltab addr [nil] [r]")

        if len(argv) == 3:
            if (argv[1] == "nil" and argv[2] == "r") or (argv[2] == "nil" and argv[1] == "r"):
                print_nil = 1
                recursive_print = 1

            else:
                raise gdb.GdbError("Usage: ltab addr [nil] [r]")

        self.type_lookup()
        m = re.match('0[xX][0-9a-fA-F]+', argv[0])
        if m:
            val = gdb.Value(int(argv[0], 16)).cast(self.TValue_pointer_type)

        else:
            val = gdb.parse_and_eval(argv[0])

        if not val:
            print "addr empty"
            return

        table_addr = val['gcr']['gcptr32']
        table = table_addr.cast(self.GCObj_pointer_type)['tab']
        self.print_table(table, 0, print_nil, recursive_print)
        sys.stdout.write("\n" )

ltab()

