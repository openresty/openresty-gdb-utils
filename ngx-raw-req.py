import gdb
import re
class NgxRawReq(gdb.Command):
    """This command dumps out the raw request header in the request specified.
Usage: ngx-raw-req <ngx_http_request>"""

    def __init__ (self):
        super (NgxRawReq, self).__init__("ngx-raw-req", gdb.COMMAND_USER)

    def type_lookup(self):
        self.int_type = gdb.lookup_type('uint32_t')

        self.ngx_http_request_pointer_type = gdb.lookup_type('ngx_http_request_t').pointer()
        self.char_pointer_type = gdb.lookup_type('char').pointer()

    def invoke (self, args, from_tty):
        argv = gdb.string_to_argv(args)
        if len(argv) != 1:
            raise gdb.GdbError("Usage: ngx-raw-req ngx_http_request")

        self.type_lookup()

        m = re.match('0[xX][0-9a-fA-F]+', argv[0])
        if m:
            r = gdb.Value(int(argv[0], 16)).cast(self.ngx_http_request_pointer_type)

        else:
            r = gdb.parse_and_eval(argv[0])

        if not r:
            print("r empty")
            return

        ascii_list = []
        data = ""
        first = None
        hc = r['main']['http_connection'];
        request_line = r['main']['request_line']
        #print("hc['nbusy']=%s" % hc['nbusy'])
        if hc['nbusy']:
            size = 0
            for i in xrange(int(hc['nbusy'])):
                b = hc['busy'][i]
                line_data = request_line['data']

                if first is None:
                    if (line_data >= b['pos'] or
                        line_data + request_line['len'] + 2 <= b['start']):
                        continue
                    first = b

                if b == r['main']['header_in']:
                    size += r['main']['header_end'] + 2 - b['start']
                    break
                size += b['pos'] - b['start']

        else:
            b = r['main']['header_in']
            if not b:
                print("not found")
            size = r['main']['header_end'] + 2 - request_line['data']

        #print("size: %s" % size)
        if hc['nbusy']:
            #print("hc['nbusy']")
            #print("first %s" % first)
            last = data
            found = 0
            for i in xrange(int(hc['nbusy'])):
                ascii_list = []
                b = hc['busy'][i]
                if not found:
                    if b != first:
                        continue
                    found = 1
                p = last

                if b == r['main']['header_in']:
                    pos = r['main']['header_end'] + 2

                else:
                    pos = b['pos']

                #print("r['main']['header_end']= %s" % r['main']['header_end'])
                #print("b['start']= %s" % b['start'])

                if b == first:
                    data = request_line['data']
                    length =  pos - request_line['data']
                else:
                    data = b['start']
                    length = pos - b['start']

                #print("length %s" % length)

                for i in xrange(length):
                    p = int(data[i])
                    if p == 0:
                        if data[i+1] == ord('\n') and i != size:
                            ascii_list.append(ord('\r'))

                        else:
                            ascii_list.append(ord(':'))
                    else:
                        ascii_list.append(p)

                ch = ascii_list.pop()
                while ch != ord('\n') and ascii_list.count > 0:
                    ch = ascii_list.pop()

                res = ''.join(map(chr, ascii_list))
                print(res)

                if b == r['main']['header_in']:
                    break

        else:
            #print("size:%d" % int(size))
            data = request_line['data']
            #print("data type:%s" % data.type)
            #print(data)
            size = int(size)
            for i in xrange(size):
                p = int(data[i])
                if p == 0:
                    if data[i + 1] == ord('\n') and i != size:
                        ascii_list.append(ord('\r'))

                    else:
                        ascii_list.append(ord(':'))
                else:
                    ascii_list.append(p)
            res = ''.join(map(chr, ascii_list))
            print(res)
        return

NgxRawReq()
