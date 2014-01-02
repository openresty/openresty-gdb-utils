import sys
class Aggregate():
    def __init__(self):
        self.hist_log = {}
        self.hist_linear = {}
        self.sum_total = 0
        self.bucket_num = 0
        self.minimum = float('inf')
        self.maximum = 0
        self.count = 0
        self.elems = []
        self.hist_elision_num = 3

    def count(self):
        return self.count()

    def sum(self):
        return sum_total;

    def min(self):
        return self.minimum

    def max(self):
        return self.maximum

    def avg(self):
        return self.sum_total/float(self.count)

    def __lshift__(self, other):
        if type(other) is list or type(other) is tuple:
            self.gather_list(other)

        elif type(other) is int:
            self.gather_num(other)
        elif type(other) is float:
            self.gather_num(int(other))

        else:
            raise Exception("type not supported!")

    def next_power_of_two(self, n):
        n -= 1
        n |= n >> 1
        n |= n >> 2
        n |= n >> 4
        n |= n >> 8
        n |= n >> 16
        n  += 1
        return n

    def set_buckets_num(self, low, high, step):
        if step == 0:
            raise Exception("step cannot be zero.\n");
        if low > high:
            raise Exception("low cannot greater than high.\n");
        self.bucket_num = (high - low) / step + 1

    def calc_bucket_start(self, n, low, high, step):
        i = 0
        start = low
        end = low + step
        while i < self.bucket_num:
            if start <= n < end:
                return start
            start += step
            end += step
            i += 1

        return -1

    def set_hist_log(self):
        i = 1
        end = self.next_power_of_two(self.max())
        while i < end:
            if not self.hist_log.has_key(i):
                self.hist_log[i] = 0
            i *= 2

    def set_hist_linear(self, low, high, step):
        self.set_buckets_num(low, high, step)

        for num in self.elems:
            n = self.calc_bucket_start(num, low, high, step)

            if n == -1:
                continue

            if self.hist_linear.has_key(n):
                self.hist_linear[n] += 1

            else:
                self.hist_linear[n] = 1

        i = 0
        start = low
        while i < self.bucket_num:
            if not self.hist_linear.has_key(start):
                self.hist_linear[start] = 0
            start += step
            i += 1

    def print_dict_result(self, d):
        curr_empty_count = 0
        in_elision = False
        l = sorted(d.keys())
        sys.stdout.write("value\t|")
        sys.stdout.write("------------------------------------------------ count\n")
        for i in l:

            if d[i] == 0:
                curr_empty_count += 1

            if d[i] != 0:
                curr_empty_count = 0

            if in_elision and d[i] != 0:
                curr_empty_count = 0
                in_elision = False

            if curr_empty_count >= self.hist_elision_num:
                if not in_elision:
                    in_elision = True
                    sys.stdout.write("\t~\n")
                continue

            sys.stdout.write("%d\t|" % i)
            at_sign_num = d[i] / float(self.count) * 50
            at_sign_num = int(at_sign_num)
            space_num = 50 - at_sign_num
            sys.stdout.write("@" * at_sign_num)
            sys.stdout.write(" " * space_num)
            sys.stdout.write("%d" % d[i])
            sys.stdout.write("\n")
        return

    def hist_log_print(self):
        self.set_hist_log()
        self.print_dict_result(self.hist_log)

    def hist_linear_print(self, low, high, step):
        self.set_hist_linear(low, high, step)
        self.print_dict_result(self.hist_linear)

    def gather_list(self, l):
        self.elems.extend(l)
        self.count += len(l)
        self.sum_total += sum(l)

        if max(l) > self.maximum:
            self.maximum = max(l)

        if min(l) < self.minimum:
            self.minimum = min(l)

        for num in l:
            n = self.next_power_of_two(num)
            if self.hist_log.has_key(n):
                self.hist_log[n] += 1

            else:
                self.hist_log[n] = 1

    def gather_num(self, num):
        self.elems.append(num)
        self.count += 1
        self.sum_total += num

        if num > self.maximum:
            self.maximum = num

        if num < self.minimum:
            self.minimum = num

        n = self.next_power_of_two(num)
        if self.hist_log.has_key(n):
            self.hist_log[n] += 1

        else:
            self.hist_log[n] = 1

if __name__ == "__main__":
    a = Aggregate()
    """a << [-101, -400,-100860,  2, 42, 2, 3, 3, 202, 1241, 32141, 12312, 124, 123, 4, 312, 4, 6, 7, 83]
    a << 51
    a << 200
    a << 700
    a << 1700
    a << 12.6
    a  << (2000, 2000)
    """
    a << 1
    a << 100
    print "max/avg/min: %d/%.1f/%d" % (a.max(), a.avg(), a.min())
    a.hist_log_print()
    print ""
    a.hist_linear_print(0, 2000, 100)
