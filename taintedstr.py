import inspect
import enum
import hashlib
import os

OpId = {}
def h_id(s):
    global OpId
    if s not in OpId: OpId[s] = int(hashlib.sha256(s.encode('utf-8')).hexdigest(), 16) % 10**8
    return OpId[s]

class Op(enum.Enum):
    EQ = enum.auto()
    NE = enum.auto()
    IN = enum.auto()
    NOT_IN = enum.auto()

class TaintException(Exception):
    pass

class CExpander:
    def __init__(self, op, op_name, opA, opB):
        self.op, self.op_name, self.opA, self.opB = op, op_name, opA, opB
        self._expanded = []

    def _find(self, opA, opB):
        sub, start, end = opB
        substr = opA[start:end]
        result = next((i for i,c in substrings(substr, len(sub)) if self._eq(c, sub)), None)
        return result

    def _eq(self, opA, opB):
        if len(opA) == 0 and len(opB) == 0:
            self._expanded.append(Instr(Op.EQ, opA, opB, True))
            return True
        elif  len(opA) == 0:
            self._expanded.append(Instr(Op.EQ, opA, opB[0], False))
            return False
        elif len(opB) == 0:
            self._expanded.append(Instr(Op.EQ, opA[0], opB, False))
            return False
        elif len(opA) == 1 and len(opB) == 1:
            v = (str(opA) == str(opB)) # dont add to compare taints
            self._expanded.append(Instr(Op.EQ, opA, opB, v))
            return v
        else:
            if not self._eq(opA[0], opB[0]): return False
            return self._eq(opA[1:], opB[1:])

    def _lstrip(self, opA, opB):
        last = len(opA)
        for i in range(0, last):
            ic = opA[i]
            found = False
            for jc in list(str(opB)):
                if self._eq(ic, jc):
                    found = True
                    break
            if not found:
                return opA[i:]
        return opA

    def _rstrip(self, opA, opB):
        last_idx = len(opA)-1
        for i in range(last_idx, -1, -1):
            ic = opA[i]
            found = False
            for jc in list(str(opB)):
                if self._eq(ic, jc):
                    found = True
                    break
            if not found:
                return opA[0:i]
        return opA

    def _strip(self, opA, opB):
        return self._rstrip(self._lstrip(opA, opB), opB)

    def expand(self):
        if self._expanded: return self._expanded
        # expand multy char string comparisons
        if self.op == h_id('__eq__'):
            self._eq(self.opA, self.opB)
            return self._expanded
        elif self.op == h_id('__ne__'):
            self._eq(self.opA, self.opB)
            return self._expanded
        elif self.op == h_id('in_'):
            result = [self._eq(self.opA, c) for i,c in substrings(self.opB, len(self.opA))]
            return self._expanded
        elif self.op == h_id('find'):
            self._find(self.opA, self.opB)
            return self._expanded
        elif self.op == h_id('rstrip'):
            self._rstrip(self.opA, self.opB)
            return self._expanded
        elif self.op == h_id('lstrip'):
            self._lstrip(self.opA, self.opB)
            return self._expanded
        elif self.op == h_id('strip'):
            self._strip(self.opA, self.opB)
            return self._expanded
        else:
            import sys
            print("Not Implemented", self.op_name, file=sys.stderr, flush=True)
            raise NotImplementedError

class Instr:

    def __getstate__(self):
        state = self.__dict__.copy()
        return state

    def __init__(self,o, a, b, r):
        self.opA = a
        self.opB = b
        if isinstance(o, str):
            self.op = h_id(o)
            self.op_name = o
        else:
            self.op = o
            self.op_name = o.name
        self.r = r
        self._value = CExpander(self.op, self.op_name, a, b)

    def expand(self):
        return self._value.expand()

    def opS(self):
        if not self.opA.has_taint() and type(self.opB) is tstr:
            return (self.opB, self.opA)
        else:
            return (self.opA, self.opB)

    @property
    def op_A(self): return self.opS()[0]

    @property
    def op_B(self): return self.opS()[1]


    def __repr__(self):
        return "%s,%s,%s" % (self.op_name, repr(self.opA), repr(self.opB))

    def __hash__(self):
        return hash(repr(self))

    def __eq__(self, other):
        return repr(self) == repr(other)

    def __str__(self):
        return str((self.op_name, repr(self.opA), repr(self.opB)))

class tstr_iterator():
    def __init__(self, tstr):
        self._tstr = tstr
        self._str_idx = 0

    def __next__(self):
        if self._str_idx == len(self._tstr): raise StopIteration
        # calls tstr getitem should be tstr
        c = self._tstr[self._str_idx]
        assert type(c) is tstr
        self._str_idx += 1
        return c

def substrings(s, l):
    for i in range(len(s)-(l-1)):
        yield (i, s[i:i+l])

class tstr(str):

    def __getstate__(self):
        state = self.__dict__.copy()
        if 'comparisons' in state: state['comparisons'] = []
        return state

    def __new__(cls, value, *args, **kw):
        return super(tstr, cls).__new__(cls, value)

    def __init__(self, value, taint=None, parent=None):
        """
        >>> my_str = tstr('abcd')
        >>> my_str._taint
        [0, 1, 2, 3]
        >>> my_str = tstr('abcd', taint=[0,0,1,1])
        >>> my_str._taint
        [0, 0, 1, 1]
        """
        # tain map contains non-overlapping portions that are mapped to the
        # original string
        self.parent = parent
        l = len(self)
        if taint:
            # assert that the provided tmap carries only
            # as many entries as len.
            assert len(taint) == l
            self._taint = taint
        else:
            self._taint = list(range(0, l))
        self.comparisons = parent.comparisons if parent is not None else []

    def untaint(self):
        """
        >>> my_str = tstr('abcd')
        >>> my_str._taint
        [0, 1, 2, 3]
        >>> my_str.untaint()
        'abcd'
        >>> my_str._taint
        [-1, -1, -1, -1]
        """
        self._taint =  [-1] * len(self)
        return self

    def has_taint(self):
        """
        >>> my_str = tstr('abcd')
        >>> my_str.has_taint()
        True
        >>> my_str.untaint()
        'abcd'
        >>> my_str.has_taint()
        False
        """
        return any(True for i in self._taint if i >= 0)

    def __repr__(self):
        return str.__repr__(self)

    def __str__(self):
        return str.__str__(self)

    def x(self, i=0):
        v = self._x(i)
        if v < 0:
            raise TaintException('Invalid mapped char idx in tstr')
        return v

    def _x(self, i=0):
        return self.get_mapped_char_idx(i)

    def get_mapped_char_idx(self, i):
        """
        >>> my_str = tstr('abc')
        >>> my_str.get_mapped_char_idx(0)
        0
        >>> my_str = tstr('abcdefghijkl', taint=list(range(4,16)))
        >>> my_str.get_mapped_char_idx(4)
        8
        """

        # if the current string is not mapped to input till
        # char 10 (_unmapped_till), but the
        # character 10 is mapped to character 5 (_idx)
        # then requesting 10 should return 5
        #   which is 5 - 10 + 10
        # and requesting 11 should return 6
        #   which is 5 - 10 + 11
        if self._taint:
            return self._taint[i]
        else:
            if i != 0: raise TaintException('Invalid request idx')
            # self._tcursor gets created only for empty strings.
            # use the exception to determine which ones need it.
            return self._tcursor

    # returns the index of the character this substring maps to
    # e.g. "start" is the original string, "art" is the current string, then
    # "art".get_first_mapped_char() returns 2
    def get_first_mapped_char(self):
        """
        >>> my_str = tstr('abc')
        >>> my_str.get_first_mapped_char()
        0
        >>> my_str = tstr('abcdefghijkl', taint=list(range(4,16)))
        >>> my_str.get_first_mapped_char()
        4
        """
        return next((i for i in self._taint if i >= 0), -1)

    # tpos is the index in the input string that we are
    # looking to see if contained in this string.
    def is_tpos_contained(self, tpos):
        """
        >>> my_str = tstr('abcdefghijkl', taint=list(range(4,16)))
        >>> my_str.is_tpos_contained(2)
        False
        >>> my_str.is_tpos_contained(4)
        True
        """
        return tpos in self._taint

    # idx is the string index of current string.
    def is_idx_tainted(self, idx):
        """
        >>> my_str = tstr('abcdefghijkl', taint=sum([list(range(4,10)), ([-1] * 6)],[]))
        >>> my_str.is_idx_tainted(2)
        True
        >>> my_str.is_idx_tainted(11)
        False
        """
        return self._taint[idx] != -1

    def in_(self, s):
        """
        >>> abc = tstr('78')
        >>> abc.get_mapped_char_idx(0)
        0
        >>> my_str = '0123456789'
        >>> abc.in_(my_str)
        True
        >>> abc.comparisons
        [in_,'78','0123456789']
        """

        r = self.__in_(s)
        self.comparisons.append(Instr(inspect.currentframe().f_code.co_name, self, s, r))
        return r

    def __in_(self, s):
        # c in '0123456789'
        # to
        # c.in_('0123456789')
        # ensure that all characters are compared
        return (str(self) in s)

    def __getitem__(self, key):          # splicing ( [ ] )
        """
        >>> my_str = tstr('abcdefghijkl', taint=list(range(4,16)))
        >>> my_str[0].x()
        4
        >>> my_str[-1].x()
        15
        >>> my_str[-2].x()
        14
        >>> s = my_str[0:4]
        >>> s.x(0)
        4
        >>> s.x(3)
        7
        >>> s = my_str[0:-1]
        >>> len(s)
        11
        >>> s.x(10)
        14
        >>> my_str.comparisons
        []
        """
        # No comparisons
        res = super().__getitem__(key)
        if type(key) == slice:
            if res:
                return tstr(res, self._taint[key], self)
            else:
                t = tstr(res, self._taint[key], self)
                key_start = 0 if key.start is None else key.start
                key_stop = len(res) if key.stop is None else key.stop
                if not len(t):
                    # the string to be returned is an empty string. For
                    # detecting EOF comparisons, we still need to carry
                    # the cursor. The main idea is the cursor indicates
                    # the taint of the character in front of it.
                    # is range start in str?
                    if key_start < len(self):
                        #is range end in str?
                        if key_stop < len(self):
                            # The only correct value for cursor.
                            t._tcursor = self._taint[key_stop]
                        else:
                            # keystart was within the string but keystop was
                            # not in an empty string -- something is wrong
                            raise TaintException('Odd empty string')
                    else:
                        # Key start was not in the string. We can reply only
                        # if the key start was just outside the string, in
                        # which case, we guess.
                        if len(self) == 0:
                            t._tcursor = self.x()
                        else:
                            if key_start == len(self):
                                t._tcursor = self._taint[len(self)-1] + 1 #
                            else:
                                # consider if we want to untaint instead
                                raise TaintException('Can not guess taint')
                return t

        elif type(key) == int:
            if key < 0:
                key = len(self) + key
            return tstr(res, [self._taint[key]], self)
        else:
            assert False

    def rsplit(self, sep = None, maxsplit = -1):
        """
        >>> my_str = tstr('ab cdef ghij kl', taint=list(range(0,15)))
        >>> ab, cdef, ghij, kl = my_str.rsplit(sep=' ')
        >>> ab.x()
        0
        >>> cdef.x()
        3
        >>> kl.x()
        13
        >>> my_str = tstr('ab   cdef ghij    kl', taint=list(range(0,20)))
        >>> ab, cdef, ghij, kl = my_str.rsplit()
        >>> ab.x()
        0
        >>> cdef.x()
        5
        >>> kl.x()
        18
        """
        splitted = super().rsplit(sep, maxsplit)
        if not sep:
            r = self._split_space(splitted)
        else:

            result_list = []
            last_idx = 0
            first_idx = 0
            sep_len = len(sep)

            for s in splitted:
                last_idx = first_idx + len(s)
                item = self[first_idx:last_idx]
                result_list.append(item)
                # reset the first_idx
                first_idx = last_idx + sep_len
            r = result_list
        self.comparisons.append(Instr(inspect.currentframe().f_code.co_name, self, sep, r))
        return r

    def split(self, sep = None, maxsplit = -1):
        """
        >>> my_str = tstr('ab cdef ghij kl', taint=list(range(0,15)))
        >>> ab, cdef, ghij, kl = my_str.split(sep=' ')
        >>> ab.x()
        0
        >>> cdef.x()
        3
        >>> kl.x()
        13
        >>> my_str = tstr('ab   cdef ghij    kl', taint=list(range(0,20)))
        >>> ab, cdef, ghij, kl = my_str.split()
        >>> ab.x()
        0
        >>> cdef.x()
        5
        >>> kl.x()
        18
        """
        splitted = super().split(sep, maxsplit)
        if not sep:
            r = self._split_space(splitted)
        else:
            result_list = []
            last_idx = 0
            first_idx = 0
            sep_len = len(sep)

            for s in splitted:
                last_idx = first_idx + len(s)
                item = self[first_idx:last_idx]
                result_list.append(item)
                # reset the first_idx
                first_idx = last_idx + sep_len
            r = result_list
        self.comparisons.append(Instr(inspect.currentframe().f_code.co_name, self, sep, r))
        return r

    def _split_space(self, splitted):
        result_list = []
        last_idx = 0
        first_idx = 0
        sep_len = 0
        for s in splitted:
            last_idx = first_idx + len(s)
            item = self[first_idx:last_idx]
            result_list.append(item)
            v = str(self[last_idx:])
            sep_len = len(v) - len(v.lstrip(' '))
            # reset the first_idx
            first_idx = last_idx + sep_len
        return result_list

    def __add__(self, other):  #concatenation (+)
        """
        >>> my_str1 = tstr("abc")
        >>> my_str2 = tstr("def", taint=[4,5,6])
        >>> my_str3 = "ghi"
        >>> v = my_str1 + my_str2
        >>> v.x()
        0
        >>> v.x(2)
        2
        >>> v.x(3)
        4
        >>> w = my_str1 + my_str3
        >>> v.x()
        0
        """
        if type(other) is tstr:
            return tstr(str.__add__(self, other), (self._taint + other._taint), self)
        else:
            return tstr(str.__add__(self, other), (self._taint + [-1 for i in other]), self)

    def __radd__(self, other):  #concatenation (+) -- other is not tstr
        """
        >>> my_str1 = "abc"
        >>> my_str2 = tstr("def")
        >>> v = my_str1 + my_str2
        >>> v._x()
        -1
        >>> v._x(3)
        0
        """
        if type(other) is tstr:
            return tstr(str.__add__(other, self), (other._taint + self._taint), self)
        else:
            return tstr(str.__add__(other, self), ([-1 for i in other] + self._taint), self)

    def format(self, *args, **kwargs): #formatting (%) self is format string
        raise NotImplementedError
        return super().format(*args, **kwargs)

    def format_map(self, mapping): #formatting (%) self is format string
        raise NotImplementedError
        return super().format_map(mapping)


    def __mod__(self, other): #formatting (%) self is format string
        assert type(other) is str
        v = super().__mod__(other)
        prefix = os.path.commonprefix(str(other), str(self))
        rest = len(v) - len(other) - len(prefix)
        r = tstr(v, self._taint[0:len(prefix)] +  [-1] * len(other) + self._taint[len(prefix)+2:])
        return r

    def __rmod__(self, other): #formatting (%) other is format string
        assert type(other) is str
        v = super().__rmod__(other)
        prefix = os.path.commonprefix([str(other), str(self)])
        rest = len(v) - len(self) - len(prefix)
        r = tstr(v, [-1] * len(prefix) + self._taint +  [-1] * rest)
        return r

    def strip(self, cl=None):
        """
        >>> my_str1 = tstr("  abc  ")
        >>> my_str1[2]
        'a'
        >>> v = my_str1.strip()
        >>> v.x()
        2
        >>> len(v)
        3
        >>> v[2]
        'c'
        >>> v[2].x()
        4
        """
        r = self._lstrip(cl)._rstrip(cl)
        self.comparisons.append(Instr(inspect.currentframe().f_code.co_name, self, cl, r))
        return r

    def lstrip(self, cl=None):
        r = self._lstrip(cl)
        self.comparisons.append(Instr(inspect.currentframe().f_code.co_name, self, cl, r))
        return r

    def _lstrip(self, cl=None):
        """
        >>> my_str1 = tstr("  abc  ")
        >>> my_str1[2]
        'a'
        >>> v = my_str1.lstrip()
        >>> v.x()
        2
        >>> v[2]
        'c'
        >>> v[2].x()
        4
        """
        res = super().lstrip(cl)
        i = self.find(res)
        r = self[i:]
        return r

    def rstrip(self, cl=None):
        r = self._rstrip(cl)
        self.comparisons.append(Instr(inspect.currentframe().f_code.co_name, self, cl, r))
        return r

    def _rstrip(self, cl=None):
        """
        >>> my_str1 = tstr("  abc  ")
        >>> my_str1[2]
        'a'
        >>> v = my_str1.rstrip()
        >>> v.x()
        0
        >>> v[2]
        'a'
        >>> v[2].x()
        2
        """
        res = super().rstrip(cl)
        r = self[0:len(res)]
        return r

    def swapcase(self):
        """
        >>> my_str1 = tstr("abc")
        >>> v = my_str1.swapcase()
        >>> v[0].x()
        0
        >>> v[2].x()
        2
        """
        res = super().swapcase()
        return tstr(res, self._taint, self)

    def upper(self):
        """
        >>> my_str1 = tstr("abc")
        >>> v = my_str1.upper()
        >>> v[0].x()
        0
        >>> v[2].x()
        2
        """
        res = super().upper()
        return tstr(res, self._taint, self)

    def lower(self):
        """
        >>> my_str1 = tstr("abc")
        >>> v = my_str1.lower()
        >>> v[0].x()
        0
        >>> v[2].x()
        2
        """
        res = super().lower()
        return tstr(res, self._taint, self)

    def capitalize(self):
        """
        >>> my_str1 = tstr("abc")
        >>> v = my_str1.capitalize()
        >>> v[0].x()
        0
        >>> v[2].x()
        2
        """
        res = super().capitalize()
        return tstr(res, self._taint, self)

    def title(self):
        """
        >>> my_str1 = tstr("abc")
        >>> v = my_str1.title()
        >>> v[0].x()
        0
        >>> v[2].x()
        2
        """
        res = super().title()
        return tstr(res, self._taint, self)

    def __iter__(self):
        return tstr_iterator(self)

    def expandtabs(self, n=8):
        """
        >>> my_str = tstr("ab\\tcd")
        >>> len(my_str)
        5
        >>> my_str.split("\\t")
        ['ab', 'cd']
        >>> v = my_str.expandtabs(4)
        >>> v._taint
        [0, 1, 1, 1, 3, 4]
        """
        parts = self.split('\t')
        res = super().expandtabs(n)
        all_parts = []
        for i,p in enumerate(parts):
            all_parts.extend(p._taint)
            if i < len(parts)-1:
                l = len(all_parts) % n
                all_parts.extend([p._taint[-1]]*l)
        r = tstr(res, all_parts, self)
        self.comparisons.append(Instr(inspect.currentframe().f_code.co_name, self, n, r))
        return r

    def partition(self, sep):
        partA, sep, partB = super().partition(sep)
        r = (tstr(partA, self._taint[0:len(partA)], self), tstr(sep, self._taint[len(partA): len(partA) + len(sep)], self), tstr(partB, self._taint[len(partA) + len(sep):], self))
        self.comparisons.append(Instr(inspect.currentframe().f_code.co_name, self, sep, r))
        return r

    def rpartition(self, sep):
        partA, sep, partB = super().rpartition(sep)
        r = (tstr(partA, self._taint[0:len(partA)], self), tstr(sep, self._taint[len(partA): len(partA) + len(sep)], self), tstr(partB, self._taint[len(partA) + len(sep):], self))
        self.comparisons.append(Instr(inspect.currentframe().f_code.co_name, self, sep, r))
        return r

    def ljust(self, width, fillchar=' '):
        res = super().ljust(width, fillchar)
        initial = len(res) - len(self)
        if type(fillchar) is tstr:
            t = fillchar.x()
        else:
            t = -1
        return tstr(res, [t] * initial + self._taint, self)

    def rjust(self, width, fillchar=' '):
        res = super().rjust(width, fillchar)
        final = len(res) - len(self)
        if type(fillchar) is tstr:
            t = fillchar.x()
        else:
            t = -1
        return tstr(res, self._taint + [t] * final, self)

    def join(self, iterable):
        mystr = ''
        mytaint = []
        sep_taint = self._taint 
        lst = list(iterable)
        for i,s in enumerate(lst):
            staint = s._taint if type(i) is tstr else [-1] * len(s)
            mytaint.extend(staint)
            if i <= len(lst):
                mytaint.extend(sep_taint)
        res = super().join(iterable)
        return tstr(res, mytaint, self)


    def __format__(self, formatspec):
        res = super().__format__(formatspec)
        raise NotImplementedError
        return res

    def __eq__(self, other):
        r = self.__eq(other)
        self.comparisons.append(Instr(inspect.currentframe().f_code.co_name, self, other, r))
        return r

    def __eq(self, other):
        return super().__eq__(other)

    def __ne__(self, other):
        r = self.__ne(other)
        self.comparisons.append(Instr(inspect.currentframe().f_code.co_name, self, other, r))
        return r

    def __ne(self, other):
        return super().__ne__(other)

    def __contains__(self, other):
        r = self.__contains(other)
        self.comparisons.append(Instr(inspect.currentframe().f_code.co_name, self, other, r))
        return r

    def __contains(self, other):
        for i,s in substrings(self, len(other)):
            if s.__eq(other): return True
        return False

    def replace(self, a, b, n=None):
        """
        >>> my_str = tstr("aa cde aa")
        >>> res = my_str.replace('aa', 'bb')
        >>> res
        'bb cde bb'
        >>> res._taint
        [-1, -1, 2, 3, 4, 5, 6, -1, -1]
        """
        old_taint = self._taint
        b_taint = b._taint if type(b) is tstr else [-1] * len(b)
        mystr = str(self)
        i = 0
        while True:
            if n and i >= n: break
            idx = mystr.find(a)
            if idx == -1: break
            last = idx + len(a)
            mystr = mystr.replace(a, b, 1)
            partA, partB = old_taint[0:idx], old_taint[last:]
            old_taint = partA + b_taint + partB
            i += 1
        r = tstr(mystr, old_taint, self)
        self.comparisons.append(Instr(inspect.currentframe().f_code.co_name, self, (a, b, n), r))
        return r

    def count(self, sub, start=0, end=None):
        r = super().count(start, end)
        self.comparisons.append(Instr(inspect.currentframe().f_code.co_name, self, (sub, start, end), r))
        return r

    def startswith(self, prefix, start=0, end=None):
        r = super().startswith(prefix ,start, end)
        self.comparisons.append(Instr(inspect.currentframe().f_code.co_name, self, (prefix, start, end), r))
        return r

    def endswith(self, suffix, start=0, end=None):
        r = super().endswith(suffix ,start, end)
        self.comparisons.append(Instr(inspect.currentframe().f_code.co_name, self, (suffix, start, end), r))
        return r

    # returns int
    def find(self, sub, start=None, end=None):
        r = self.__find(sub, start, end)
        self.comparisons.append(Instr(inspect.currentframe().f_code.co_name, self, (sub, start, end), r))
        return r

    def __find(self, sub, start=None, end=None):
        if start == None: start = 0
        if end == None: end = len(self)
        substr = self[start:end]

        result = next((i for i,c in substrings(substr, len(sub)) if c.__eq(sub)), None)
        if not result: return -1
        return result + start

    # returns int
    def index(self, sub, start=None, end=None):
        r = super().index(sub, start, end)
        self.comparisons.append(Instr(inspect.currentframe().f_code.co_name, self, (sub, start, end), r))
        return r

    # returns int
    def rfind(self, sub, start=None, end=None):
        r = super().rfind(sub, start, end)
        self.comparisons.append(Instr(inspect.currentframe().f_code.co_name, self, (sub, start, end), r))
        return r

    # returns int
    def rindex(self, sub, start=None, end=None):
        r = super().rindex(sub, start, end)
        self.comparisons.append(Instr(inspect.currentframe().f_code.co_name, self, (sub, start, end), r))
        return r

    def isalnum(self):
        r = super().isalnum()
        self.comparisons.append(Instr(inspect.currentframe().f_code.co_name, self, None, r))
        return r
    def isalpha(self):
        r = super().isalpha()
        self.comparisons.append(Instr(inspect.currentframe().f_code.co_name, self, None, r))
        return r
    def isdigit(self):
        r = super().isdigit()
        self.comparisons.append(Instr(inspect.currentframe().f_code.co_name, self, None, r))
        return r
    def islower(self):
        r = super().islower()
        self.comparisons.append(Instr(inspect.currentframe().f_code.co_name, self, None, r))
        return r
    def isupper(self):
        r = super().isupper()
        self.comparisons.append(Instr(inspect.currentframe().f_code.co_name, self, None, r))
        return r
    def isspace(self):
        r = super().isspace()
        self.comparisons.append(Instr(inspect.currentframe().f_code.co_name, self, None, r))
        return r
    def istitle(self):
        r = super().istitle()
        self.comparisons.append(Instr(inspect.currentframe().f_code.co_name, self, None, r))
        return r
    def isdecimal(self):
        r = super().isdecimal()
        self.comparisons.append(Instr(inspect.currentframe().f_code.co_name, self, None, r))
        return r
    def isidentifier(self):
        r = super().isidentifier()
        self.comparisons.append(Instr(inspect.currentframe().f_code.co_name, self, None, r))
        return r
    def isnumeric(self):
        r = super().isnumeric()
        self.comparisons.append(Instr(inspect.currentframe().f_code.co_name, self, None, r))
        return r
    def isprintable(self):
        r = super().isprintable()
        self.comparisons.append(Instr(inspect.currentframe().f_code.co_name, self, None, r))
        return r

def make_str_wrapper(fun):
    def proxy(*args, **kwargs):
        res = fun(*args, **kwargs)
        if res.__class__ == str:
            # brk()
            if fun.__name__ == '__mul__': #repeating (*)
                return tstr(res, idx=0)
            elif fun.__name__ == '__rmul__': #repeating (*)
                return tstr(res, idx=0)
            elif fun.__name__ == 'splitlines':
                return tstr(res, idx=0)
            elif fun.__name__ == 'center':
                return tstr(res, idx=0)
            elif fun.__name__ == 'zfill':
                return tstr(res, idx=0)
            elif fun.__name__ == 'decode':
                return tstr(res, idx=0)
            elif fun.__name__ == 'encode':
                return tstr(res, idx=0)
            else:
                raise TaintException('%s Not implemented in TSTR' % fun.__name__)
        return res
    return proxy

for name, fn in inspect.getmembers(str, callable):
    if name not in ['__class__', '__new__', '__str__', '__init__', '__repr__',
            '__getattribute__', '__getitem__', '__rmod__', '__mod__', '__add__',
            '__radd__', 'strip', 'lstrip', 'rstrip', '__iter__', 'expandtabs',
            '__format__', 'split', 'rsplit', 'format', 'join',
            '__eq__', '__ne__', '__contains__', 'count',
            'startswith', 'endswith', 'find', 'index', 'rfind' 'rindex',
            'capitalize', 'replace', 'title', 'lower', 'upper', 'swapcase',
            'partition', 'rpartition', 'ljust', 'rjust',
            'isalnum', 'isalpha', 'isdigit', 'islower', 'isupper', 'isspace',
            'istitle', 'isdecimal', 'isidentifier', 'isnumeric', 'isprintable'
            ]:
        setattr(tstr, name, make_str_wrapper(fn))

def get_t(v):
    if type(v) is tstr: return v
    if hasattr(v, '__dict__') and '_tstr' in v.__dict__: return get_t(v._tstr)
    return None

if __name__ in ['__main__']:
    my_str = tstr('ab cd')
    print("Taint information: for %s" % my_str)
    print(my_str._taint)
    values = my_str.split()
    print("After split:")
    print(values[1]._taint)
    new = 'hello' + values[1]
    print("Values after appending hello to front:")
    print(new._taint)
    print('Comparisons:')
    new[5] == 'A'
    my_str[0] == 'h'
    my_str[0] == 'a'
    for i in my_str.comparisons:
        print(i)
    for i in my_str.comparisons:
        print(i.op_A._taint, i)
