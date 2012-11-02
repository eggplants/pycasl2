# -*- coding: utf-8 -*-
'''
PyCOMET2, COMET II emulator implemented in Python.
Copyright (c) 2012, Yasuaki Mitani
Copyright (c) 2009, Masahiko Nakamoto.

Based on a simple implementation of COMET II emulator.
Copyright (c) 2001-2008, Osamu Mizuno.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
'''

import sys
import string
import array
import logging
from functools import wraps
from optparse import OptionParser
from types import MethodType

from utils import l2a, a2l, get_bit, i2bin
from argtype import noarg, r, r1r2, adrx, radrx, strlen


# スタックポインタの初期値
initSP = 0xff00


def get_effective_address(m, adr, x):
    ''' 実効アドレスを返す '''
    return adr if x == 0 else a2l(adr + m.GR[x])


def get_value_at_effective_address(m, adr, x):
    ''' 実効アドレス番地の値を返す '''
    return m.memory[adr] if x == 0 else m.memory[a2l(adr + m.GR[x])]


def flags(result, logical=False, ZF=None, SF=None, OF=None):
    '''
    計算結果に応じたフラグを返す
    論理演算の場合は第二引数をTrueにする
    '''
    if ZF is None: ZF = (result == 0)
    if SF is None: SF = (get_bit(result, 15) == 0)
    if OF is None:
        if logical is True:
            OF = (result < 0 or 0xffff < result)
        else:
            OF = (result < -32768 or 0x7fff < result)
    return map(int, (ZF, SF, OF))


class Jump(Exception):
    def __init__(self, addr, result=None):
        self.addr = addr
        self.result = result


def instruction(opcode, opname, argtype):
    def _(ir):
        @wraps(ir)
        def __(machine):
            try:
                result = ir(machine, *argtype(machine))
            except Jump as jump:
                machine.PR = jump.addr
                result = jump.result
            else:
                machine.PR += argtype.size
            if result is not None:
                machine.ZF = machine.ZF if result[0] is None else result[0]
                machine.SF = machine.SF if result[1] is None else result[1]
                machine.OF = machine.OF if result[2] is None else result[2]
        __.opcode = opcode
        __.opname = opname
        __.argtype = argtype
        return __
    return _


@instruction(0x00, 'NOP', noarg)
def nop(machine):
    pass


@instruction(0x10, 'LD', radrx)
def ld2(machine, r, adr, x):
    machine.GR[r] = get_value_at_effective_address(machine, adr, x)
    return flags(machine.GR[r], OF=0)


@instruction(0x11, 'ST', radrx)
def st(machine, r, adr, x):
    machine.memory[get_effective_address(machine, adr, x)] = machine.GR[r]


@instruction(0x12, 'LAD', radrx)
def lad(machine, r, adr, x):
    machine.GR[r] = get_effective_address(machine, adr, x)


@instruction(0x14, 'LD', r1r2)
def ld1(machine, r1, r2):
    machine.GR[r1] = machine.GR[r2]
    return flags(machine.GR[r1], OF=0)


@instruction(0x20, 'ADDA', radrx)
def adda2(machine, r, adr, x):
    v = get_value_at_effective_address(machine, adr, x)
    result = l2a(machine.GR[r]) + l2a(v)
    machine.GR[r] = a2l(result)
    return flags(result)


@instruction(0x21, 'SUBA', radrx)
def suba2(machine, r, adr, x):
    v = get_value_at_effective_address(machine, adr, x)
    result = l2a(machine.GR[r]) - l2a(v)
    machine.GR[r] = a2l(result)
    return flags(result)


@instruction(0x22, 'ADDL', radrx)
def addl2(machine, r, adr, x):
    v = get_value_at_effective_address(machine, adr, x)
    result = machine.GR[r] + v
    machine.GR[r] = result & 0xffff
    return flags(result, logical=True)


@instruction(0x23, 'SUBL', radrx)
def subl2(machine, r, adr, x):
    v = get_value_at_effective_address(machine, adr, x)
    result = machine.GR[r] - v
    machine.GR[r] = result & 0xffff
    return flags(result, logical=True)


@instruction(0x24, 'ADDA', r1r2)
def adda1(machine, r1, r2):
    result = l2a(machine.GR[r1]) + l2a(machine.GR[r2])
    machine.GR[r1] = a2l(result)
    return flags(result)


@instruction(0x25, 'SUBA', r1r2)
def suba1(machine, r1, r2):
    result = l2a(machine.GR[r1]) - l2a(machine.GR[r2])
    machine.GR[r1] = a2l(result)
    return flags(result)


@instruction(0x26, 'ADDL', r1r2)
def addl1(machine, r1, r2):
    result = machine.GR[r1] + machine.GR[r2]
    machine.GR[r1] = result & 0xffff
    return flags(result, logical=True)


@instruction(0x27, 'SUBL', r1r2)
def subl1(machine, r1, r2):
    result = machine.GR[r1] - machine.GR[r2]
    machine.GR[r1] = result & 0xffff
    return flags(result, logical=True)


@instruction(0x30, 'AND', radrx)
def and2(machine, r, adr, x):
    v = get_value_at_effective_address(machine, adr, x)
    machine.GR[r] = machine.GR[r] & v
    return flags(machine.GR[r], OF=0)


@instruction(0x31, 'OR', radrx)
def or2(machine, r, adr, x):
    v = get_value_at_effective_address(machine, adr, x)
    machine.GR[r] = machine.GR[r] | v
    return flags(machine.GR[r], OF=0)


@instruction(0x32, 'XOR', radrx)
def xor2(machine, r, adr, x):
    v = get_value_at_effective_address(machine, adr, x)
    machine.GR[r] = machine.GR[r] ^ v
    return flags(machine.GR[r], OF=0)


@instruction(0x34, 'AND', r1r2)
def and1(machine, r1, r2):
    machine.GR[r1] = machine.GR[r1] & machine.GR[r2]
    return flags(machine.GR[r1], OF=0)


@instruction(0x35, 'OR', r1r2)
def or1(machine, r1, r2):
    machine.GR[r1] = machine.GR[r1] | machine.GR[r2]
    return flags(machine.GR[r1], OF=0)


@instruction(0x36, 'XOR', r1r2)
def xor1(machine, r1, r2):
    machine.GR[r1] = machine.GR[r1] ^ machine.GR[r2]
    return flags(machine.GR[r1], OF=0)


@instruction(0x40, 'CPA', radrx)
def cpa2(machine, r, adr, x):
    v = get_value_at_effective_address(machine, adr, x)
    diff = l2a(machine.GR[r]) - l2a(v)
    return int(diff == 0), int(diff < 0), 0


@instruction(0x41, 'CPL', radrx)
def cpl2(machine, r, adr, x):
    v = get_value_at_effective_address(machine, adr, x)
    diff = machine.GR[r] - v
    return int(diff == 0), int(diff < 0), 0


@instruction(0x44, 'CPA', r1r2)
def cpa1(machine, r1, r2):
    diff = l2a(machine.GR[r1]) - l2a(machine.GR[r2])
    return int(diff == 0), int(diff < 0), 0


@instruction(0x45, 'CPL', r1r2)
def cpl1(machine, r1, r2):
    diff = machine.GR[r1] - machine.GR[r2]
    return int(diff == 0), int(diff < 0), 0


@instruction(0x50, 'SLA', radrx)
def sla(machine, r, adr, x):
    v = get_effective_address(machine, adr, x)
    p = l2a(machine.GR[r])
    prev_p = p
    sign = get_bit(machine.GR[r], 15)
    ans = (p << v) & 0x7fff
    if sign == 0:
        ans = ans & 0x7fff
    else:
        ans = ans | 0x8000
    machine.GR[r] = ans
    if 0 < v:
        return flags(machine.GR[r], OF=get_bit(prev_p, 15 - v))
    else:
        return flags(machine.GR[r])


@instruction(0x51, 'SRA', radrx)
def sra(machine, r, adr, x):
    v = get_effective_address(machine, adr, x)
    p = l2a(machine.GR[r])
    prev_p = p
    sign = get_bit(machine.GR[r], 15)
    ans = (p >> v) & 0x7fff
    if sign == 0:
        ans = ans & 0x7fff
    else:
        ans = ans | 0x8000
    machine.GR[r] = ans
    if 0 < v:
        return flags(machine.GR[r], OF=get_bit(prev_p, v - 1))
    else:
        return flags(machine.GR[r])


@instruction(0x52, 'SLL', radrx)
def sll(machine, r, adr, x):
    v = get_effective_address(machine, adr, x)
    p = machine.GR[r]
    prev_p = p
    ans = p << v
    ans = ans & 0xffff
    machine.GR[r] = ans
    if 0 < v:
        return flags(machine.GR[r], logical=True,
                     OF=get_bit(prev_p, 15 - (v - 1)))
    else:
        return flags(machine.GR[r], logical=True)


@instruction(0x53, 'SRL', radrx)
def srl(machine, r, adr, x):
    v = get_effective_address(machine, adr, x)
    p = machine.GR[r]
    prev_p = p
    ans = machine.GR[r] >> v
    ans = ans & 0xffff
    machine.GR[r] = ans
    if 0 < v:
        return flags(machine.GR[r], OF=get_bit(prev_p, (v - 1)))
    else:
        return flags(machine.GR[r])


@instruction(0x61, 'JMI', adrx)
def jmi(machine, adr, x):
    if machine.SF == 1:
        raise Jump(get_effective_address(machine, adr, x))


@instruction(0x62, 'JNZ', adrx)
def jnz(machine, adr, x):
    if machine.ZF == 0:
        raise Jump(get_effective_address(machine, adr, x))


@instruction(0x63, 'JZE', adrx)
def jze(machine, adr, x):
    if machine.ZF == 1:
        raise Jump(get_effective_address(machine, adr, x))


@instruction(0x64, 'JUMP', adrx)
def jump(machine, adr, x):
    raise Jump(get_effective_address(machine, adr, x))


@instruction(0x65, 'JPL', adrx)
def jpl(machine, adr, x):
    if machine.ZF == 0 and machine.SF == 0:
        raise Jump(get_effective_address(machine, adr, x))


@instruction(0x66, 'JOV', adrx)
def jov(machine, adr, x):
    if machine.OF == 0:
        raise Jump(get_effective_address(machine, adr, x))


@instruction(0x70, 'PUSH', adrx)
def push(machine, adr, x):
    machine.SP -= 1
    machine.memory[machine.SP] = get_effective_address(machine, adr, x)


@instruction(0x71, 'POP', r)
def pop(machine, r):
    machine.GR[r] = machine.memory[machine.SP]
    machine.SP += 1


@instruction(0x80, 'CALL', adrx)
def call(machine, adr, x):
    machine.SP -= 1
    machine.memory[machine.SP] = machine.PR
    machine.call_level += 1
    raise Jump(get_effective_address(machine, adr, x))


@instruction(0x81, 'RET', noarg)
def ret(machine):
    if machine.call_level == 0:
        machine.step_count += 1
        machine.exit()
    adr = machine.memory[machine.SP]
    machine.SP += 1
    machine.call_level -= 1
    raise Jump(adr + 2)


@instruction(0xf0, 'SVC', adrx)
def svc(machine, adr, x):
    raise Jump(machine.PR)


@instruction(0x90, 'IN', strlen)
def in_(machine, s, l):
    sys.stderr.write('-> ')
    sys.stderr.flush()
    line = sys.stdin.readline()
    line = line[:-1]
    if 256 < len(line):
        line = line[0:256]
    machine.memory[l] = len(line)
    for i, ch in enumerate(line):
        machine.memory[s + i] = ord(ch)


@instruction(0x91, 'OUT', strlen)
def out(machine, s, l):
    length = machine.memory[l]
    ch = ''
    for i in range(s, s + length):
        ch += chr(machine.memory[i])
    print ch


@instruction(0xa0, 'RPUSH', noarg)
def rpush(machine):
    for i in range(1, 9):
        machine.SP -= 1
        machine.memory[machine.SP] = machine.GR[i]


@instruction(0xa1, 'RPOP', noarg)
def rpop(machine):
    for i in range(1, 9)[::-1]:
        machine.GR[i] = machine.memory[machine.SP]
        machine.SP += 1


class Disassembler(object):

    def __init__(self, machine):
        self.m = machine

    def disassemble(self, addr, num=16):
        for i in xrange(num):
            try:
                inst = self.m.getInstruction(addr)
                yield addr, self.dis_inst(addr)
                if 1 < inst.argtype.size:
                    yield (addr + 1, '')
                if 2 < inst.argtype.size:
                    yield (addr + 2, '')
                addr += inst.argtype.size
            except InvalidOperation:
                yield (addr, self.dis_inst(addr))
                addr += 1

    def dis_inst(self, addr):
        try:
            inst = self.m.getInstruction(addr)
            args = inst.argtype(self.m, addr)
            return getattr(self, 'dis_' + inst.argtype.__name__)(inst, *args)
        except:
            return self.dis_dc(addr)

    def dis_noarg(self, inst):
        return '%--8s' % inst.opname

    def dis_r(self, inst, r):
        return '%-8sGR%1d' % (inst.opname, r)

    def dis_r1r2(self, inst, r1, r2):
        return '%-8sGR%1d, GR%1d' % (inst.opname, r1, r2)

    def dis_adrx(self, inst, adr, x):
        if x == 0: return '%-8s#%04x' % (inst.opname, adr)
        else: return '%-8s#%04x, GR%1d' % (inst.opname, adr, x)

    def dis_radrx(self, inst, r, adr, x):
        if x == 0: return '%-8sGR%1d, #%04x' % (inst.opname, r, adr)
        else: return '%-8sGR%1d, #%04x, GR%1d' % (inst.opname, r, adr, x)

    def dis_strlen(self, inst, s, l):
        return '%-8s#%04x, #%04x' % (inst.opname, s, l)

    def dis_dc(self, addr):
        return '%-8s#%04x' % ('DC', self.m.memory[addr])


class StatusMonitor:
    def __init__(self, machine):
        self.m = machine
        self.vars = [self.watcher('%04d: ', 'step_count')]
        self.decimalFlag = False

    def __str__(self):
        return ' '.join([v() for v in self.vars])

    def watcher(self, fmt, attr, index=None):
        def _():
            if index is None:
                return fmt % getattr(self.m, attr)
            else:
                return fmt % getattr(self.m, attr)[index]
        _.__name__ = 'watcher_' + attr
        if index is not None: _.__name__ += '[' + str(index) + ']'
        return _

    def append(self, s):
        try:
            if s == 'PR':
                self.vars.append(self.watcher("PR=#%04x", 'PR'))
            elif s == 'OF':
                self.vars.append(self.watcher("OF=#%01d", 'OF'))
            elif s == 'SF':
                self.vars.append(self.watcher("SF=#%01d", 'SF'))
            elif s == 'ZF':
                self.vars.append(self.watcher("ZF=#%01d", 'ZF'))
            elif s[0:2] == 'GR':
                reg = int(s[2])
                if reg < 0 or 8 < reg:
                    raise
                if self.decimalFlag:
                    self.vars.append(
                        self.watcher(
                            "GR" + str(reg) + "=#%d", 'GR', reg))
                else:
                    self.vars.append(
                        self.watcher(
                            "GR" + str(reg) + "=#%04x", 'GR', reg))
            else:
                adr = self.m.cast_int(s)
                if adr < 0 or 0xffff < adr:
                    raise
                if self.decimalFlag:
                    self.vars.append(
                        self.watcher(
                            "#%04x" % adr + "=%d", 'memory', adr))
                else:
                    self.vars.append(
                        self.watcher(
                            "#%04x" % adr + "=%04x", 'memory', adr))
        except:
            print >> sys.stderr, ("Warning: Invalid monitor "
                                  "target is found."
                                  " %s is ignored." % s)


class InvalidOperation(BaseException):
    def __init__(self, address):
        self.address = address

    def __str__(self):
        return 'Invalid operation is found at #%04x.' % self.address


class PyComet2(object):

    def __init__(self):
        self.inst_list = [nop, ld2, st, lad, ld1,
                          adda2, suba2, addl2, subl2,
                          adda1, suba1, addl1, subl1,
                          and2, or2, xor2, and1, or1, xor1,
                          cpa2, cpl2, cpa1, cpl1,
                          sla, sra, sll, srl,
                          jmi, jnz, jze, jump, jpl, jov,
                          push, pop, call, ret, svc,
                          in_, out, rpush, rpop]

        self.inst_table = {}
        for ir in self.inst_list:
            self.inst_table[ir.opcode] = MethodType(ir, self, PyComet2)

        self.isAutoDump = False
        self.break_points = []
        self.call_level = 0
        self.step_count = 0
        self.monitor = StatusMonitor(self)
        self.dis = Disassembler(self)

        self.initialize()

    def initialize(self):
        # 主記憶 1 word = 2 byte unsigned short
        self.memory = array.array('H', [0] * 65536)
        # レジスタ unsigned short
        self.GR = array.array('H', [0] * 9)
        # スタックポインタ SP = GR[8]
        self.SP = initSP
        # プログラムレジスタ
        self.PR = 0
        # Overflow Flag
        self.OF = 0
        # Sign Flag
        self.SF = 0
        # Zero Flag
        self.ZF = 1
        logging.info('Initialize memory and registers.')

    @property
    def FR(self):
        return self.OF << 2 | self.SF << 1 | self.ZF

    def _set_SP(self, value):
        self.GR[8] = value

    def _get_SP(self):
        return self.GR[8]

    SP = property(_get_SP, _set_SP)

    def print_status(self):
        try:
            code = self.dis.dis_inst(self.PR)
        except InvalidOperation:
            code = '%04x' % self.memory[self.PR]
        sys.stderr.write('PR  #%04x [ %-30s ]  STEP %d\n'
                         % (self.PR, code, self.step_count) )
        sys.stderr.write('SP  #%04x(%7d) FR(OF, SF, ZF)  %03s  (%7d)\n'
                         % (self.SP, self.SP,
                            i2bin(self.FR, 3), self.FR))
        sys.stderr.write('GR0 #%04x(%7d) GR1 #%04x(%7d) '
                         ' GR2 #%04x(%7d) GR3: #%04x(%7d)\n'
                         % (self.GR[0], l2a(self.GR[0]),
                            self.GR[1], l2a(self.GR[1]),
                            self.GR[2], l2a(self.GR[2]),
                            self.GR[3], l2a(self.GR[3])))
        sys.stderr.write('GR4 #%04x(%7d) GR5 #%04x(%7d) '
                         'GR6 #%04x(%7d) GR7: #%04x(%7d)\n'
                         % (self.GR[4], l2a(self.GR[4]),
                            self.GR[5], l2a(self.GR[5]),
                            self.GR[6], l2a(self.GR[6]),
                            self.GR[7], l2a(self.GR[7])))

    def exit(self):
        if self.isCountStep:
            print 'Step count:', self.step_count

        if self.isAutoDump:
            print >> sys.stderr, "dump last status to last_state.txt"
            self.dump_to_file('last_state.txt')

        sys.exit()

    def set_auto_dump(self, flg):
        self.isAutoDump = flg

    def set_count_step(self, flg):
        self.isCountStep = flg

    def setLoggingLevel(self, lv):
        logging.basicConfig(level=lv)

    # PRが指す命令を返す
    def getInstruction(self, adr=None):
        try:
            if adr is None: adr = self.PR
            return self.inst_table[(self.memory[adr] & 0xff00) >> 8]
        except KeyError:
            raise InvalidOperation(adr)

    # 命令を1つ実行
    def step(self):
        self.getInstruction()()
        self.step_count += 1

    def watch(self, variables, decimalFlag=False):
        self.monitor.decimalFlag = decimalFlag
        for v in variables.split(","):
            self.monitor.append(v)

        while (True):
            if self.PR in self.break_points:
                break
            else:
                try:
                    print self.monitor
                    sys.stdout.flush()
                    self.step()
                except InvalidOperation, e:
                    print >> sys.stderr, e
                    self.dump(e.address)
                    break

    def run(self):
        while (True):
            if self.PR in self.break_points:
                break
            else:
                try:
                    self.step()
                except InvalidOperation, e:
                    print >> sys.stderr, e
                    self.dump(e.address)
                    break

    # オブジェクトコードを主記憶に読み込む
    def load(self, filename, quiet=False):
        if not quiet:
            print >> sys.stderr, 'load %s ...' % filename,
        self.initialize()
        fp = file(filename, 'rb')
        try:
            tmp = array.array('H')
            tmp.fromfile(fp, 65536)
        except EOFError:
            pass
        fp.close()
        tmp.byteswap()
        self.PR = tmp[2]
        tmp = tmp[8:]
        for i in range(0, len(tmp)):
            self.memory[i] = tmp[i]
        if not quiet:
            print >> sys.stderr, 'done.'

    def dump_memory(self, start_addr=0x0000, lines=0xffff / 8):
        printable = (string.letters
                     + string.digits
                     + string.punctuation + ' ')

        def to_char(array):
            def chr2(i):
                c = 0x00ff & i
                return chr(c) if chr(c) in printable else '.'
            return ''.join([chr2(i) for i in array])

        def to_hex(array):
            return ' '.join(['%04x' % i for i in array])

        st = []
        for i in range(0, lines):
            addr = i * 8 + start_addr
            if 0xffff < addr: return st
            st.append('%04x: %-39s %-8s\n'
                      % (addr,
                         to_hex(self.memory[addr:addr + 8]),
                         to_char(self.memory[addr:addr + 8])))
        return ''.join(st)

    # 8 * 16 wordsダンプする
    def dump(self, start_addr=0x0000):
        print self.dump_memory(start_addr, 16),

    def dump_stack(self):
        print self.dump_memory(self.SP, 16),

    def dump_to_file(self, filename, lines=0xffff / 8):
        fp = file(filename, 'w')
        fp.write('Step count: %d\n' % self.step_count)
        fp.write('PR: #%04x\n' % self.PR)
        fp.write('SP: #%04x\n' % self.SP)
        fp.write('OF: %1d\n' % self.OF)
        fp.write('SF: %1d\n' % self.SF)
        fp.write('ZF: %1d\n' % self.ZF)
        for i in range(0, 8):
            fp.write('GR%d: #%04x\n' % (i, self.GR[i]))
        fp.write('Memory:\n')
        fp.write(self.dump_memory(0, lines))
        fp.close()

    def disassemble(self, start_addr=0x0000):
        addr = start_addr
        for addr, dis in self.dis.disassemble(addr, 16):
            print >> sys.stderr, ('#%04x\t#%04x\t%s'
                                  % (addr, self.memory[addr], dis))

    def cast_int(self, addr):
        if addr[0] == '#':
            return int(addr[1:], 16)
        else:
            return int(addr)

    def set_break_point(self, addr):
        if addr in self.break_points:
            print >> sys.stderr, '#%04x is already set.' % addr
        else:
            self.break_points.append(addr)

    def print_break_points(self):
        if len(self.break_points) == 0:
            print >> sys.stderr, 'No break points.'
        else:
            for i, addr in enumerate(self.break_points):
                print >> sys.stderr, '%d: #%04x' % (i, addr)

    def delete_break_points(self, n):
        if 0 <= n < len(self.break_points):
            print >> sys.stderr, '#%04x is removed.' % (self.break_points[n])
        else:
            print >> sys.stderr, 'Invalid number is specified.'

    def write_memory(self, addr, value):
        self.memory[addr] = value

    def jump(self, addr):
        self.PR = addr
        self.print_status()

    def wait_for_command(self):
            line = raw_input('pycomet2> ')
            args = line.split()
            if line[0] == 'q':
                break
            elif line[0] == 'b':
                if 2 <= len(args):
                    self.set_break_point(self.cast_int(args[1]))
            elif line[0:2] == 'df':
                self.dump_to_file(args[1])
                print >> sys.stderr, 'dump to', filename
            elif line[0:2] == 'di':
                if len(args) == 1:
                    self.disassemble()
                else:
                    self.disassemble(self.cast_int(args[1]))
            elif line[0:2] == 'du':
                if len(args) == 1:
                    self.dump()
                else:
                    self.dump(self.cast_int(args[1]))
            elif line[0] == 'd':
                if 2 <= len(args):
                    self.delete_break_points(int(args[1]))
            elif line[0] == 'h':
                self.print_help()
            elif line[0] == 'i':
                self.print_break_points()
            elif line[0] == 'j':
                self.jump(self.cast_int(args[1]))
            elif line[0] == 'm':
                self.write_memory(self.cast_int(args[1]),
                                  self.cast_int(args[2]))
            elif line[0] == 'p':
                self.print_status()
            elif line[0] == 'r':
                self.run()
            elif line[0:2] == 'st':
                self.dump_stack()
            elif line[0] == 's':
                try:
                    self.step()
                except InvalidOperation as e:
                    print >> sys.stderr, e
                    self.dump(e.address)

                self.print_status()
            else:
                print >> sys.stderr, 'Invalid command.'

    def print_help(self):
        print >> sys.stderr, ('b ADDR        '
                              'Set a breakpoint at specified address.')
        print >> sys.stderr, 'd NUM         Delete breakpoints.'
        print >> sys.stderr, ('di ADDR       '
                              'Disassemble 32 words from specified address.')
        print >> sys.stderr, 'du ADDR       Dump 128 words of memory.'
        print >> sys.stderr, 'h             Print help.'
        print >> sys.stderr, 'i             Print breakpoints.'
        print >> sys.stderr, 'j ADDR        Set PR to ADDR.'
        print >> sys.stderr, 'm ADDR VAL    Change the memory at ADDR to VAL.'
        print >> sys.stderr, 'p             Print register status.'
        print >> sys.stderr, 'q             Quit.'
        print >> sys.stderr, 'r             Strat execution of program.'
        print >> sys.stderr, 's             Step execution.'
        print >> sys.stderr, 'st            Dump 128 words of stack image.'


def main():
    usage = 'usage: %prog [options] input.com'
    parser = OptionParser(usage)
    parser.add_option('-c', '--count-step', action='store_true',
                      dest='count_step', default=False, help='count step.')
    parser.add_option('-d', '--dump', action='store_true',
                      dest='dump', default=False,
                      help='dump last status to last_state.txt.')
    parser.add_option('-r', '--run', action='store_true',
                      dest='run', default=False, help='run')
    parser.add_option('-w', '--watch', type='string',
                      dest='watchVariables', default='',
                      help='run in watching mode. (ex. -w PR,GR0,GR8,#001f)')
    parser.add_option('-D', '--Decimal', action='store_true',
                      dest='decimalFlag', default=False,
                      help='watch GR[0-8] and specified address in decimal '
                           'notation. (Effective in watcing mode only)')
    parser.add_option('-v', '--version', action='store_true',
                      dest='version', default=False,
                      help='display version information.')
    options, args = parser.parse_args()

    if options.version:
        print 'PyCOMET2 version 1.2'
        print '$Revision: a31dbeeb4d1c $'
        print 'Copyright (c) 2009, Masahiko Nakamoto.'
        print 'All rights reserved.'
        sys.exit()

    if len(args) < 1:
        parser.print_help()
        sys.exit()

    comet2 = PyComet2()
    comet2.set_auto_dump(options.dump)
    comet2.set_count_step(options.count_step)
    if len(options.watchVariables) != 0:
        comet2.load(args[0], True)
        comet2.watch(options.watchVariables, options.decimalFlag)
    elif options.run:
        comet2.load(args[0], True)
        comet2.run()
    else:
        comet2.load(args[0])
        comet2.print_status()
        comet2.wait_for_command()

if __name__ == '__main__':
    import os
    import readline
    histfile = os.path.join(os.path.abspath(os.path.dirname(__file__)),
                            '.comet2_history')
    try:
        readline.read_history_file(histfile)
    except IOError:
        pass
    import atexit
    atexit.register(readline.write_history_file, histfile)
    del os, histfile
    main()
