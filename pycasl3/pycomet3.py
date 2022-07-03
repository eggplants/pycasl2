import array
import atexit
import logging
import os
import readline
import string
import sys
from optparse import OptionParser
from types import MethodType

from .instructions import (
    adda1,
    adda2,
    addl1,
    addl2,
    and1,
    and2,
    call,
    cpa1,
    cpa2,
    cpl1,
    cpl2,
    in_,
    jmi,
    jnz,
    jov,
    jpl,
    jump,
    jze,
    lad,
    ld1,
    ld2,
    nop,
    or1,
    or2,
    out,
    pop,
    push,
    ret,
    rpop,
    rpush,
    sla,
    sll,
    sra,
    srl,
    st,
    suba1,
    suba2,
    subl1,
    subl2,
    svc,
    xor1,
    xor2,
)
from .utils import i2bin, l2a


class Disassembler:
    def __init__(self, machine):
        self.m = machine

    def disassemble(self, addr, num=16):
        for _ in range(num):
            try:
                inst = self.m.get_instruction(addr)
                yield addr, self.dis_inst(addr)
                if 1 < inst.argtype.size:
                    yield (addr + 1, "")
                if 2 < inst.argtype.size:
                    yield (addr + 2, "")
                addr += inst.argtype.size
            except InvalidOperation:
                yield (addr, self.dis_inst(addr))
                addr += 1

    def dis_inst(self, addr):
        try:
            inst = self.m.get_instruction(addr)
            args = inst.argtype(self.m, addr)
            return getattr(self, "dis_" + inst.argtype.__name__)(inst, *args)
        except Exception:
            return self.dis_dc(addr)

    def dis_noarg(self, inst):
        return "%--8s" % inst.opname

    def dis_r(self, inst, r):
        return "%-8sGR%1d" % (inst.opname, r)

    def dis_r1r2(self, inst, r1, r2):
        return "%-8sGR%1d, GR%1d" % (inst.opname, r1, r2)

    def dis_adrx(self, inst, adr, x):
        if x == 0:
            return "%-8s#%04x" % (inst.opname, adr)
        else:
            return "%-8s#%04x, GR%1d" % (inst.opname, adr, x)

    def dis_radrx(self, inst, r, adr, x):
        if x == 0:
            return "%-8sGR%1d, #%04x" % (inst.opname, r, adr)
        else:
            return "%-8sGR%1d, #%04x, GR%1d" % (inst.opname, r, adr, x)

    def dis_strlen(self, inst, s, l):
        return "%-8s#%04x, #%04x" % (inst.opname, s, l)

    def dis_dc(self, addr):
        return "%-8s#%04x" % ("DC", self.m.memory[addr])


class StatusMonitor:
    def __init__(self, machine):
        self.m = machine
        self.vars = []
        self.watch("%04d: ", "step_count")
        self.decimalFlag = False

    def __str__(self):
        return " ".join([v() for v in self.vars])

    def watch(self, fmt, attr, index=None):
        def _():
            if index is None:
                return fmt % getattr(self.m, attr)
            else:
                return fmt % getattr(self.m, attr)[index]

        _.__name__ = "watcher_" + attr
        if index is not None:
            _.__name__ += "[" + str(index) + "]"
        self.vars.append(_)

    def append(self, s):
        try:
            if s == "PR":
                self.watch("PR=#%04x", "PR")
            elif s == "OF":
                self.watch("OF=#%01d", "OF")
            elif s == "SF":
                self.watch("SF=#%01d", "SF")
            elif s == "ZF":
                self.watch("ZF=#%01d", "ZF")
            elif s[0:2] == "GR":
                reg = int(s[2])
                if reg < 0 or 8 < reg:
                    raise
                if self.decimalFlag:
                    self.watch("GR" + str(reg) + "=#%d", "GR", reg)
                else:
                    self.watch("GR" + str(reg) + "=#%04x", "GR", reg)
            else:
                adr = self.m.cast_int(s)
                if adr < 0 or 0xFFFF < adr:
                    raise
                if self.decimalFlag:
                    self.watch("#%04x" % adr + "=%d", "memory", adr)
                else:
                    self.watch("#%04x" % adr + "=%04x", "memory", adr)
        except ValueError:
            print(
                "Warning: Invalid monitor " "target is found." " %s is ignored." % s,
                file=sys.stderr,
            )


class InvalidOperation(BaseException):
    def __init__(self, address):
        self.address = address

    def __str__(self):
        return "Invalid operation is found at #%04x." % self.address


class MachineExit(BaseException):
    def __init__(self, machine):
        self.machine = machine


class PyComet2:

    # スタックポインタの初期値
    initSP = 0xFF00

    def __init__(self):
        self.inst_list = [
            nop,
            ld2,
            st,
            lad,
            ld1,
            adda2,
            suba2,
            addl2,
            subl2,
            adda1,
            suba1,
            addl1,
            subl1,
            and2,
            or2,
            xor2,
            and1,
            or1,
            xor1,
            cpa2,
            cpl2,
            cpa1,
            cpl1,
            sla,
            sra,
            sll,
            srl,
            jmi,
            jnz,
            jze,
            jump,
            jpl,
            jov,
            push,
            pop,
            call,
            ret,
            svc,
            in_,
            out,
            rpush,
            rpop,
        ]

        self.inst_table = {}
        for ir in self.inst_list:
            self.inst_table[ir.opcode] = MethodType(ir, PyComet2)

        self.is_auto_dump = False
        self.break_points = []
        self.call_level = 0
        self.step_count = 0
        self.monitor = StatusMonitor(self)
        self.dis = Disassembler(self)

        self.initialize()

    def initialize(self):
        # 主記憶 1 word = 2 byte unsigned short
        self.memory = array.array("H", [0] * 65536)
        # レジスタ unsigned short
        self.GR = array.array("H", [0] * 9)
        # スタックポインタ SP = GR[8]
        self.SP = self.initSP
        # プログラムレジスタ
        self.PR = 0
        # Overflow Flag
        self.OF = 0
        # Sign Flag
        self.SF = 0
        # Zero Flag
        self.ZF = 1
        logging.info("Initialize memory and registers.")

    @property
    def FR(self):
        return self.OF << 2 | self.SF << 1 | self.ZF

    def _set_SP(self, value):
        self.GR[8] = value

    def _get_SP(self):
        return self.GR[8]

    SP = property(_get_SP, _set_SP)

    def set_logging_level(self, lv):
        logging.basicConfig(level=lv)

    # PRが指す命令を返す
    def get_instruction(self, adr=None):
        try:
            if adr is None:
                adr = self.PR
            return self.inst_table[(self.memory[adr] & 0xFF00) >> 8]
        except KeyError:
            raise InvalidOperation(adr)

    # 命令を1つ実行
    def step(self):
        self.get_instruction()()
        self.step_count += 1

    def watch(self, variables, decimalFlag=False):
        self.monitor.decimalFlag = decimalFlag
        for v in variables.split(","):
            self.monitor.append(v)

        while True:
            if self.PR in self.break_points:
                break
            else:
                try:
                    print(self.monitor)
                    sys.stdout.flush()
                    self.step()
                except InvalidOperation as e:
                    print(e, file=sys.stderr)
                    self.dump(e.address)
                    break

    def run(self):
        while True:
            if self.PR in self.break_points:
                break
            else:
                self.step()

    # オブジェクトコードを主記憶に読み込む
    def load(self, filename, quiet=False):
        if not quiet:
            print("load %s ..." % filename, file=sys.stderr)
        self.initialize()
        fp = open(filename, "rb")
        try:
            tmp = array.array("H")
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
            print("done.", file=sys.stderr)

    def exit(self):
        raise MachineExit(self)

    def cast_int(self, addr):
        if addr[0] == "#":
            return int(addr[1:], 16)
        else:
            return int(addr)

    def dump_memory(self, start_addr=0x0000, lines=0xFFFF / 8):
        printable = string.ascii_letters + string.digits + string.punctuation + " "

        def to_char(array):
            def chr2(i):
                c = 0x00FF & i
                return chr(c) if chr(c) in printable else "."

            return "".join([chr2(i) for i in array])

        def to_hex(array):
            return " ".join(["%04x" % i for i in array])

        st = []
        for i in range(0, lines):
            addr = i * 8 + start_addr
            if 0xFFFF < addr:
                return st
            st.append(
                "%04x: %-39s %-8s\n"
                % (
                    addr,
                    to_hex(self.memory[addr : addr + 8]),
                    to_char(self.memory[addr : addr + 8]),
                )
            )
        return "".join(st)

    # 8 * 16 wordsダンプする
    def dump(self, start_addr=0x0000):
        print(self.dump_memory(start_addr, 16))

    def dump_stack(self):
        print(self.dump_memory(self.SP, 16))

    def dump_to_file(self, filename, lines=0xFFFF / 8):
        fp = open(filename, "w")
        fp.write("Step count: %d\n" % self.step_count)
        fp.write("PR: #%04x\n" % self.PR)
        fp.write("SP: #%04x\n" % self.SP)
        fp.write("OF: %1d\n" % self.OF)
        fp.write("SF: %1d\n" % self.SF)
        fp.write("ZF: %1d\n" % self.ZF)
        for i in range(0, 8):
            fp.write("GR%d: #%04x\n" % (i, self.GR[i]))
        fp.write("Memory:\n")
        fp.write(self.dump_memory(0, lines))
        fp.close()

    def disassemble(self, start_addr=0x0000):
        addr = start_addr
        for addr_, dis in self.dis.disassemble(addr, 16):
            print(
                "#{:04x}\t#{:04x}\t{}".format(addr_, self.memory[addr_], dis),
                file=sys.stderr,
            )

    def set_break_point(self, addr):
        if addr in self.break_points:
            print("#%04x is already set." % addr, file=sys.stderr)
        else:
            self.break_points.append(addr)

    def print_break_points(self):
        if len(self.break_points) == 0:
            print("No break points.", file=sys.stderr)
        else:
            for i, addr in enumerate(self.break_points):
                print("%d: #%04x" % (i, addr), file=sys.stderr)

    def delete_break_points(self, n):
        if 0 <= n < len(self.break_points):
            print("#%04x is removed." % (self.break_points[n]), file=sys.stderr)
        else:
            print("Invalid number is specified.", file=sys.stderr)

    def write_memory(self, addr, value):
        self.memory[addr] = value

    def jump(self, addr):
        self.PR = addr
        self.print_status()

    def print_status(self):
        try:
            code = self.dis.dis_inst(self.PR)
        except InvalidOperation:
            code = "%04x" % self.memory[self.PR]
        sys.stderr.write(
            "PR  #%04x [ %-30s ]  STEP %d\n" % (self.PR, code, self.step_count)
        )
        sys.stderr.write(
            "SP  #%04x(%7d) FR(OF, SF, ZF)  %03s  (%7d)\n"
            % (self.SP, self.SP, i2bin(self.FR, 3), self.FR)
        )
        sys.stderr.write(
            "GR0 #%04x(%7d) GR1 #%04x(%7d) "
            "GR2 #%04x(%7d) GR3: #%04x(%7d)\n"
            % (
                self.GR[0],
                l2a(self.GR[0]),
                self.GR[1],
                l2a(self.GR[1]),
                self.GR[2],
                l2a(self.GR[2]),
                self.GR[3],
                l2a(self.GR[3]),
            )
        )
        sys.stderr.write(
            "GR4 #%04x(%7d) GR5 #%04x(%7d) "
            "GR6 #%04x(%7d) GR7: #%04x(%7d)\n"
            % (
                self.GR[4],
                l2a(self.GR[4]),
                self.GR[5],
                l2a(self.GR[5]),
                self.GR[6],
                l2a(self.GR[6]),
                self.GR[7],
                l2a(self.GR[7]),
            )
        )

    def wait_for_command(self):
        while True:
            try:
                line = input("pycomet2> ").strip()
            except EOFError:
                print
                break
            if line == "":
                continue
            try:
                args = line.split()
                if line[0] == "q":
                    break
                elif line[0] == "b":
                    if 2 <= len(args):
                        self.set_break_point(self.cast_int(args[1]))
                elif line[0:2] == "df":
                    self.dump_to_file(args[1])
                    print("dump to", args[1], file=sys.stderr)
                elif line[0:2] == "di":
                    if len(args) == 1:
                        self.disassemble()
                    else:
                        self.disassemble(self.cast_int(args[1]))
                elif line[0:2] == "du":
                    if len(args) == 1:
                        self.dump()
                    else:
                        self.dump(self.cast_int(args[1]))
                elif line[0] == "d":
                    if 2 <= len(args):
                        self.delete_break_points(int(args[1]))
                elif line[0] == "h":
                    self.print_help()
                elif line[0] == "i":
                    self.print_break_points()
                elif line[0] == "j":
                    self.jump(self.cast_int(args[1]))
                elif line[0] == "m":
                    self.write_memory(self.cast_int(args[1]), self.cast_int(args[2]))
                elif line[0] == "p":
                    self.print_status()
                elif line[0] == "r":
                    self.run()
                elif line[0:2] == "st":
                    self.dump_stack()
                elif line[0] == "s":
                    self.step()
                    self.print_status()
                else:
                    print("Invalid command", args[0], file=sys.stderr)
            except (IndexError, ValueError):
                print("Invalid arguments", ", ".join(args[1:]), file=sys.stderr)
            except InvalidOperation as e:
                print(e, file=sys.stderr)
                self.dump(e.address)
                break
            except MachineExit:
                if self.is_count_step:
                    print("Step count:", self.step_count)
                if self.is_auto_dump:
                    print("dump last status to last_state.txt", file=sys.stderr)
                    self.dump_to_file("last_state.txt")
                break

    def print_help(self):
        print(
            "b ADDR        "
            "Set a breakpoint at specified address.\n"
            "d NUM         Delete breakpoints.\n"
            "di ADDR       \n"
            "Disassemble 32 words from specified address.\n"
            "du ADDR       Dump 128 words of memory.\n"
            "h             Print help.\n"
            "i             Print breakpoints.\n"
            "j ADDR        Set PR to ADDR.\n"
            "m ADDR VAL    Change the memory at ADDR to VAL.\n"
            "p             Print register status.\n"
            "q             Quit.\n"
            "r             Strat execution of program.\n"
            "s             Step execution.\n"
            "st            Dump 128 words of stack image.",
            file=sys.stderr,
        )


def _main():
    usage = "usage: %prog [options] input.com"
    parser = OptionParser(usage)
    parser.add_option(
        "-c",
        "--count-step",
        action="store_true",
        dest="count_step",
        default=False,
        help="count step.",
    )
    parser.add_option(
        "-d",
        "--dump",
        action="store_true",
        dest="dump",
        default=False,
        help="dump last status to last_state.txt.",
    )
    parser.add_option(
        "-r", "--run", action="store_true", dest="run", default=False, help="run"
    )
    parser.add_option(
        "-w",
        "--watch",
        type="string",
        dest="watchVariables",
        default="",
        help="run in watching mode. (ex. -w PR,GR0,GR8,#001f)",
    )
    parser.add_option(
        "-D",
        "--Decimal",
        action="store_true",
        dest="decimalFlag",
        default=False,
        help="watch GR[0-8] and specified address in decimal "
        "notation. (Effective in watcing mode only)",
    )
    parser.add_option(
        "-v",
        "--version",
        action="store_true",
        dest="version",
        default=False,
        help="display version information.",
    )
    options, args = parser.parse_args()

    if options.version:
        print(
            "PyCOMET2 version 1.2\n"
            "$Revision: a31dbeeb4d1c $\n"
            "Copyright (c) 2012, Yasuaki Mitani.\n"
            "Copyright (c) 2009, Masahiko Nakamoto.\n"
            "All rights reserved."
        )
        sys.exit()

    if len(args) < 1:
        parser.print_help()
        sys.exit()

    comet2 = PyComet2()
    comet2.is_auto_dump = options.dump
    comet2.is_count_step = options.count_step
    try:
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
    except InvalidOperation as e:
        print(e, file=sys.stderr)
        comet2.dump(e.address)
    except MachineExit:
        if comet2.is_count_step:
            print("Step count:", comet2.step_count)
        if comet2.is_auto_dump:
            print("dump last status to last_state.txt", file=sys.stderr)
            comet2.dump_to_file("last_state.txt")


def main():

    histfile = os.path.join(
        os.path.abspath(os.path.dirname(__file__)), ".comet2_history"
    )
    try:
        readline.read_history_file(histfile)
    except OSError:
        pass

    atexit.register(readline.write_history_file, histfile)
    del histfile
    _main()


if __name__ == "__main__":
    main()
