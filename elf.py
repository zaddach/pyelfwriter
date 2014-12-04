# -*- coding: utf-8 -*-

"""Tools for writing an ELF file.
"""
import struct

EM_NONE = 0
EM_ARM = 40

EV_NONE = 0
EV_CURRENT = 1

EI_MAG0 = 0
EI_MAG1 = 1
EI_MAG2 = 2
EI_MAG3 = 3
EI_CLASS = 4
EI_DATA = 5
EI_VERSION = 6
EI_OSABI = 7
EI_ABIVERSION = 8
EI_PAD = 9
EI_NIDENT = 16

ELFMAG0 = '\x7f'
ELFMAG1 = 'E'
ELFMAG2 = 'L'
ELFMAG3 = 'F'

ELFCLASSNONE = 0
ELFCLASS32 = 1
ELFCLASS64 = 2

ELFDATANONE = 0
ELFDATALSB = 1
ELFDATAMSB = 2

ELFOSABI_SYSV = 0
ELFOSABI_STANDALONE = 0xff

ET_NONE = 0
ET_EXEC = 2

PT_NULL = 0
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_NOTE = 4
PT_SHLIB = 5
PT_PHDR = 6

PF_X = 1
PF_W = 2
PF_R = 4

SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_HASH = 5
SHT_DYNAMIC = 6
SHT_NOTE = 7
SHT_NOBITS = 8
SHT_REL = 9
SHT_SHLIB = 10
SHT_DYNSYM = 11

SHF_NONE = 0x0
SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4


class Elf32_Ehdr(object):
    SIZE = 0x34

    def __init__(self, clazz = ELFCLASS32, abi = ELFOSABI_SYSV):
        self.e_ident = [ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3, chr(clazz), chr(ELFDATALSB), \
            chr(EV_CURRENT), chr(abi), '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', \
            '\x00', '\x00']
        self.e_type = ET_EXEC
        self.e_machine = EM_ARM
        self.e_version = EV_CURRENT
        self.e_entry = 0
        self.e_phoff = 0
        self.e_shoff = 0
        self.e_flags = 0
        self.e_ehsize = 0
        self.e_phentsize = 0
        self.e_phnum = 0
        self.e_shentsize = 0
        self.e_shnum = 0
        self.e_shtrndx = 0

    def get_size(self):
        return self.SIZE
        
    def get_endianess(self):  
        return ord(self.e_ident[5])

    def get_data(self):
        return struct.pack("<16sHHLLLLLHHHHHH", "".join(self.e_ident), self.e_type, self.e_machine, self.e_version,\
             self.e_entry, self.e_phoff, self.e_shoff, self.e_flags, self.e_ehsize, self.e_phentsize, self.e_phnum, \
             self.e_shentsize, self.e_shnum, self.e_shtrndx)

class Elf32_Phdr(object):
    SIZE = 0x20

    def __init__(self, type, vaddr, paddr, memsz, flags, align, data_chunk):
        self.p_type = type
        self.p_vaddr = vaddr
        self.p_paddr = paddr
        self.p_memsz = memsz
        self.p_flags = flags
        self.p_align = align
        self.data_chunk = data_chunk

    def get_size(self):
        return self.SIZE

    def get_data(self):
        offset = 0
        file_size = 0
        if not self.data_chunk is None:
            offset = self.data_chunk.get_offset()
            file_size = self.data_chunk.get_run_size()
        return struct.pack("<LLLLLLLL", self.p_type, offset, self.p_vaddr, 
                           self.p_paddr, file_size, self.p_memsz, self.p_flags, self.p_align)

    def get_data_chunk(self):
        return self.data_chunk
        
    def to_s(self):
        return "p_type = 0x%x, p_vaddr = 0x%x, p_paddr = 0x%x, " \
               "p_memsz = 0x%x, p_flags = 0x%x, p_align = 0x%x" % (self.p_type, 
                    self.p_vaddr, self.p_paddr, self.p_memsz, self.p_flags, self.p_align)
    
#    def set_data_chunk(self, data_chunk):
#        self.filesz = data_chunk.get_run_size()
#        self.data_chunk = data_chunk
        
class Elf32_Shdr(object):
    SIZE = 0x28
    
    def __init__(self, name, type, addr, flags, data_chunk, link = 0, info = 0, addralign = 1, entsize = 0):
        self.sh_name = name
        self.sh_type = type
        self.sh_flags = flags
        self.sh_addr = addr
        self.sh_offset = 0
        self.sh_link = link
        self.sh_info = info
        self.sh_addralign = addralign 
        self.sh_entsize = entsize
        self.data_chunk = data_chunk

    def get_size(self):
        return self.SIZE

    def get_data(self):
        size = 0
        offset = 0
        if not self.data_chunk is None:
            size = self.data_chunk.get_size()
            offset = self.data_chunk.get_offset()
        return struct.pack("<LLLLLLLLLL", self.sh_name, self.sh_type, self.sh_flags, self.sh_addr, offset, size, self.sh_link, self.sh_info, self.sh_addralign, self.sh_entsize)
        
    def get_data_chunk(self):
        return self.data_chunk

class DataChunk(object):
    def __init__(self, data):
        self.data = data
        self.next_chunk = None
        self.offset = 0

    def get_size(self):
        if isinstance(self.data, list):
            return reduce(lambda x, y: x + y, map(len, self.data))
        return len(self.data)

    def get_data(self):
        if isinstance(self.data, list):
            return "".join(self.data)
        else:
            return self.data

    def set_next_chunk(self, chunk):
        self.next_chunk = chunk

    def get_next_chunk(self):
        return self.next_chunk

    def get_run_size(self):
        if not self.next_chunk is None: 
            return self.get_size() + self.next_chunk.get_run_size()
        else:
            return self.get_size()

    def get_run_data(self):
        if not self.next_chunk is None:
            return self.get_data() + self.next_chunk.get_run_data()
        else:
            return self.get_data()

    def get_offset(self):
        return self.offset
        
class EmptyDataChunk(DataChunk):
    def __init__(self, size):
        super(EmptyDataChunk, self).__init__("\x00" * size)
        
class StringTableSection(Elf32_Shdr):
    def __init__(self):
        self.string_table = []
        self.next_index = 0
        self.insert_string("\0")
        shstrtab_stridx = self.insert_string(".shstrtab")
        super(StringTableSection, self).__init__(shstrtab_stridx, SHT_STRTAB, 0, SHF_NONE, DataChunk(self.string_table), 0, 0, 0, 0)
        
    def insert_string(self, string):
        idx = self.next_index
        self.next_index += len(string) + 1
        self.string_table.append(string)
        self.string_table.append("\0")
        return idx

#class ElfSection(object):
#    def __init__(self, address):
#        self.header = Elf32_Shdr()
   

class ElfFile(object):
    """This class encapsulates an ELF file. 
    
    At the moment you can only start from a blank file, 
    and then add segments and sections. Symbols and other funky stuff is not yet implemented 
    (but can of course be done).
    
    """
   
    def __init__(self):
        self.sections = []
        self.segments = []
        self.data_chunks = []
        self.header = Elf32_Ehdr()
        self.sections.append(Elf32_Shdr(0, SHT_NULL, 0, SHF_NONE, None, 0, 0, 0, 0))
        self.string_section = StringTableSection()
        self.sections.append(self.string_section)
        self.data_chunks.append(self.string_section.get_data_chunk())

#    def add_section(self, name, virtual_addr, data_chunk, type = SHT_PROGBITS, physical_addr = virtual_addr, flags = SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR, addralign = 1, ):
#        Elf32_Shdr()
#        self.sections.append(section)

    
       
    def add_segment(self, type, virtual_address, data_chunk, flags = PF_X | PF_R | PF_W, mem_size = -1, physical_address = -1, addr_align = 1):
        """Add a segment together with data to the file.
        type -- One of the PT_* constants.
        virtual_address -- Virtual address where this segment is mapped to.
        data_chunk -- Data chunk that this segment refers to.
        flags -- Segment flags. Can be a combination of the PF_* constants.
        physical_address -- Physical address where code should reside. Useless in most cases, set equal to virtual_address.
        mem_size -- size of this segment in memory. In most cases is identical to data_chunk.get_run_size().
        addr_align -- Address align.
        """
        
        if physical_address == -1:
            physical_address = virtual_address
            
        if mem_size == -1:
            mem_size = data_chunk.get_run_size()
            
        self.segments.append(Elf32_Phdr(type, virtual_address, physical_address, mem_size, flags, addr_align, data_chunk))
        if not data_chunk is None:
            self.add_data_chunk(data_chunk)
    
    def add_data_chunk(self, chunk):
        self.data_chunks.append(chunk)

    def assemble(self):
        position = self.header.get_size()
        phdr_table_offset = position

        for phdr in self.segments:
            position += phdr.get_size()

        shdr_table_offset = position
        for shdr in self.sections:
            position += shdr.get_size()

        for data_chunk in self.data_chunks:
            subchunk = data_chunk
            while not subchunk is None:
                subchunk.offset = position
                position += subchunk.get_size()
                subchunk = subchunk.get_next_chunk()

        self.header.e_ehsize = Elf32_Ehdr.SIZE
        self.header.e_phentsize = Elf32_Phdr.SIZE
        self.header.e_shentsize = Elf32_Shdr.SIZE
        self.header.e_phoff = phdr_table_offset
        self.header.e_shoff = shdr_table_offset
        self.header.e_phnum = len(self.segments)
        self.header.e_shnum = len(self.sections)
        self.header.e_shtrndx = 1
        

    def get_data(self):
        self.assemble()
        return self.header.get_data() + \
            "".join(map(lambda x: x.get_data(), self.segments)) + \
            "".join(map(lambda x: x.get_data(), self.sections)) + \
            "".join(map(lambda x: x.get_run_data(), self.data_chunks))
            
    def save(self, filename):
        """Save to a file.
        filename -- File path to save to.
        """
        file = open(filename, 'wb')
        file.write(self.get_data())
        file.close()
    
    def set_entry(self, entry):
        self.header.e_entry = entry
        
    def get_entry(self):
        return self.header.e_entry
        
    def memory_map(self):
        memory_map = []
        for seg in self.segments:
            flags = ""
            if seg.p_flags & PF_R != 0:
                flags += "r"
            if seg.p_flags & PF_W != 0:
                flags += "w"
            if seg.p_flags & PF_X != 0:
                flags += "x"
            endianess = ""
            if self.header.get_endianess() == ELFDATALSB:
                endianess = "little"
            elif self.header.get_endianess() == ELFDATAMSB:
                endianess = "big"
            else:
                assert(False)
                
            memory_map.append({"address": seg.p_vaddr, "memory_size": seg.p_memsz, 
                "flags": flags, "alignment": seg.p_align, "data": seg.data_chunk.data, 
                "type": "data", "endianess": endianess, "physical_address": seg.p_paddr})
            
        return memory_map
        
def load(filename):
    f = open(filename, 'rb')
    raw_data = f.read()
    f.close()
    
    elffile = ElfFile()
    elffile.sections = []
    
    (header, elffile.header.e_type, elffile.header.e_machine, elffile.header.e_version, 
     elffile.header.e_entry, elffile.header.e_phoff, elffile.header.e_shoff, 
     elffile.header.e_flags, elffile.header.e_ehsize, elffile.header.e_phentsize, 
     elffile.header.e_phnum, elffile.header.e_shentsize, elffile.header.e_shnum, 
     elffile.header.e_shtrndx) = struct.unpack("<16sHHLLLLLHHHHHH", raw_data[0:Elf32_Ehdr.SIZE])
    
    elffile.header.e_ident = map(lambda x: x, header)
    
    for segnum in range(0, elffile.header.e_phnum):
        phoff = elffile.header.e_phoff + segnum * elffile.header.e_phentsize
        (p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, 
         p_flags, p_align) = struct.unpack("<LLLLLLLL", raw_data[phoff: phoff + elffile.header.e_phentsize])
        
        data_chunk = DataChunk(raw_data[p_offset: p_offset + p_filesz])
        elffile.segments.append(Elf32_Phdr(p_type, p_vaddr, p_paddr, p_memsz, p_flags, p_align, data_chunk))
    
    return elffile
    
def elffile_from_memory_map(memmap, entry = 0):
    elffile = ElfFile()
    for memmap_region in memmap:
        if memmap_region["type"] != "io":
            flags = ("r" in memmap_region["flags"] and PF_R or 0) | \
                    ("w" in memmap_region["flags"] and PF_W or 0) | \
                    ("x" in memmap_region["flags"] and PF_X or 0)
            size = "memory_size" in memmap_region and memmap_region["memory_size"] or len(memmap_region["data"])
            data = "data" in memmap_region and memmap_region["data"] or "\0" * memmap_region["memory_size"]
            physical_address = "physical_address" in memmap_region and memmap_region["physical_address"] or memmap_region["address"]
            alignment = "alignment" in memmap_region and memmap_region["alignment"] or 1
            elffile.add_segment(PT_LOAD, memmap_region["address"], DataChunk(data), flags, size, physical_address, alignment)
            
    elffile.set_entry(entry)
    return elffile
    
    
    
    
        
if __name__ == "__main__":
    f = open('/tmp/test.elf', 'wb')
    elffile = ElfFile()
    elffile.add_segment(PT_LOAD, 0x1000, DataChunk("\xde\xad\xbe\xef" * 0x100))
    elffile.set_entry(0x1000)
    f.write(elffile.get_data())
    f.close()

