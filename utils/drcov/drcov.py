#!/usr/bin/python
import os
import re
import sys
import mmap
import struct
import collections
from ctypes import *

#
# I know people like to use this parser in their own projects, so this
# if/def makes it compatible with being imported or used outside Lighthouse
#

try:
    from lighthouse.exceptions import CoverageMissingError
    from lighthouse.reader.coverage_file import CoverageFile
    g_lighthouse = True
except ImportError as e:
    CoverageFile = object
    g_lighthouse = False

#------------------------------------------------------------------------------
# DynamoRIO Drcov Log Parser
#------------------------------------------------------------------------------

class DrcovData(CoverageFile):
    """
    A drcov log parser.
    """

    def __init__(self, filepath=None):
        self.filepath = filepath

        # drcov header attributes
        self.version = 0
        self.flavor = None

        # drcov module table
        self.module_table_count = 0
        self.module_table_version = 0
        self.modules = {}

        # drcov basic block data
        self.bbs = []
        self.bb_table_count = 0
        self.bb_table_is_binary = True

        # parse
        if g_lighthouse:
            super(DrcovData, self).__init__(filepath)
        else:
            self._parse()

    #--------------------------------------------------------------------------
    # Public
    #--------------------------------------------------------------------------

    def get_offsets(self, module_name):
        """
        Return coverage data as basic block offsets for the named module.
        """
        modules = self.modules.get(module_name, [])
        if not modules:
            return []

        #
        # I don't know if this should ever actually trigger, but if it does,
        # it is a strange testcase to collect coverage against. It means that
        # maybe the target library/module was loaded, unloaded, and reloaded?
        #
        # if someone ever actally triggers this, we can look into it :S
        #

        if self.version > 2:
            assert all(module.containing_id == modules[0].id for module in modules)

        # extract the unique module ids that we need to collect blocks for
        mod_ids = [module.id for module in modules]

        # loop through the coverage data and filter out data for the target ids
        coverage_blocks = [bb.start for bb in self.bbs if bb.mod_id in mod_ids]

        # return the filtered coverage blocks
        return coverage_blocks

    def get_offset_blocks(self, module_name):
        """
        Return coverage data as basic blocks (offset, size) for the named module.
        """
        modules = self.modules.get(module_name, [])
        if not modules:
            return []

        # NOTE: see comment in get_offsets() for more info...
        if self.version > 2:
            assert all(module.containing_id == modules[0].id for module in modules)

        # extract the unique module ids that we need to collect blocks for
        mod_ids = [module.id for module in modules]

        # loop through the coverage data and filter out data for the target ids
        if self.version < 3:
            coverage_blocks = [(bb.start, bb.size) for bb in self.bbs if bb.mod_id in mod_ids]

        #
        # drcov version 3 does not include the 'preferred' / sub-module base
        # in the bb offset, so we must add that base offset before returning
        # the block offsets to correctly normalize things
        #
        # it's unclear if the preferred_base for given sub-module segments
        # will always be correct, so we opt to simply use the first segment
        # in a given module as the base to compute the known runtime offset
        #

        else:
            mod_bases = dict([(module.id, module.start - modules[0].start) for module in modules])
            coverage_blocks = [(mod_bases[bb.mod_id] + bb.start, bb.size) for bb in self.bbs if bb.mod_id in mod_ids]

        # return the filtered coverage blocks
        return coverage_blocks

    #--------------------------------------------------------------------------
    # Parsing Routines - Top Level
    #--------------------------------------------------------------------------

    def _parse(self):
        """
        Parse drcov coverage from the given log file.
        """
        with open(self.filepath, "rb") as f:
            self._parse_drcov_header(f)
            self._parse_module_table(f)
            self._parse_bb_table(f)

    #--------------------------------------------------------------------------
    # Parsing Routines - Internals
    #--------------------------------------------------------------------------

    def _parse_drcov_header(self, f):
        """
        Parse drcov log header from filestream.
        """

        # parse drcov version from log
        #   eg: DRCOV VERSION: 2
        version_line = f.readline().decode('utf-8').strip()
        self.version = int(version_line.split(":")[1])

        # parse drcov flavor from log
        #   eg: DRCOV FLAVOR: drcov
        flavor_line = f.readline().decode('utf-8').strip()
        self.flavor = flavor_line.split(":")[1]

        assert self.version == 2 or self.version == 3, "Only drcov versions 2 and 3 log files supported"

    def _parse_module_table(self, f):
        """
        Parse drcov log module table from filestream.
        """
        self._parse_module_table_header(f)
        self._parse_module_table_columns(f)
        self._parse_module_table_modules(f)

    def _parse_module_table_header(self, f):
        """
        Parse drcov log module table header from filestream.

        -------------------------------------------------------------------

        Format used in DynamoRIO v6.1.1 through 6.2.0
           eg: 'Module Table: 11'

        Format used in DynamoRIO v7.0.0-RC1 (and hopefully above)
           eg: 'Module Table: version X, count 11'

        """

        # parse module table 'header'
        #   eg: Module Table: version 2, count 11
        header_line = f.readline().decode('utf-8').strip()
        field_name, field_data = header_line.split(": ")
        #assert field_name == "Module Table"

        #
        # NOTE/COMPAT:
        #
        #   DynamoRIO doesn't document their drcov log format, and it has
        #   changed its format at least once during its lifetime.
        #
        #   we just have to try parsing the table header one way to determine
        #   if its the old (say, a 'v1') table, or the new 'v2' table.
        #

        try:

            # seperate 'version X' and 'count Y' from each other ('v2')
            version_data, count_data = field_data.split(", ")

        # failure to unpack indicates this is an 'older, v1' drcov log
        except ValueError:
            self.module_table_count   = int(field_data)
            self.module_table_version = 1
            return

        # parse module table version out of 'version X'
        data_name, version = version_data.split(" ")
        #assert data_name == "version"
        self.module_table_version = int(version)
        if not self.module_table_version in [2, 3, 4, 5]:
            raise ValueError("Unsupported (new?) drcov log format...")

        # parse module count in table from 'count Y'
        data_name, count = count_data.split(" ")
        #assert data_name == "count"
        self.module_table_count = int(count)

    def _parse_module_table_columns(self, f):
        """
        Parse drcov log module table columns from filestream.

        -------------------------------------------------------------------

        DynamoRIO v6.1.1, table version 1:
           eg: (Not present)

        DynamoRIO v7.0.0-RC1, table version 2:
           Windows:
             'Columns: id, base, end, entry, checksum, timestamp, path'
           Mac/Linux:
             'Columns: id, base, end, entry, path'

        DynamoRIO v7.0.17594B, table version 3:
           Windows:
             'Columns: id, containing_id, start, end, entry, checksum, timestamp, path'
           Mac/Linux:
             'Columns: id, containing_id, start, end, entry, path'

        DynamoRIO v7.0.17640, table version 4:
           Windows:
             'Columns: id, containing_id, start, end, entry, offset, checksum, timestamp, path'
           Mac/Linux:
             'Columns: id, containing_id, start, end, entry, offset, path'

        DynamoRIO v10.0.19734, table version 5:
           Windows:
             'Columns: id, containing_id, start, end, entry, offset, preferred_base, checksum, timestamp, path'
           Mac/Linux:
             'Columns: id, containing_id, start, end, entry, offset, preferred_base, path'

        """

        # NOTE/COMPAT: there is no 'Columns' line for the v1 table...
        if self.module_table_version == 1:
            return

        # parse module table 'columns'
        #   eg: Columns: id, base, end, entry, checksum, timestamp, path
        column_line = f.readline().decode('utf-8').strip()
        field_name, field_data = column_line.split(": ")
        #assert field_name == "Columns"

        # seperate column names
        #   Windows:   id, base, end, entry, checksum, timestamp, path
        #   Mac/Linux: id, base, end, entry, path
        columns = field_data.split(", ")

    def _parse_module_table_modules(self, f):
        """
        Parse drcov log modules in the module table from filestream.
        """
        modules = collections.defaultdict(list)

        # loop through each *expected* line in the module table and parse it
        for i in range(self.module_table_count):
            module = DrcovModule(f.readline().decode('utf-8').strip(), self.module_table_version)
            modules[module.filename].append(module)

        self.modules = modules

    def _parse_bb_table(self, f):
        """
        Parse dcov log basic block table from filestream.
        """
        self._parse_bb_table_header(f)
        self._parse_bb_table_entries(f)

    def _parse_bb_table_header(self, f):
        """
        Parse drcov log basic block table header from filestream.
        """

        # parse basic block table 'header'
        #   eg: BB Table: 2792 bbs
        header_line = f.readline().decode('utf-8').strip()
        field_name, field_data = header_line.split(": ")
        #assert field_name == "BB Table"

        # parse basic block count out of 'X bbs'
        count_data, data_name = field_data.split(" ")
        #assert data_name == "bbs"
        self.bb_table_count = int(count_data)

        # peek at the next few bytes to determine if this is a binary bb table.
        # An ascii bb table will have the line: 'module id, start, size:'
        token = b"module id"
        saved_position = f.tell()

        # is this an ascii table?
        if f.read(len(token)) == token:
            self.bb_table_is_binary = False

        # nope! binary table
        else:
            self.bb_table_is_binary = True

        # seek back to the start of the table
        f.seek(saved_position)

    def _parse_bb_table_entries(self, f):
        """
        Parse drcov log basic block table entries from filestream.
        """

        # allocate the ctypes structure array of basic blocks
        self.bbs = (DrcovBasicBlock * self.bb_table_count)()

        # read binary basic block entries directly into the newly allocated array
        if self.bb_table_is_binary:
            f.readinto(self.bbs)

        # parse the plaintext basic block entries one by one
        else:
            self._parse_bb_table_text_entries(f)

    def _parse_bb_table_text_entries(self, f):
        """
        Parse drcov log basic block table text entries from filestream.
        """
        table_header = f.readline().decode('utf-8').strip()

        if table_header != "module id, start, size:":
            raise ValueError("Invalid BB header: %r" % table_header)

        pattern = re.compile(r"^module\[\s*(?P<mod>[0-9]+)\]\:\s*(?P<start>0x[0-9a-fA-F]+)\,\s*(?P<size>[0-9]+)$")
        for i, bb in enumerate(self.bbs):
            text_entry = f.readline().decode('utf-8').strip()
            if not text_entry:
                continue

            match = pattern.match(text_entry)
            if not match:
                raise ValueError("Invalid BB entry: %r" % text_entry)

            bb.start = int(match.group("start"), 16)
            bb.size = int(match.group("size"), 10)
            bb.mod_id = int(match.group("mod"), 10)

#------------------------------------------------------------------------------
# drcov module parser
#------------------------------------------------------------------------------

class DrcovModule(object):
    """
    Parser & wrapper for module details as found in a drcov coverage log.

    A 'module' in this context is a .EXE, .DLL, ELF, MachO, etc.
    """
    def __init__(self, module_data, version):
        self.id    = 0
        self.base  = 0
        self.end   = 0
        self.size  = 0
        self.entry = 0
        self.checksum  = 0
        self.timestamp = 0
        self.path      = ""
        self.filename  = ""
        self.containing_id = 0

        # parse the module
        self._parse_module(module_data, version)

    @property
    def start(self):
        """
        Compatability alias for the module base.

        DrCov table version 2 --> 3 changed this paramter name base --> start.
        """
        return self.base

    def _parse_module(self, module_line, version):
        """
        Parse a module table entry.
        """
        data = module_line.split(", ")

        # NOTE/COMPAT
        if version == 1:
            self._parse_module_v1(data)
        elif version == 2:
            self._parse_module_v2(data)
        elif version == 3:
            self._parse_module_v3(data)
        elif version == 4:
            self._parse_module_v4(data)
        elif version == 5:
            self._parse_module_v5(data)
        else:
            raise ValueError("Unknown module format (v%u)" % version)

    def _parse_module_v1(self, data):
        """
        Parse a module table v1 entry.
        """
        self.id       = int(data[0])
        self.size     = int(data[1])
        self.path     = str(data[2])
        self.filename = os.path.basename(self.path.replace('\\', os.sep))

    def _parse_module_v2(self, data):
        """
        Parse a module table v2 entry.
        """
        self.id        = int(data[0])
        self.base      = int(data[1], 16)
        self.end       = int(data[2], 16)
        self.entry     = int(data[3], 16)
        if len(data) == 7: # Windows Only
            self.checksum  = int(data[4], 16)
            self.timestamp = int(data[5], 16)
        self.path      = str(data[-1])
        self.size      = self.end-self.base
        self.filename  = os.path.basename(self.path.replace('\\', os.sep))

    def _parse_module_v3(self, data):
        """
        Parse a module table v3 entry.
        """
        self.id            = int(data[0])
        self.containing_id = int(data[1])
        self.base          = int(data[2], 16)
        self.end           = int(data[3], 16)
        self.entry         = int(data[4], 16)
        if len(data) > 7: # Windows Only
            self.checksum  = int(data[5], 16)
            self.timestamp = int(data[6], 16)
        self.path          = str(data[-1])
        self.size          = self.end-self.base
        self.filename      = os.path.basename(self.path.replace('\\', os.sep))

    def _parse_module_v4(self, data):
        """
        Parse a module table v4 entry.
        """
        self.id            = int(data[0])
        self.containing_id = int(data[1])
        self.base          = int(data[2], 16)
        self.end           = int(data[3], 16)
        self.entry         = int(data[4], 16)
        self.offset        = int(data[5], 16)
        if len(data) > 8: # Windows Only
            self.checksum  = int(data[6], 16)
            self.timestamp = int(data[7], 16)
        self.path          = str(data[-1])
        self.size          = self.end-self.base
        self.filename      = os.path.basename(self.path.replace('\\', os.sep))

    def _parse_module_v5(self, data):
        """
        Parse a module table v5 entry.
        """
        self.id             = int(data[0])
        self.containing_id  = int(data[1])
        self.base           = int(data[2], 16)
        self.end            = int(data[3], 16)
        self.entry          = int(data[4], 16)
        self.offset         = int(data[5], 16)
        self.preferred_base = int(data[6], 16)
        if len(data) > 8: # Windows Only
            self.checksum   = int(data[7], 16)
            self.timestamp  = int(data[8], 16)
        self.path           = str(data[-1])
        self.size           = self.end-self.base
        self.filename       = os.path.basename(self.path.replace('\\', os.sep))


#------------------------------------------------------------------------------
# drcov basic block parser
#------------------------------------------------------------------------------

class DrcovBasicBlock(Structure):
    """
    Parser & wrapper for basic block details as found in a drcov coverage log.

    NOTE:

      Based off the C structure as used by drcov -

        /* Data structure for the coverage info itself */
        typedef struct _bb_entry_t {
            uint   start;      /* offset of bb start from the image base */
            ushort size;
            ushort mod_id;
        } bb_entry_t;

    """
    _pack_   = 1
    _fields_ = [
        ('start',  c_uint32),
        ('size',   c_uint16),
        ('mod_id', c_uint16)
    ]

#------------------------------------------------------------------------------
# Command Line Testing
#------------------------------------------------------------------------------

if __name__ == "__main__":
    argc = len(sys.argv)
    argv = sys.argv

    # base usage
    if argc < 2:
        print("usage: {} <coverage filename>".format(os.path.basename(sys.argv[0])))
        sys.exit()

    # attempt file parse
    x = DrcovData(argv[1])
    for bb in x.bbs:
        print("0x{:08x}".format(bb.start))

