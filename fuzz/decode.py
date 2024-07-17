# tool to decompile a fuzz_run_program test case to human readable form

import sys
import io
from ir import reader
from klvm_tools import binutils
from klvm.serialize import sexp_from_stream
from klvm import to_sexp_f

with open(sys.argv[1], 'rb') as f:
    blob = f.read()
    sexp = sexp_from_stream(io.BytesIO(blob), to_sexp_f)
    print(binutils.disassemble(sexp))

