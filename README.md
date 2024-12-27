> [!IMPORTANT]
> Work In Progress

# PDP-11 UNIX a.out IDA Loader
IDA loader for PDP-11 UNIX a.out binaries. First attempt at writing something in Python that's not university/school assignment, time to laugh at my failure. Also possibly the worst Python code known to exist.

# Status
Handles UNIX V2 and V3 binaries (maybe later ones too; haven't tested), most of the symbols are loaded (imports and exports yet to be implemented). Does NOT handle relocation or V1 bins yet. Works slightly better for C binaries compared to ASM ones because IDA is to dumb to handle arguments passed via program text rather than stack. A bit of manual work is needed to make sense of B binaries - B is an interpreted language.
