# Technical debt and possible work

Everything below is known and deliberate. See `Design.md` for how things work
now and for where the line with Wine is.

## LoadLibrary

### Coverage of PE features (images that are not large address aware are beyond the line too)

- **Not large address aware** images are refused. Fix: `MAP_32BIT` for the
  image, and for every allocation a provider hands to it.

### Beyond the line (decided: Wine, see "Where the line is" in LoadLibrary.md)

Exceptions, the dynamic CRT, real locales and `KUSER_SHARED_DATA` are what Wine is
for. They stay here as a record of what a DLL may need, not as work to do.


- **Locale and environment.** Code pages are Windows-1252, 437 and UTF-8,
  character types and case are Latin-1, `GetEnvironmentStrings` is empty.
- **SEH and C++ exceptions** inside the DLL abort in `RtlUnwindEx` /
  `RaiseException`. Fix: an unwinder over `.pdata`/`.xdata`. This is the
  largest item here, do it only for a DLL that really throws.
- **`KUSER_SHARED_DATA` at `0x7ffe0000`.** Not mapped. Some code reads time
  or CPU features from it. Fix: map a page there and keep the time fields
  updated, only if a DLL reads it (grep the disassembly for `0x7ffe0`).

### Diagnostics

- **Crash stacks stop at DLL frames.** The DLL has `.pdata` but no DWARF.
  `GetLibraryAddressName` already names an address as `module+offset` with
  the nearest export, and is safe in a fault handler. What is left is to call
  it from the fault handler of the host process: the loader cannot install one
  itself without taking over the signals of its host.
