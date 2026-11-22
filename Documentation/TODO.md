# Technical debt and possible work

Everything below is known and deliberate. See `Design.md` for how things work
now and for where the line with Wine is.

## LoadLibrary

### Beyond the line (decided: Wine)

Exceptions, the dynamic CRT, real locales and `KUSER_SHARED_DATA` are what Wine is
for. See [Where the line is](../README.md#where-the-line-is) for the supported scope.

- **Images without large address awareness.** These require low addresses for
  the image and for allocations the providers return to it.
- **Locale and environment.** Code pages are Windows-1252, 437 and UTF-8,
  character types and case are Latin-1, `GetEnvironmentStrings` is empty.
- **SEH and C++ exceptions** inside the DLL abort in `RtlUnwindEx` /
  `RaiseException`. Supporting them would require an unwinder over
  `.pdata`/`.xdata`.
- **`KUSER_SHARED_DATA` at `0x7ffe0000`.** Not mapped. Some code reads time
  or CPU features from it.

### Diagnostics

- **Crash stacks stop at DLL frames.** The DLL has `.pdata` but no DWARF.
  `GetLibraryAddressName` already names an address as `module+offset` with
  the nearest export, and is safe in a fault handler. What is left is to call
  it from the fault handler of the host process: the loader cannot install one
  itself without taking over the signals of its host.
