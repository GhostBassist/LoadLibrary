// loadlibrary-check: whether a DLL fits LoadLibrary, and why not
//
//   loadlibrary-check [--attach] <dll>
//
// The DLL is loaded by the real loader with the registered providers (Kernel32.c), so the verdict about loading is
// what a module would get. Unresolved imports are grouped: beyond the line (Wine) or candidates for a provider.
// --attach also runs DllMain (AttachLibrary) in a child process and tells how it ended.
// Which unresolved imports the needed exports can actually reach is told by LibraryCheck.py

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

#include "LoadLibrary.h"

#define CATEGORY_DYNAMIC_CRT  0
#define CATEGORY_SUBSYSTEM    1
#define CATEGORY_EXCEPTIONS   2
#define CATEGORY_FILES        3
#define CATEGORY_PROVIDER     4
#define CATEGORY_COUNT        5

static const char* CategoryNames[CATEGORY_COUNT] =
{
  "dynamic CRT (beyond the line: Wine)",
  "Windows subsystems (beyond the line: Wine)",
  "exceptions and unwinding (beyond the line: Wine, unless only __report_gsfailure reaches them)",
  "files, consoles, registry (beyond the line: Wine, unless a few are worth a provider)",
  "missing in providers (can be added to Kernel32.c or a provider of its own)"
};

static const char* DynamicCRT[] = { "vcruntime", "msvcp", "msvcr", "ucrtbase", "api-ms-win-crt-", "concrt", NULL };
static const char* Subsystems[] = { "user32", "gdi32", "advapi32", "ole32", "oleaut32", "shell32", "ws2_32", "winmm", "comdlg32", "comctl32", "shlwapi", "crypt32", "bcrypt", "ntdll", NULL };
static const char* Exceptions[] = { "RaiseException", "RtlUnwind", "RtlUnwindEx", "RtlVirtualUnwind", "RtlLookupFunctionEntry", "RtlCaptureContext", "RtlRestoreContext", "_CxxThrowException", "__CxxFrameHandler", "__C_specific_handler", NULL };
static const char* Files[] = { "CreateFile", "ReadFile", "WriteConsole", "GetConsole", "SetConsole", "SetFilePointer", "FlushFileBuffers", "CloseHandle", "FindFirstFile", "FindNextFile", "FindClose", "DeleteFile", "GetFileAttributes", "SetStdHandle", "Reg", "GetFileSize", "CreateDirectory", NULL };

struct Entry
{
  char module[64];
  char name[96];
  int category;
};

static struct Entry Entries[4096];
static int EntryCount = 0;

static char Messages[16384];
static size_t MessageLength = 0;
static int Direct = 0;

static void Report(int priority, const char* format, ...)
{
  va_list arguments;
  int length;

  if (Direct)
  {
    // In the child of --attach: an abort of a thunk must not lose its message
    va_start(arguments, format);
    vdprintf(STDERR_FILENO, format, arguments);
    va_end(arguments);
    return;
  }

  va_start(arguments, format);
  length = vsnprintf(Messages + MessageLength, sizeof(Messages) - MessageLength, format, arguments);
  va_end(arguments);

  if ((length > 0) &&
      (MessageLength + length < sizeof(Messages)))
    MessageLength += length;
}

static int StartsWith(const char* string, const char* const* prefixes)
{
  for (; *prefixes != NULL; prefixes ++)
    if (strncasecmp(string, *prefixes, strlen(*prefixes)) == 0)
      return 1;

  return 0;
}

static void CollectImport(const char* module, const char* name, void* context)
{
  struct Entry* entry;

  if (EntryCount >= (int)(sizeof(Entries) / sizeof(Entries[0])))
    return;

  entry = Entries + EntryCount ++;
  snprintf(entry->module, sizeof(entry->module), "%s", module);

  if ((uintptr_t)name < 0x10000)
    snprintf(entry->name, sizeof(entry->name), "#%u", (unsigned int)(uintptr_t)name);
  else
    snprintf(entry->name, sizeof(entry->name), "%s", name);

  if (StartsWith(entry->module, DynamicCRT))
    entry->category = CATEGORY_DYNAMIC_CRT;
  else if (StartsWith(entry->module, Subsystems))
    entry->category = CATEGORY_SUBSYSTEM;
  else if (StartsWith(entry->name, Exceptions))
    entry->category = CATEGORY_EXCEPTIONS;
  else if (StartsWith(entry->name, Files))
    entry->category = CATEGORY_FILES;
  else
    entry->category = CATEGORY_PROVIDER;
}

static int CollectModule(struct Module* image, struct Module*** visited, size_t* count, size_t* capacity)
{
  for (size_t index = 0; index < *count; index ++)
    if ((*visited)[index] == image)
      return 0;

  if (*count == *capacity)
  {
    if (*capacity > SIZE_MAX / sizeof(**visited) / 2)
      return -1;
    size_t next = *capacity ? *capacity * 2 : 16;
    struct Module** entries = realloc(*visited, next * sizeof(*entries));
    if (entries == NULL)
      return -1;
    *visited = entries;
    *capacity = next;
  }

  (*visited)[(*count) ++] = image;
  GetLibraryUnresolvedImports(image, CollectImport, NULL);

  for (size_t index = 0; index < image->number; index ++)
    if (CollectModule(image->dependencies[index], visited, count, capacity) < 0)
      return -1;
  return 0;
}

// DllMain in a child: the exit code tells the result, aborts of thunks come through stderr

static int Attach(struct Module* image)
{
  char output[8192];
  int pipes[2];
  pid_t process;
  ssize_t length;
  int status;
  pid_t waited;
  int readError = 0;

  fflush(stdout);

  if (pipe(pipes) < 0)
  {
    perror("pipe");
    return 1;
  }

  process = fork();
  if (process < 0)
  {
    perror("fork");
    close(pipes[0]);
    close(pipes[1]);
    return 1;
  }
  if (process == 0)
  {
    close(pipes[0]);
    if (pipes[1] != STDERR_FILENO)
    {
      if (dup2(pipes[1], STDERR_FILENO) < 0)
        _exit(3);
      close(pipes[1]);
    }
    Direct = 1;
    _exit((AttachLibrary(image) == 0) ? 0 : 2);
  }

  close(pipes[1]);
  do
  {
    length = read(pipes[0], output, sizeof(output));
    if (length > 0)
      fwrite(output, 1, length, stdout);
  } while (length > 0 || (length < 0 && errno == EINTR));
  if (length < 0)
  {
    perror("read");
    readError = 1;
  }
  close(pipes[0]);
  do
    waited = waitpid(process, &status, 0);
  while (waited < 0 && errno == EINTR);

  if (waited < 0)
  {
    perror("waitpid");
    return 1;
  }
  if (WIFEXITED(status) && (WEXITSTATUS(status) == 0))
    printf("DllMain:      OK (TLS callbacks and DllMain with DLL_PROCESS_ATTACH passed)\n");
  else if (WIFEXITED(status) && (WEXITSTATUS(status) == 2))
    printf("DllMain:      returned FALSE\n");
  else if (WIFSIGNALED(status))
    printf("DllMain:      killed by signal %d (%s)\n", WTERMSIG(status), strsignal(WTERMSIG(status)));
  else
    printf("DllMain:      child did not complete the attach check\n");

  return readError || !WIFEXITED(status) || WEXITSTATUS(status) != 0;
}

int main(int argc, char** argv)
{
  struct Module* image;
  struct Module** visited = NULL;
  const char* path;
  int attach;
  size_t count = 0;
  size_t capacity = 0;
  int result = 0;
  int totals[CATEGORY_COUNT] = { 0 };

  attach = (argc > 1) && (strcmp(argv[1], "--attach") == 0);

  if (argc != 2 + attach)
  {
    fprintf(stderr, "usage: loadlibrary-check [--attach] <dll>\n");
    return 2;
  }
  path = argv[1 + attach];

  printf("DLL:          %s\n", path);

  if ((image = LoadLibrary(path, NULL, Report)) == NULL)
  {
    int error = GetLibraryLastError();

    printf("Load:         FAILED, %s\n", GetLibraryErrorText(error));
    if (MessageLength > 0)
      printf("%s", Messages);
    printf("Verdict:      does not fit%s\n", (error == LIBRARY_ERROR_ADDRESS_AWARE) ? ", use Wine" : "");
    return 1;
  }

  printf("Load:         OK at %p, %zu bytes\n", (void*)image->base, image->size);
  printf("DllMain:      %s\n", image->entry ? "present (AttachLibrary runs it with the startup of its CRT)" : "none");
  printf("Static TLS:   %s\n", (image->slot >= 0) ? "yes" : "no");

  if (MessageLength > 0)
    printf("%s", Messages);

  if (CollectModule(image, &visited, &count, &capacity) < 0)
  {
    fprintf(stderr, "Unable to allocate dependency list\n");
    free(visited);
    FreeLibrary(image);
    return 1;
  }

  if (count > 1)
  {
    printf("Dependencies:");
    for (size_t index = 1; index < count; index ++)
      printf(" %s", visited[index]->name);
    printf("\n");
  }
  free(visited);

  printf("Unresolved:   %d imports (they abort with their name when called)\n", EntryCount);

  for (int category = 0; category < CATEGORY_COUNT; category ++)
  {
    for (int index = 0; index < EntryCount; index ++)
    {
      if (Entries[index].category != category)
        continue;

      if (totals[category] ++ == 0)
        printf("  %s:\n", CategoryNames[category]);

      printf("    %s!%s\n", Entries[index].module, Entries[index].name);
    }
  }

  if (attach)
    result = Attach(image);

  if (totals[CATEGORY_DYNAMIC_CRT] + totals[CATEGORY_SUBSYSTEM] > 0)
    printf("Verdict:      beyond the line, use Wine (imports of the dynamic CRT or of Windows subsystems)\n");
  else if (result)
    printf("Verdict:      loads, but the attach check failed\n");
  else if (EntryCount > 0)
    printf("Verdict:      loads; unresolved imports abort only when called. Check which ones the exports you need reach:\n"
           "              LibraryCheck.py %s <export>...\n", path);
  else
    printf("Verdict:      fits, every import is resolved\n");

  FreeLibrary(image);
  return result;
}
