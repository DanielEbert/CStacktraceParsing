#ifdef __cplusplus
extern "C"
{
#endif

#include <execinfo.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// TODO: remove
#include <assert.h>

    char* FUZZING_crashingInputsDir = NULL;

    uint64_t FUZZING_numberOfAssertionsFailed = 0;
    uint64_t FUZZING_numberOfSanitizerErrors = 0;

    void __sanitizer_print_stack_trace(void);

    // demangled __sanitizer::Printf(char const*, ...)
    void _ZN11__sanitizer6PrintfEPKcz(const char* format, ...);

    // Based on djb2 hash
    uint64_t fuzz_hash_stacktrace(void** stacktraceBuffer, int numberOfFrames)
    {
        uint64_t hash = 5381;

        for (int i = 0; i < numberOfFrames; i++)
        {
            hash = ((hash << 5) + hash) ^ (uint64_t)stacktraceBuffer[i];
        }

        return hash;
    }

    void fuzz_init_wrapper()
    {
        if (FUZZING_crashingInputsDir == NULL)
        {
            FUZZING_crashingInputsDir = getenv("FUZZING_crashingInputsDir");

            if (FUZZING_crashingInputsDir == NULL)
            {
                write(1, "No environment variable FUZZING_crashingInputsDir set. Using default /tmp.\n", 76);
                FUZZING_crashingInputsDir = (char*)"/tmp";
            }
        }
    }

    // noinline because we break here with GDB
    void __attribute__((noinline)) fuzz_on_new_assertion(char* crashFilePath, const char* __assertion,
                                                         int numberOfFrames, void** stacktrace, uint64_t stacktraceHash)
    {
        int fd = open(crashFilePath, O_CREAT | O_EXCL | O_WRONLY, 0644);
        if (fd == -1)
        {
            fprintf(stderr, "Error: Couldn't create crashing input file %s\n", crashFilePath);
            return;
        }

        // TODO: in while loop and check returned value
        // TODO: write actual fuzzer inp value, use for dedup later
        write(fd, "123", 3);

        close(fd);

        // TODO: use this as header to find start of assertion failures and to get assertion reason
        printf("_FUZZING Assertion failed: %s\n", __assertion);

        __sanitizer_print_stack_trace();

        printf("Stacktrace hash: %lx\n", stacktraceHash);
    }

    void __wrap___assert_fail(const char* __assertion, const char* __file, unsigned int __line, const char* __function)
    {
        static bool doubleAssertCalled = false;
        if (doubleAssertCalled)
        {
            abort();
        }
        doubleAssertCalled = true;

        fuzz_init_wrapper();

        FUZZING_numberOfAssertionsFailed++;

        int stacktraceBufferSize = 256;
        void* stacktrace[stacktraceBufferSize];

        int numberOfFrames = backtrace(stacktrace, stacktraceBufferSize);

        uint64_t stacktraceHash = fuzz_hash_stacktrace(stacktrace, numberOfFrames);

        char crashFilePath[1024];
        snprintf(crashFilePath, 1024, "%s/assert_%lx", FUZZING_crashingInputsDir, stacktraceHash);

        if (access(crashFilePath, F_OK) != -1)
        {
            // crashFilePath exists already
            if (FUZZING_numberOfAssertionsFailed % 100000 == 1)
            {
                printf("Stacktrace hash observed previously %s\n", crashFilePath);
                printf("Assertion count: %ld\n", FUZZING_numberOfAssertionsFailed);
            }
            doubleAssertCalled = false;
            return;
        }

        fuzz_on_new_assertion(crashFilePath, __assertion, numberOfFrames, stacktrace, stacktraceHash);

        // requires -rdynamic
        backtrace_symbols_fd(stacktrace, numberOfFrames, 1);

        // volatile int i = 1;
        // volatile int j = 2;
        // assert(i > 2);

        doubleAssertCalled = false;

        return;
    }

    // noinline because we break here with GDB
    void __attribute__((noinline))
    fuzz_on_new_sanitizer_error(char* crashFilePath, int numberOfFrames, void** stacktrace, uint64_t stacktraceHash)
    {
        int fd = open(crashFilePath, O_CREAT | O_EXCL | O_WRONLY, 0644);
        if (fd == -1)
        {
            printf("Error: Couldn't create crashing input file %s\n", crashFilePath);
            return;
        }

        // TODO: in while loop and check returned value
        // TODO: write actual fuzzer inp value, use for dedup later
        write(fd, "456", 3);

        close(fd);

        printf("_FUZZING SanitizerError\n");

        printf("_FUZZING Stacktrace: [");

        for (int i = 0; i < numberOfFrames; i++)
        {
            printf("%p", stacktrace[i]);
            if (i != numberOfFrames - 1)
            {
                printf(", ");
            }
        }
        printf("]\n");

        printf("Stacktrace hash: %lx\n", stacktraceHash);
    }

    void __sanitizer_report_error_summary(const char* error_summary)
    {
        _ZN11__sanitizer6PrintfEPKcz(error_summary);

        static bool doubleSANCalled = false;
        if (doubleSANCalled)
        {
            abort();
        }
        doubleSANCalled = true;

        fuzz_init_wrapper();

        FUZZING_numberOfSanitizerErrors++;

        int stacktraceBufferSize = 256;
        void* stacktrace[stacktraceBufferSize];

        int numberOfFrames = backtrace(stacktrace, stacktraceBufferSize);

        uint64_t stacktraceHash = fuzz_hash_stacktrace(stacktrace, numberOfFrames);

        char crashFilePath[1024];
        snprintf(crashFilePath, 1024, "%s/sanitizer_%lx", FUZZING_crashingInputsDir, stacktraceHash);

        if (access(crashFilePath, F_OK) != -1)
        {
            // crashFilePath exists already
            if (FUZZING_numberOfSanitizerErrors % 1000 == 1)
            {
                printf("Stacktrace hash observed previously %s\n", crashFilePath);
                printf("Sanitizer error count: %ld\n", FUZZING_numberOfSanitizerErrors);
            }
            doubleSANCalled = false;
            return;
        }

        fuzz_on_new_sanitizer_error(crashFilePath, numberOfFrames, stacktrace, stacktraceHash);

        doubleSANCalled = false;
    }

#ifdef __cplusplus
}
#endif
