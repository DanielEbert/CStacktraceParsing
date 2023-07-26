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

    // If an assertion or sanitizer error is found, FUZZING_foundCrash is set to true
    bool FUZZING_foundCrash = false;

    char *FUZZING_crashingInputsDir = NULL;
    uint64_t FUZZING_numberOfAssertionsFailed = 0;
    uint64_t FUZZING_numberOfSanitizerErrors = 0;
    char FUZZING_crashFilePath[1024];

    void __sanitizer_print_stack_trace(void);

    // demangled __sanitizer::Printf(char const*, ...)
    void _ZN11__sanitizer6PrintfEPKcz(const char *format, ...);

    // Based on djb2 hash
    uint64_t fuzzing_hash_stacktrace(void **stacktraceBuffer, int numberOfFrames)
    {
        uint64_t hash = 5381;

        for (int i = 0; i < numberOfFrames; i++)
        {
            hash = ((hash << 5) + hash) ^ (uint64_t)stacktraceBuffer[i];
        }

        return hash;
    }

    void fuzzing_init_wrapper()
    {
        if (FUZZING_crashingInputsDir != NULL)
        {
            return;
        }

        FUZZING_crashingInputsDir = getenv("FUZZING_crashingInputsDir");

        if (FUZZING_crashingInputsDir == NULL)
        {
            write(1, "No environment variable FUZZING_crashingInputsDir set. Using default /tmp.\n", 76);
            FUZZING_crashingInputsDir = (char *)"/tmp";
        }
    }

    void fuzzing_on_new_assertion(char *crashFilePath, const char *__assertion,
                                  int numberOfFrames, void **stacktrace, uint64_t stacktraceHash)
    {
        int fd = open(crashFilePath, O_CREAT | O_EXCL | O_WRONLY, 0644);
        if (fd == -1)
        {
            fprintf(stderr, "Error: Couldn't create crashing input file %s\n", crashFilePath);
            return;
        }

        close(fd);

        // TODO: use this as header to find start of assertion failures and to get assertion reason
        printf("_FUZZING Assertion failed: %s\n", __assertion);

        __sanitizer_print_stack_trace();

        printf("Stacktrace hash: %lx\n", stacktraceHash);

        FUZZING_foundCrash = true;
    }

    void __wrap___assert_fail(const char *__assertion, const char *__file, unsigned int __line, const char *__function)
    {
        static bool doubleAssertCalled = false;
        if (doubleAssertCalled)
        {
            abort();
        }
        doubleAssertCalled = true;

        fuzzing_init_wrapper();

        FUZZING_numberOfAssertionsFailed++;

        int stacktraceBufferSize = 256;
        void *stacktrace[stacktraceBufferSize];

        int numberOfFrames = backtrace(stacktrace, stacktraceBufferSize);

        uint64_t stacktraceHash = fuzzing_hash_stacktrace(stacktrace, numberOfFrames);

        snprintf(FUZZING_crashFilePath, 1024, "%s/assert_%lx", FUZZING_crashingInputsDir, stacktraceHash);

        if (access(FUZZING_crashFilePath, F_OK) != -1)
        {
            // crashFilePath exists already
            if (FUZZING_numberOfAssertionsFailed % 100000 == 1)
            {
                printf("Stacktrace hash observed previously %s\n", FUZZING_crashFilePath);
                printf("Assertion count: %ld\n", FUZZING_numberOfAssertionsFailed);
            }
            doubleAssertCalled = false;
            return;
        }

        fuzzing_on_new_assertion(FUZZING_crashFilePath, __assertion, numberOfFrames, stacktrace, stacktraceHash);

        // requires -rdynamic
        // backtrace_symbols_fd(stacktrace, numberOfFrames, 1);

        // volatile int i = 1;
        // volatile int j = 2;
        // assert(i > 2);

        doubleAssertCalled = false;

        return;
    }

    void fuzzing_on_new_sanitizer_error(char *crashFilePath, int numberOfFrames, void **stacktrace, uint64_t stacktraceHash)
    {
        int fd = open(crashFilePath, O_CREAT | O_EXCL | O_WRONLY, 0644);
        if (fd == -1)
        {
            printf("Error: Couldn't create crashing input file %s\n", crashFilePath);
            return;
        }

        close(fd);

        // printf("_FUZZING SanitizerError\n");

        // printf("_FUZZING Stacktrace: [");

        // for (int i = 0; i < numberOfFrames; i++)
        // {
        //     printf("%p", stacktrace[i]);
        //     if (i != numberOfFrames - 1)
        //     {
        //         printf(", ");
        //     }
        // }
        // printf("]\n");

        // printf("Stacktrace hash: %lx\n", stacktraceHash);

        FUZZING_foundCrash = true;
    }

    void __sanitizer_report_error_summary(const char *error_summary)
    {
        _ZN11__sanitizer6PrintfEPKcz(error_summary);

        static bool doubleSANCalled = false;
        if (doubleSANCalled)
        {
            abort();
        }
        doubleSANCalled = true;

        fuzzing_init_wrapper();

        FUZZING_numberOfSanitizerErrors++;

        int stacktraceBufferSize = 256;
        void *stacktrace[stacktraceBufferSize];

        int numberOfFrames = backtrace(stacktrace, stacktraceBufferSize);

        uint64_t stacktraceHash = fuzzing_hash_stacktrace(stacktrace, numberOfFrames);

        snprintf(FUZZING_crashFilePath, 1024, "%s/sanitizer_%lx", FUZZING_crashingInputsDir, stacktraceHash);

        if (access(FUZZING_crashFilePath, F_OK) != -1)
        {
            // crashFilePath exists already
            if (FUZZING_numberOfSanitizerErrors % 1000 == 1)
            {
                printf("Stacktrace hash observed previously %s\n", FUZZING_crashFilePath);
                printf("Sanitizer error count: %ld\n", FUZZING_numberOfSanitizerErrors);
            }
            doubleSANCalled = false;
            return;
        }

        fuzzing_on_new_sanitizer_error(FUZZING_crashFilePath, numberOfFrames, stacktrace, stacktraceHash);

        doubleSANCalled = false;
    }

#ifdef __cplusplus
}
#endif
