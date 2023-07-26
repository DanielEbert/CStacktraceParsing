#include <assert.h>
#include <stdbool.h>
#include <stdio.h>

extern bool FUZZING_foundCrash;
extern char FUZZING_crashFilePath[1024];

int foo(int argc)
{
    assert(argc > 10);
    return 1;
    volatile int arr = 2147483547;
    // doesnt work: assert(false);
    return arr + 2000;
}

int bar(int argc)
{
    assert(argc > 10);
    return 1;
    volatile int arr = 2147483547;
    // doesnt work: assert(false);
    return arr + 2000;
}

int main(int argc, char *argv[])
{
    int iter = 0;
    while (1)
    {
        FUZZING_foundCrash = false;
        iter++;
        if (iter % 10000000 == 1)
        {
            printf("iter: %d\n", iter);
        }

        foo(argc);
        bar(argc);

        if (FUZZING_foundCrash)
        {
            printf("FOUND CRASH %s\n", FUZZING_crashFilePath);
        }
    }
    return 1;
}
