#include <assert.h>
#include <stdbool.h>
#include <stdio.h>

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

int main(int argc, char* argv[])
{
    int iter = 0;
    while (1)
    {
        iter++;
        if (iter % 10000000 == 1)
        {
            printf("iter: %d\n", iter);
        }

        foo(argc);
        bar(argc);
    }
    return 1;
}
