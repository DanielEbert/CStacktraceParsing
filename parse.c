#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
    FILE* inputFile = fopen("e2.txt", "r");
    if (!inputFile)
    {
        return 1;
    }

    bool headerFound = false;
    bool stacktraceFound = false;
    uint32_t frameIndex = 0;

    char* line = NULL;

    uint32_t maxLineLength = 512;
    for (int i = 0; i < maxLineLength; i++)
    {
        size_t lineSize = 0;
        if (getline(&line, &lineSize, inputFile) == -1)
        {
            break;
        }

        if (!headerFound)
        {
            bool isASAN = strstr(line, "==ERROR:") != NULL;
            bool isUBSAN = strstr(line, "runtime error:") != NULL;
            if (isASAN || isUBSAN)
            {
                headerFound = true;
            }
            continue;
        }

        char* lineColumn = line;

        while (*lineColumn != '\0' && isspace((unsigned char)*lineColumn))
        {
            lineColumn++;
        }

        // Empty line is stacktrace end
        if (*lineColumn == '\0')
        {
            break;
        }

        stacktraceFound = true;

        void* pc;
        if (sscanf(lineColumn, "#%*u 0x%p", &pc) == 1)
        {
            printf("Worked. PC: %p\n", pc);
        }
        // else
        //{
        //     printf("No stackframe in line %s\n", line);
        // }
    }

    if (stacktraceFound)
    {
        printf("Stacktrace found\n");
    }

    free(line);
}