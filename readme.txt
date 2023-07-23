- assert wrapping fails due to no return and that causes issues if optimizations occur with no_return
    - can result in false positives, in stacktrace dedup blacklist if __asan_handle_no_return 
        - __asan_handle_no_return  is not in /lib so spcial case here
    - could for now just let it in because thats really bad done like that

- have to use noaslr when using multiple cores or when restarting libafl instance. each libafl instance will have
 other stacktrace. but because of fork, for one instance it should stay the same

- one input can hit multiple asserts. maybe even 10000s. in dedup break at *__wrap___assert_fail and 
    continue until exit, each time hitting breakpoing checking backtrace and obtaining stacktrace from it
    - with timeout in case we hit 10000s
    - could be fixed with extra func in wrap assert that checks for file or in hashmap if new hash

- obtaining might hit timeout not due to real timeout, but due to printing so much

- export UBSAN_OPTIONS=print_summary=1 is important

- add -fsanitize-recover=address

- TODO: need to know reason for error. could write that info also in file TLV encoded
    - could write that to global var and then read that at breakpoint via gdb
    - 
