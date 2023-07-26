all:
	g++ target.c obtain.c -Wl,--wrap=__assert_fail -fsanitize=address,undefined -static-libasan -g -O0 -o target && LD_PRELOAD=/home/user/P/LibAFL/utils/noaslr/target/release/libnoaslr.so UBSAN_OPTIONS=print_summary=1:print_stacktrace=1 FUZZING_crashingInputsDir=/tmp ./target
