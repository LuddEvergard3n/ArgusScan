#include "test.h"

int argus_test_failures = 0;

int main(void)
{
    test_checksum();
    test_connect();
    test_engine();
    test_os_detect();
    test_response_classifier();
    test_packet();
    test_capture_frame();
    test_port_list();
    test_service();
    test_thread_pool();
    test_target_parser();

    if (argus_test_failures != 0) {
        fprintf(stderr, "%d test check(s) failed\n", argus_test_failures);
        return 1;
    }

    puts("all unit checks passed");
    return 0;
}
