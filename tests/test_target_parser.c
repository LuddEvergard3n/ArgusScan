#include "test.h"

#include "engine/target_parser.h"

#include <string.h>

void test_target_parser(void)
{
    ArgusTargetList list;
    char error[128];

    ARGUS_CHECK(argus_target_list_parse("192.0.2.4/30", &list, error, sizeof(error)));
    ARGUS_CHECK(list.count == 4U);
    ARGUS_CHECK(strcmp(list.targets[0].numeric, "192.0.2.4") == 0);
    ARGUS_CHECK(strcmp(list.targets[3].numeric, "192.0.2.7") == 0);
    argus_target_list_destroy(&list);

    ARGUS_CHECK(argus_target_list_parse("10.0.0.250-255", &list, error, sizeof(error)));
    ARGUS_CHECK(list.count == 6U);
    ARGUS_CHECK(strcmp(list.targets[0].numeric, "10.0.0.250") == 0);
    ARGUS_CHECK(strcmp(list.targets[5].numeric, "10.0.0.255") == 0);
    argus_target_list_destroy(&list);

    ARGUS_CHECK(argus_target_list_parse("localhost", &list, error, sizeof(error)));
    ARGUS_CHECK(list.count == 1U);
    ARGUS_CHECK(strcmp(list.targets[0].numeric, "127.0.0.1") == 0);
    argus_target_list_destroy(&list);

    ARGUS_CHECK(!argus_target_list_parse("192.0.2.0/19", &list, error, sizeof(error)));
    ARGUS_CHECK(strstr(error, "limit") != NULL);
    ARGUS_CHECK(!argus_target_list_parse("10.0.0.20-10", &list, error, sizeof(error)));
}

