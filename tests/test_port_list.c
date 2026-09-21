#include "test.h"

#include "engine/port_list.h"

void test_port_list(void)
{
    ArgusPortList list;

    ARGUS_CHECK(argus_port_list_parse("443, 22,80-82,80", &list));
    ARGUS_CHECK(list.count == 5U);
    ARGUS_CHECK(list.ports[0] == 22U);
    ARGUS_CHECK(list.ports[1] == 80U);
    ARGUS_CHECK(list.ports[2] == 81U);
    ARGUS_CHECK(list.ports[3] == 82U);
    ARGUS_CHECK(list.ports[4] == 443U);
    argus_port_list_destroy(&list);

    ARGUS_CHECK(!argus_port_list_parse("0", &list));
    ARGUS_CHECK(!argus_port_list_parse("80-20", &list));
    ARGUS_CHECK(!argus_port_list_parse("65536", &list));
    ARGUS_CHECK(!argus_port_list_parse("22,", &list));
    ARGUS_CHECK(!argus_port_list_parse("ssh", &list));
}

