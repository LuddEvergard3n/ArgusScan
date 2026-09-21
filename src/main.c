#include "engine/port_state.h"
#include "engine/timing.h"

#include <stdio.h>
#include <string.h>

#define ARGUS_VERSION "0.1.0-dev"

static void print_help(const char *program)
{
    printf(
        "ArgusScan %s - educational network reconnaissance engine\n"
        "\n"
        "Usage:\n"
        "  %s --help\n"
        "  %s --version\n"
        "\n"
        "Current milestone:\n"
        "  Core checksums, port states, timing templates and test infrastructure.\n"
        "  Network scanning is not enabled in this build yet.\n"
        "\n"
        "Use only on systems you own or are explicitly authorized to test.\n",
        ARGUS_VERSION,
        program,
        program
    );
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        printf("argusscan %s\n", ARGUS_VERSION);
        return 0;
    }

    if (argc == 1 || (argc == 2 && strcmp(argv[1], "--help") == 0)) {
        print_help(argv[0]);
        return 0;
    }

    fprintf(stderr, "error: scanning commands are not implemented in this milestone\n");
    fprintf(stderr, "try '%s --help'\n", argv[0]);
    return 2;
}

