#include "engine/port_list.h"
#include "engine/timing.h"
#include "net/target_resolver.h"
#include "scan/connect_engine.h"

#include <stdlib.h>
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
        "  %s --scan tcp-connect --ports PORTS [--timing PROFILE] TARGET\n"
        "\n"
        "Examples:\n"
        "  %s --scan tcp-connect --ports 22,80,443 --timing normal 127.0.0.1\n"
        "  %s --scan tcp-connect --ports 1-1024 localhost\n"
        "\n"
        "Timing profiles:\n"
        "  paranoid, sneaky, polite, normal, aggressive, insane\n"
        "\n"
        "Implemented scan types:\n"
        "  tcp-connect\n"
        "\n"
        "Use only on systems you own or are explicitly authorized to test.\n",
        ARGUS_VERSION,
        program,
        program,
        program,
        program,
        program
    );
}

static int run_connect_scan(
    const char *target_name,
    const char *port_text,
    ArgusTimingTemplate timing_template
)
{
    ArgusTimingConfig timing;
    ArgusIPv4Target target;
    ArgusPortList ports;
    ArgusConnectResult *results;
    size_t index;

    if (!argus_port_list_parse(port_text, &ports)) {
        fprintf(stderr, "error: invalid port list '%s'\n", port_text);
        return 2;
    }
    if (!argus_resolve_ipv4(target_name, &target)) {
        fprintf(stderr, "error: could not resolve IPv4 target '%s'\n", target_name);
        argus_port_list_destroy(&ports);
        return 2;
    }
    if (!argus_timing_config(timing_template, &timing)) {
        argus_port_list_destroy(&ports);
        return 2;
    }

    results = calloc(ports.count, sizeof(*results));
    if (results == NULL) {
        fprintf(stderr, "error: could not allocate scan results\n");
        argus_port_list_destroy(&ports);
        return 1;
    }

    printf(
        "ArgusScan tcp-connect: %s (%s), timing=%s, ports=%zu\n",
        target_name,
        target.numeric,
        argus_timing_name(timing_template),
        ports.count
    );
    if (!argus_tcp_connect_scan(&target, &ports, &timing, results)) {
        fprintf(stderr, "error: scan engine could not complete the work queue\n");
        free(results);
        argus_port_list_destroy(&ports);
        return 1;
    }

    puts("PORT      STATE          LATENCY");
    for (index = 0U; index < ports.count; ++index) {
        printf(
            "%-9u %-14s %d ms\n",
            (unsigned int)results[index].port,
            argus_port_state_name(results[index].state),
            results[index].latency_ms
        );
    }

    free(results);
    argus_port_list_destroy(&ports);
    return 0;
}

int main(int argc, char **argv)
{
    const char *scan_type = NULL;
    const char *port_text = NULL;
    const char *target_name = NULL;
    ArgusTimingTemplate timing = ARGUS_TIMING_NORMAL;
    int index;

    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        printf("argusscan %s\n", ARGUS_VERSION);
        return 0;
    }

    if (argc == 1 || (argc == 2 && strcmp(argv[1], "--help") == 0)) {
        print_help(argv[0]);
        return 0;
    }

    for (index = 1; index < argc; ++index) {
        if (strcmp(argv[index], "--scan") == 0 && index + 1 < argc) {
            scan_type = argv[++index];
        } else if (strcmp(argv[index], "--ports") == 0 && index + 1 < argc) {
            port_text = argv[++index];
        } else if (strcmp(argv[index], "--timing") == 0 && index + 1 < argc) {
            if (!argus_timing_parse(argv[++index], &timing)) {
                fprintf(stderr, "error: unknown timing profile '%s'\n", argv[index]);
                return 2;
            }
        } else if (argv[index][0] == '-') {
            fprintf(stderr, "error: unknown or incomplete option '%s'\n", argv[index]);
            return 2;
        } else if (target_name == NULL) {
            target_name = argv[index];
        } else {
            fprintf(stderr, "error: more than one target was provided\n");
            return 2;
        }
    }

    if (scan_type == NULL || port_text == NULL || target_name == NULL) {
        fprintf(stderr, "error: --scan, --ports and one target are required\n");
        fprintf(stderr, "try '%s --help'\n", argv[0]);
        return 2;
    }
    if (strcmp(scan_type, "tcp-connect") != 0) {
        fprintf(stderr, "error: scan type '%s' is not implemented yet\n", scan_type);
        return 2;
    }

    return run_connect_scan(target_name, port_text, timing);
}
