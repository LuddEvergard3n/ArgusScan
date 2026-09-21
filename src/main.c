#include "engine/port_list.h"
#include "engine/target_parser.h"
#include "engine/timing.h"
#include "fingerprint/service_detect.h"
#include "net/raw_socket.h"
#include "net/target_resolver.h"
#include "output/report.h"
#include "scan/connect_engine.h"
#include "scan/raw_tcp.h"
#include "scan/udp.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define ARGUS_VERSION "0.1.0-dev"

static void print_help(const char *program)
{
    printf(
        "ArgusScan %s - educational network reconnaissance engine\n"
        "\n"
        "Usage:\n"
        "  %s --help\n"
        "  %s --version\n"
        "  %s --check-raw\n"
        "  %s --scan TYPE --ports PORTS [--timing PROFILE] [--services] [--output FORMAT] TARGET\n"
        "\n"
        "Examples:\n"
        "  %s --scan tcp-connect --ports 22,80,443 --timing normal 127.0.0.1\n"
        "  %s --scan tcp-connect --ports 1-1024 localhost\n"
        "  %s --scan tcp-connect --ports 80 192.168.1.0/24\n"
        "\n"
        "Timing profiles:\n"
        "  paranoid, sneaky, polite, normal, aggressive, insane\n"
        "Output formats:\n"
        "  text, json, xml\n"
        "\n"
        "Implemented scan types:\n"
        "  tcp-connect, syn, fin, null, xmas, ack, window, udp\n"
        "\n"
        "Use only on systems you own or are explicitly authorized to test.\n",
        ARGUS_VERSION,
        program,
        program,
        program,
        program,
        program,
        program,
        program
    );
}

static int64_t monotonic_ms(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0;
    }
    return (int64_t)now.tv_sec * 1000 + (int64_t)now.tv_nsec / 1000000;
}

static void utc_timestamp(char *output, size_t output_capacity)
{
    time_t current = time(NULL);
    struct tm broken_down;

    if (gmtime_r(&current, &broken_down) == NULL ||
        strftime(output, output_capacity, "%Y-%m-%dT%H:%M:%SZ", &broken_down) == 0U) {
        if (output_capacity != 0U) {
            output[0] = '\0';
        }
    }
}

static int check_raw_access(const char *program, bool announce_success)
{
    ArgusRawSocket socket_state;

    if (argus_raw_socket_open(&socket_state)) {
        argus_raw_socket_close(&socket_state);
        if (announce_success) {
            puts("raw socket access: available");
        }
        return 0;
    }

    fprintf(stderr, "raw socket access: unavailable (system error %d)\n", socket_state.error_code);
    fprintf(stderr, "SYN/FIN/NULL/XMAS/ACK/Window/UDP raw scans require CAP_NET_RAW.\n");
    fprintf(stderr, "  Option 1: run as root in an authorized lab\n");
    fprintf(stderr, "  Option 2: sudo setcap cap_net_raw+ep %s\n", program);
    fprintf(stderr, "  Option 3: use --scan tcp-connect (no raw privilege required)\n");
    return 1;
}

static bool detect_service(
    struct in_addr address,
    uint16_t port,
    int timeout_ms,
    ArgusServiceResult *service
)
{
    return argus_service_detect_ipv4(address, port, timeout_ms, service);
}

static int run_connect_scan(
    const char *target_name,
    const char *port_text,
    ArgusTimingTemplate timing_template,
    bool detect_services,
    ArgusOutputFormat output_format
)
{
    ArgusTimingConfig timing;
    ArgusIPv4Target target;
    ArgusPortList ports;
    ArgusConnectResult *results;
    ArgusReportPort *report_ports;
    ArgusScanReport report;
    char started_at[32];
    int64_t started_ms;
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
    report_ports = calloc(ports.count, sizeof(*report_ports));
    if (results == NULL || report_ports == NULL) {
        fprintf(stderr, "error: could not allocate scan results\n");
        free(report_ports);
        free(results);
        argus_port_list_destroy(&ports);
        return 1;
    }

    utc_timestamp(started_at, sizeof(started_at));
    started_ms = monotonic_ms();
    if (!argus_tcp_connect_scan(&target, &ports, &timing, results)) {
        fprintf(stderr, "error: scan engine could not complete the work queue\n");
        free(report_ports);
        free(results);
        argus_port_list_destroy(&ports);
        return 1;
    }

    for (index = 0U; index < ports.count; ++index) {
        report_ports[index].port = results[index].port;
        report_ports[index].protocol = "tcp";
        report_ports[index].state = results[index].state;
        report_ports[index].latency_ms = results[index].latency_ms;
        if (detect_services && results[index].state == ARGUS_PORT_OPEN) {
            report_ports[index].has_service = detect_service(
                target.address,
                results[index].port,
                timing.initial_rtt_timeout_ms,
                &report_ports[index].service
            );
        }
    }

    report.target = target_name;
    report.target_ip = target.numeric;
    report.scan_type = "tcp-connect";
    report.timing = argus_timing_name(timing_template);
    report.started_at = started_at;
    report.duration_ms = monotonic_ms() - started_ms;
    report.ports = report_ports;
    report.port_count = ports.count;
    argus_output_report(&report, output_format);

    free(report_ports);
    free(results);
    argus_port_list_destroy(&ports);
    return 0;
}

static int run_raw_scan(
    const char *program,
    const char *target_name,
    const char *port_text,
    ArgusTimingTemplate timing_template,
    ArgusRawTcpScanType scan_type,
    bool detect_services,
    ArgusOutputFormat output_format
)
{
    ArgusTimingConfig timing;
    ArgusIPv4Target target;
    ArgusPortList ports;
    ArgusRawTcpResult *results;
    ArgusReportPort *report_ports;
    ArgusScanReport report;
    char started_at[32];
    char error[256];
    int64_t started_ms;
    size_t index;

    if (check_raw_access(program, false) != 0) {
        return 1;
    }
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
    report_ports = calloc(ports.count, sizeof(*report_ports));
    if (results == NULL || report_ports == NULL) {
        fprintf(stderr, "error: could not allocate scan results\n");
        free(report_ports);
        free(results);
        argus_port_list_destroy(&ports);
        return 1;
    }

    utc_timestamp(started_at, sizeof(started_at));
    started_ms = monotonic_ms();
    if (!argus_raw_tcp_scan(
            &target,
            &ports,
            &timing,
            scan_type,
            results,
            error,
            sizeof(error)
        )) {
        fprintf(stderr, "error: %s\n", error[0] == '\0' ? "raw scan failed" : error);
        free(report_ports);
        free(results);
        argus_port_list_destroy(&ports);
        return 1;
    }

    for (index = 0U; index < ports.count; ++index) {
        report_ports[index].port = results[index].port;
        report_ports[index].protocol = "tcp";
        report_ports[index].state = results[index].state;
        report_ports[index].latency_ms = results[index].latency_ms;
        report_ports[index].has_fingerprint = results[index].has_fingerprint;
        report_ports[index].fingerprint = results[index].fingerprint;
        if (detect_services && scan_type == ARGUS_SCAN_SYN &&
            results[index].state == ARGUS_PORT_OPEN) {
            report_ports[index].has_service = detect_service(
                target.address,
                results[index].port,
                timing.initial_rtt_timeout_ms,
                &report_ports[index].service
            );
        }
    }

    report.target = target_name;
    report.target_ip = target.numeric;
    report.scan_type = argus_raw_tcp_scan_name(scan_type);
    report.timing = argus_timing_name(timing_template);
    report.started_at = started_at;
    report.duration_ms = monotonic_ms() - started_ms;
    report.ports = report_ports;
    report.port_count = ports.count;
    argus_output_report(&report, output_format);

    free(report_ports);
    free(results);
    argus_port_list_destroy(&ports);
    return 0;
}

static int run_udp_scan(
    const char *program,
    const char *target_name,
    const char *port_text,
    ArgusTimingTemplate timing_template,
    ArgusOutputFormat output_format
)
{
    ArgusTimingConfig timing;
    ArgusIPv4Target target;
    ArgusPortList ports;
    ArgusUdpResult *results;
    ArgusReportPort *report_ports;
    ArgusScanReport report;
    char started_at[32];
    char error[256];
    int64_t started_ms;
    size_t index;

    if (check_raw_access(program, false) != 0) {
        return 1;
    }
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
    report_ports = calloc(ports.count, sizeof(*report_ports));
    if (results == NULL || report_ports == NULL) {
        fprintf(stderr, "error: could not allocate scan results\n");
        free(report_ports);
        free(results);
        argus_port_list_destroy(&ports);
        return 1;
    }

    utc_timestamp(started_at, sizeof(started_at));
    started_ms = monotonic_ms();
    if (!argus_udp_scan(&target, &ports, &timing, results, error, sizeof(error))) {
        fprintf(stderr, "error: %s\n", error[0] == '\0' ? "UDP scan failed" : error);
        free(report_ports);
        free(results);
        argus_port_list_destroy(&ports);
        return 1;
    }

    for (index = 0U; index < ports.count; ++index) {
        report_ports[index].port = results[index].port;
        report_ports[index].protocol = "udp";
        report_ports[index].state = results[index].state;
        report_ports[index].latency_ms = results[index].latency_ms;
    }

    report.target = target_name;
    report.target_ip = target.numeric;
    report.scan_type = "udp";
    report.timing = argus_timing_name(timing_template);
    report.started_at = started_at;
    report.duration_ms = monotonic_ms() - started_ms;
    report.ports = report_ports;
    report.port_count = ports.count;
    argus_output_report(&report, output_format);

    free(report_ports);
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
    ArgusOutputFormat output_format = ARGUS_OUTPUT_TEXT;
    bool detect_services = false;
    ArgusRawTcpScanType raw_type = ARGUS_SCAN_SYN;
    bool is_raw_tcp = false;
    ArgusTargetList targets;
    char target_error[160];
    size_t target_index;
    int final_status = 0;
    int index;

    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        printf("argusscan %s\n", ARGUS_VERSION);
        return 0;
    }

    if (argc == 2 && strcmp(argv[1], "--check-raw") == 0) {
        return check_raw_access(argv[0], true);
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
        } else if (strcmp(argv[index], "--services") == 0) {
            detect_services = true;
        } else if (strcmp(argv[index], "--output") == 0 && index + 1 < argc) {
            if (!argus_output_format_parse(argv[++index], &output_format)) {
                fprintf(stderr, "error: unknown output format '%s'\n", argv[index]);
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
    if (strcmp(scan_type, "tcp-connect") != 0 && strcmp(scan_type, "udp") != 0) {
        is_raw_tcp = argus_raw_tcp_scan_parse(scan_type, &raw_type);
        if (!is_raw_tcp) {
            fprintf(stderr, "error: scan type '%s' is not implemented yet\n", scan_type);
            return 2;
        }
    }

    if (!argus_target_list_parse(
            target_name,
            &targets,
            target_error,
            sizeof(target_error)
        )) {
        fprintf(stderr, "error: %s\n", target_error[0] == '\0' ? "invalid target" : target_error);
        return 2;
    }
    if (targets.count > 1U && output_format != ARGUS_OUTPUT_TEXT) {
        fprintf(stderr, "error: multi-target scans currently support text output only\n");
        argus_target_list_destroy(&targets);
        return 2;
    }

    for (target_index = 0U; target_index < targets.count; ++target_index) {
        const char *current_target = targets.count == 1U
            ? target_name
            : targets.targets[target_index].numeric;

        if (strcmp(scan_type, "tcp-connect") == 0) {
            final_status = run_connect_scan(
                current_target,
                port_text,
                timing,
                detect_services,
                output_format
            );
        } else if (strcmp(scan_type, "udp") == 0) {
            final_status = run_udp_scan(
                argv[0],
                current_target,
                port_text,
                timing,
                output_format
            );
        } else {
            final_status = run_raw_scan(
                argv[0],
                current_target,
                port_text,
                timing,
                raw_type,
                detect_services,
                output_format
            );
        }
        if (final_status != 0) {
            break;
        }
    }

    argus_target_list_destroy(&targets);
    return final_status;
}
