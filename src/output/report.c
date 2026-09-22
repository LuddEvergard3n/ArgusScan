#include "output/report.h"

#include <stdio.h>
#include <string.h>

static void print_json_string(const char *text)
{
    const unsigned char *cursor = (const unsigned char *)text;

    putchar('"');
    while (*cursor != '\0') {
        unsigned char byte = *cursor++;

        switch (byte) {
        case '"':
            fputs("\\\"", stdout);
            break;
        case '\\':
            fputs("\\\\", stdout);
            break;
        case '\b':
            fputs("\\b", stdout);
            break;
        case '\f':
            fputs("\\f", stdout);
            break;
        case '\n':
            fputs("\\n", stdout);
            break;
        case '\r':
            fputs("\\r", stdout);
            break;
        case '\t':
            fputs("\\t", stdout);
            break;
        default:
            if (byte < 0x20U) {
                printf("\\u%04x", (unsigned int)byte);
            } else {
                putchar((int)byte);
            }
            break;
        }
    }
    putchar('"');
}

static void print_xml_text(const char *text)
{
    const char *cursor;

    for (cursor = text; *cursor != '\0'; ++cursor) {
        switch (*cursor) {
        case '&':
            fputs("&amp;", stdout);
            break;
        case '<':
            fputs("&lt;", stdout);
            break;
        case '>':
            fputs("&gt;", stdout);
            break;
        case '"':
            fputs("&quot;", stdout);
            break;
        case '\'':
            fputs("&apos;", stdout);
            break;
        default:
            putchar((unsigned char)*cursor);
            break;
        }
    }
}

static const ArgusFingerprint *first_fingerprint(const ArgusScanReport *report)
{
    size_t index;

    for (index = 0U; index < report->port_count; ++index) {
        if (report->ports[index].has_fingerprint) {
            return &report->ports[index].fingerprint;
        }
    }
    return NULL;
}

static void output_text(const ArgusScanReport *report)
{
    size_t index;

    printf(
        "ArgusScan %s: %s (%s), timing=%s, ports=%zu, duration=%lld ms\n",
        report->scan_type,
        report->target,
        report->target_ip,
        report->timing,
        report->port_count,
        (long long)report->duration_ms
    );
    if (report->has_active_fingerprint) {
        ArgusOsGuess guess = argus_os_guess_active(&report->active_fingerprint);

        printf(
            "OS multiprobe guess: %s (confidence %.2f, signature db %s)\n",
            guess.name,
            guess.confidence,
            guess.signature_db_version
        );
        printf("Active evidence: %s\n", guess.evidence);
    }
    puts("PORT      PROTOCOL STATE          LATENCY");
    for (index = 0U; index < report->port_count; ++index) {
        const ArgusReportPort *port = &report->ports[index];

        printf(
            "%-9u %-8s %-14s %d ms\n",
            (unsigned int)port->port,
            port->protocol,
            argus_port_state_name(port->state),
            port->latency_ms
        );
        if (port->has_fingerprint && !report->has_active_fingerprint) {
            ArgusOsGuess guess = argus_os_guess(&port->fingerprint);
            printf(
                "  OS guess: %s (confidence %.2f, signature db %s)\n",
                guess.name,
                guess.confidence,
                guess.signature_db_version
            );
            printf("  Evidence: %s\n", guess.evidence);
        }
        if (port->has_service) {
            printf(
                "  Service: %s\n",
                port->service.detected ? port->service.service_name : "unknown"
            );
            if (port->service.banner_length != 0U) {
                printf(
                    "  Banner: %s%s\n",
                    port->service.banner_text,
                    port->service.banner_truncated ? " [truncated]" : ""
                );
            }
        }
    }
}

static void output_json(const ArgusScanReport *report)
{
    const ArgusFingerprint *fingerprint = first_fingerprint(report);
    size_t index;

    fputs("{\n  \"target\": ", stdout);
    print_json_string(report->target);
    fputs(",\n  \"target_ip\": ", stdout);
    print_json_string(report->target_ip);
    fputs(",\n  \"scan_type\": ", stdout);
    print_json_string(report->scan_type);
    fputs(",\n  \"timing\": ", stdout);
    print_json_string(report->timing);
    fputs(",\n  \"started_at\": ", stdout);
    print_json_string(report->started_at);
    printf(",\n  \"duration_ms\": %lld,\n", (long long)report->duration_ms);

    if (report->has_active_fingerprint) {
        ArgusOsGuess guess = argus_os_guess_active(&report->active_fingerprint);

        fputs("  \"os_guess\": {\"name\": ", stdout);
        print_json_string(guess.name);
        printf(", \"confidence\": %.2f, \"signature_db_version\": ", guess.confidence);
        print_json_string(guess.signature_db_version);
        fputs(", \"probe_mode\": \"active-multiprobe\", \"evidence\": [", stdout);
        print_json_string(guess.evidence);
        fputs("]},\n", stdout);
    } else if (fingerprint == NULL) {
        fputs("  \"os_guess\": null,\n", stdout);
    } else {
        ArgusOsGuess guess = argus_os_guess(fingerprint);
        fputs("  \"os_guess\": {\"name\": ", stdout);
        print_json_string(guess.name);
        printf(", \"confidence\": %.2f, \"signature_db_version\": ", guess.confidence);
        print_json_string(guess.signature_db_version);
        fputs(", \"evidence\": [", stdout);
        print_json_string(guess.evidence);
        fputs("]},\n", stdout);
    }

    fputs("  \"ports\": [\n", stdout);
    for (index = 0U; index < report->port_count; ++index) {
        const ArgusReportPort *port = &report->ports[index];

        printf("    {\"port\": %u, \"state\": ", (unsigned int)port->port);
        print_json_string(argus_port_state_name(port->state));
        fputs(", \"protocol\": ", stdout);
        print_json_string(port->protocol);
        printf(", \"latency_ms\": %d, \"service\": ", port->latency_ms);
        if (port->has_service && port->service.detected) {
            print_json_string(port->service.service_name);
        } else {
            fputs("null", stdout);
        }
        fputs(", \"banner\": ", stdout);
        if (port->has_service && port->service.banner_length != 0U) {
            print_json_string(port->service.banner_text);
        } else {
            fputs("null", stdout);
        }
        fputs("}", stdout);
        fputs(index + 1U == report->port_count ? "\n" : ",\n", stdout);
    }
    fputs("  ]\n}\n", stdout);
}

static void output_xml(const ArgusScanReport *report)
{
    const ArgusFingerprint *fingerprint = first_fingerprint(report);
    size_t index;

    fputs("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<argusscan>\n  <target name=\"", stdout);
    print_xml_text(report->target);
    fputs("\" address=\"", stdout);
    print_xml_text(report->target_ip);
    fputs("\" />\n  <scan type=\"", stdout);
    print_xml_text(report->scan_type);
    fputs("\" timing=\"", stdout);
    print_xml_text(report->timing);
    fputs("\" started-at=\"", stdout);
    print_xml_text(report->started_at);
    printf("\" duration-ms=\"%lld\" />\n", (long long)report->duration_ms);

    if (report->has_active_fingerprint || fingerprint != NULL) {
        ArgusOsGuess guess = report->has_active_fingerprint
            ? argus_os_guess_active(&report->active_fingerprint)
            : argus_os_guess(fingerprint);
        fputs("  <os-guess name=\"", stdout);
        print_xml_text(guess.name);
        printf("\" confidence=\"%.2f\" signature-db-version=\"", guess.confidence);
        print_xml_text(guess.signature_db_version);
        if (report->has_active_fingerprint) {
            fputs("\" probe-mode=\"active-multiprobe", stdout);
        }
        fputs("\"><evidence>", stdout);
        print_xml_text(guess.evidence);
        fputs("</evidence></os-guess>\n", stdout);
    }

    fputs("  <ports>\n", stdout);
    for (index = 0U; index < report->port_count; ++index) {
        const ArgusReportPort *port = &report->ports[index];

        printf("    <port number=\"%u\" protocol=\"", (unsigned int)port->port);
        print_xml_text(port->protocol);
        fputs("\" state=\"", stdout);
        print_xml_text(argus_port_state_name(port->state));
        printf("\" latency-ms=\"%d\">", port->latency_ms);
        if (port->has_service) {
            fputs("<service name=\"", stdout);
            print_xml_text(port->service.detected ? port->service.service_name : "unknown");
            fputs("\">", stdout);
            if (port->service.banner_length != 0U) {
                fputs("<banner>", stdout);
                print_xml_text(port->service.banner_text);
                fputs("</banner>", stdout);
            }
            fputs("</service>", stdout);
        }
        fputs("</port>\n", stdout);
    }
    fputs("  </ports>\n</argusscan>\n", stdout);
}

bool argus_output_format_parse(const char *text, ArgusOutputFormat *format)
{
    if (text == NULL || format == NULL) {
        return false;
    }
    if (strcmp(text, "text") == 0) {
        *format = ARGUS_OUTPUT_TEXT;
        return true;
    }
    if (strcmp(text, "json") == 0) {
        *format = ARGUS_OUTPUT_JSON;
        return true;
    }
    if (strcmp(text, "xml") == 0) {
        *format = ARGUS_OUTPUT_XML;
        return true;
    }
    return false;
}

void argus_output_report(const ArgusScanReport *report, ArgusOutputFormat format)
{
    if (report == NULL) {
        return;
    }
    if (format == ARGUS_OUTPUT_JSON) {
        output_json(report);
    } else if (format == ARGUS_OUTPUT_XML) {
        output_xml(report);
    } else {
        output_text(report);
    }
}
