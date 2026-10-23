#include "lab.h"
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef TEST
#define main main_exclude
#endif

/* Keep the usage text identical for help output and command-line errors. */
static void print_usage(FILE *out) {
  (void)fprintf(out,
                "Usage: myapp info <address>/<prefix>\n"
                "       myapp split <network>/<prefix> <count>\n"
                "       myapp lookup <table-file> <address>...\n");
}

static int report_bad_command(const char *message) {
  (void)fprintf(stderr, "myapp: %s\n", message);
  print_usage(stderr);
  return 1;
}

static int command_info(const char *text) {
  cidr_t block;
  if (!cidr_parse(text, &block)) {
    (void)fprintf(stderr, "myapp: '%s' is not a valid address/prefix\n", text);
    return 1;
  }

  char address[IP_STR_LEN];
  char netmask[IP_STR_LEN];
  char network[IP_STR_LEN];
  char broadcast[IP_STR_LEN];
  char first_host[IP_STR_LEN];
  char last_host[IP_STR_LEN];
  char prefix[5];

  /* Derive each displayed value from the parsed address and prefix. */
  ip_format(block.addr, address);
  ip_format(cidr_mask(block.prefix), netmask);
  ip_format(cidr_network(block), network);
  ip_format(cidr_broadcast(block), broadcast);
  ip_format(cidr_first_host(block), first_host);
  ip_format(cidr_last_host(block), last_host);
  (void)snprintf(prefix, sizeof(prefix), "/%u", (unsigned int)block.prefix);

  (void)printf("%-10s %s\n", "address", address);
  (void)printf("%-10s %s\n", "prefix", prefix);
  (void)printf("%-10s %s\n", "netmask", netmask);
  (void)printf("%-10s %s\n", "network", network);
  (void)printf("%-10s %s\n", "broadcast", broadcast);
  (void)printf("%-10s %s\n", "first host", first_host);
  (void)printf("%-10s %s\n", "last host", last_host);
  (void)printf("%-10s %" PRIu64 "\n", "hosts", cidr_host_count(block));
  return 0;
}

static bool parse_count(const char *text, uint32_t *count) {
  if (text == NULL || *text == '\0') {
    return false;
  }
  for (const char *p = text; *p != '\0'; ++p) {
    if (*p < '0' || *p > '9') {
      return false;
    }
  }

  /* Check conversion overflow as well as rejecting trailing characters. */
  errno = 0;
  char *end = NULL;
  unsigned long long value = strtoull(text, &end, 10);
  if (errno == ERANGE || end == text || *end != '\0' ||
      value > UINT32_MAX) {
    return false;
  }
  *count = (uint32_t)value;
  return true;
}

static int command_split(const char *text, const char *count_text) {
  cidr_t block;
  uint32_t count;
  if (!cidr_parse(text, &block)) {
    (void)fprintf(stderr, "myapp: '%s' is not a valid network/prefix\n", text);
    return 1;
  }
  if (!cidr_is_network(block)) {
    (void)fprintf(stderr, "myapp: '%s' has host bits set; expected a network\n",
                  text);
    return 1;
  }
  if (!parse_count(count_text, &count) || count == 0 ||
      (count & (count - 1U)) != 0) {
    (void)fprintf(stderr, "myapp: '%s' is not a positive power-of-two count\n",
                  count_text);
    return 1;
  }

  cidr_t subnet;
  /* Validate that this count can be represented by equal subnets up front. */
  if (!cidr_subnet(block, count, 0, &subnet)) {
    (void)fprintf(stderr,
                  "myapp: cannot split %s into %" PRIu32 " subnets\n",
                  text, count);
    return 1;
  }

  /* cidr_subnet orders results from the lowest subnet address upward. */
  for (uint32_t i = 0; i < count; ++i) {
    (void)cidr_subnet(block, count, i, &subnet);
    char formatted[CIDR_STR_LEN];
    cidr_format(subnet, formatted);
    (void)puts(formatted);
  }
  return 0;
}

static int command_lookup(const char *path, int address_count,
                          char *const addresses[]) {
  FILE *input = fopen(path, "r");
  if (input == NULL) {
    (void)fprintf(stderr, "myapp: cannot open '%s': %s\n", path,
                  strerror(errno));
    return 2;
  }

  fwd_table_t *table = table_create();
  if (table == NULL) {
    (void)fprintf(stderr, "myapp: cannot allocate forwarding table\n");
    (void)fclose(input);
    return 2;
  }

  size_t bad_line = 0;
  /* Do not begin lookups if the forwarding table is incomplete or invalid. */
  if (!table_load(table, input, &bad_line)) {
    if (bad_line != 0) {
      (void)fprintf(stderr, "myapp: %s:%zu: not a valid route\n", path,
                    bad_line);
    } else {
      (void)fprintf(stderr, "myapp: failed reading table '%s'\n", path);
    }
    table_destroy(table);
    (void)fclose(input);
    return 2;
  }
  (void)fclose(input);

  bool malformed = false;
  bool unreachable = false;
  /* Process every address so one bad input does not hide the other results. */
  for (int i = 0; i < address_count; ++i) {
    uint32_t address;
    if (!ip_parse(addresses[i], &address)) {
      (void)fprintf(stderr, "myapp: '%s' is not a valid address\n",
                    addresses[i]);
      malformed = true;
      continue;
    }

    const route_t *route = table_lookup(table, address);
    if (route == NULL) {
      (void)printf("%s unreachable\n", addresses[i]);
      unreachable = true;
      continue;
    }

    (void)printf("%s", addresses[i]);
    if (route->gateway != 0) {
      char gateway[IP_STR_LEN];
      ip_format(route->gateway, gateway);
      (void)printf(" via %s", gateway);
    }
    (void)printf(" dev %s\n", route->dev);
  }

  table_destroy(table);
  /* A malformed address takes precedence over an otherwise valid no-route. */
  if (malformed) {
    return 1;
  }
  return unreachable ? 3 : 0;
}

int main(int argc, char **argv) {
  /* No-argument invocation is a successful way to display help. */
  if (argc == 1) {
    print_usage(stdout);
    return 0;
  }
  /* Dispatch only after checking each command's exact argument count. */
  if (strcmp(argv[1], "info") == 0) {
    if (argc != 3) {
      return report_bad_command("info requires exactly one address/prefix");
    }
    return command_info(argv[2]);
  }
  if (strcmp(argv[1], "split") == 0) {
    if (argc != 4) {
      return report_bad_command("split requires a network/prefix and count");
    }
    return command_split(argv[2], argv[3]);
  }
  if (strcmp(argv[1], "lookup") == 0) {
    if (argc < 4) {
      return report_bad_command("lookup requires a table file and addresses");
    }
    return command_lookup(argv[2], argc - 3, &argv[3]);
  }
  return report_bad_command("unknown command");
}
