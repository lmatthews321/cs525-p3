#include "lab.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define TRIE_INDEX_NONE UINT32_MAX
#define TRIE_INITIAL_CAPACITY 8

typedef struct {
  uint32_t child[2];
  uint32_t route_index;
} trie_node_t;

struct fwd_table {
  route_t *routes;
  size_t count;
  size_t capacity;
  trie_node_t *trie;
  size_t trie_count;
  size_t trie_capacity;
};

bool ip_parse(const char *text, uint32_t *addr) {
  if (text == NULL || addr == NULL) {
    return false;
  }

  /* Build the host-order address one octet at a time. */
  uint32_t result = 0;
  const char *p = text;

  for (unsigned int octet = 0; octet < 4; ++octet) {
    if (*p == '\0') {
      return false;
    }

    unsigned int value = 0;
    unsigned int digits = 0;
    while (*p >= '0' && *p <= '9') {
      unsigned int digit = (unsigned int)(*p - '0');
      /* Check the limit before multiplying, so long input cannot wrap. */
      if (value > 255U / 10U || (value == 255U / 10U && digit > 255U % 10U)) {
        return false;
      }
      value = value * 10U + digit;
      ++digits;
      ++p;
    }

    /* Only one-digit zero is allowed; "0", not "00" or "010". */
    if (digits == 0 || (digits > 1 && *(p - digits) == '0')) {
      return false;
    }

    /* Each successful octet becomes the next most-significant byte. */
    result = (result << 8) | value;
    if (octet < 3) {
      if (*p != '.') {
        return false;
      }
      ++p;
      if (*p == '\0') {
        return false;
      }
    } else if (*p != '\0') {
      return false;
    }
  }

  *addr = result;
  return true;
}

void ip_format(uint32_t addr, char out[IP_STR_LEN]) {
  /* Extract bytes from most significant to least significant. */
  (void)snprintf(out, IP_STR_LEN, "%u.%u.%u.%u",
                 (unsigned int)((addr >> 24) & 0xffU),
                 (unsigned int)((addr >> 16) & 0xffU),
                 (unsigned int)((addr >> 8) & 0xffU),
                 (unsigned int)(addr & 0xffU));
}

bool cidr_parse(const char *text, cidr_t *block) {
  if (text == NULL || block == NULL) {
    return false;
  }

  const char *slash = strchr(text, '/');
  /* Exactly one slash is required. */
  if (slash == NULL || strchr(slash + 1, '/') != NULL) {
    return false;
  }

  /* Copy the address portion so ip_parse() receives a complete C string. */
  size_t address_length = (size_t)(slash - text);
  char address[IP_STR_LEN];
  if (address_length == 0 || address_length >= sizeof(address)) {
    return false;
  }
  memcpy(address, text, address_length);
  address[address_length] = '\0';

  uint32_t addr;
  if (!ip_parse(address, &addr)) {
    return false;
  }

  const char *p = slash + 1;
  if (*p == '\0') {
    return false;
  }
  unsigned int prefix = 0;
  /* /0 is valid, but multi-digit prefixes cannot have a leading zero. */
  if (*p == '0' && *(p + 1) >= '0' && *(p + 1) <= '9') {
    return false;
  }
  while (*p >= '0' && *p <= '9') {
    unsigned int digit = (unsigned int)(*p - '0');
    prefix = prefix * 10U + digit;
    ++p;
    if (prefix > 32U) {
      return false;
    }
  }
  if (p == slash + 1 || *p != '\0') {
    return false;
  }

  cidr_t parsed = {addr, (uint8_t)prefix};
  *block = parsed;
  return true;
}

void cidr_format(cidr_t block, char out[CIDR_STR_LEN]) {
  char address[IP_STR_LEN];
  ip_format(block.addr, address);
  unsigned int prefix = block.prefix;
  /* Match cidr_mask(): prefixes above 32 are represented as /32. */
  if (prefix > 32U) {
    prefix = 32U;
  }
  (void)snprintf(out, CIDR_STR_LEN, "%s/%u", address, prefix);
}

uint32_t cidr_mask(uint8_t prefix) {
  /* Avoid the undefined shift-by-32 produced by a /0 formula. */
  if (prefix == 0) {
    return 0;
  }
  /* Larger prefixes are treated as /32 throughout the API. */
  if (prefix > 32) {
    prefix = 32;
  }
  return UINT32_MAX << (32U - (uint32_t)prefix);
}

uint32_t cidr_network(cidr_t block) {
  /* Clearing with the mask retains only the network portion. */
  return block.addr & cidr_mask(block.prefix);
}

uint32_t cidr_broadcast(cidr_t block) {
  return cidr_network(block) | ~cidr_mask(block.prefix);
}

uint32_t cidr_first_host(cidr_t block) {
  uint32_t prefix = block.prefix > 32 ? 32U : block.prefix;
  uint32_t network = cidr_network(block);
  /* /31 and /32 have no excluded network address. */
  return prefix < 31 ? network + 1U : network;
}

uint32_t cidr_last_host(cidr_t block) {
  uint32_t prefix = block.prefix > 32 ? 32U : block.prefix;
  uint32_t broadcast = cidr_broadcast(block);
  /* /31 and /32 use the broadcast address as a usable endpoint. */
  return prefix < 31 ? broadcast - 1U : broadcast;
}

uint64_t cidr_host_count(cidr_t block) {
  uint32_t prefix = block.prefix > 32 ? 32U : block.prefix;
  /* Handle the point-to-point and single-host cases explicitly. */
  if (prefix == 32) {
    return 1;
  }
  if (prefix == 31) {
    return 2;
  }
  /* Compute in 64 bits because a /0 contains 2^32 addresses. */
  return (UINT64_C(1) << (32U - prefix)) - 2U;
}

bool cidr_contains(cidr_t block, uint32_t addr) {
  /* Masking both sides removes the bits that the block does not own. */
  return cidr_network(block) == (addr & cidr_mask(block.prefix));
}

bool cidr_is_network(cidr_t block) {
  /* Host bits are absent exactly when the network address is unchanged. */
  return cidr_network(block) == block.addr;
}

bool cidr_subnet(cidr_t block, uint32_t n, uint32_t i, cidr_t *out) {
  /* A size must be both nonzero and an exact power of two. */
  if (out == NULL || !cidr_is_network(block) || n == 0 || (n & (n - 1)) != 0 || i >= n) {
    return false;
  }

  /* Find log2(n), the number of host bits borrowed from the block. */
  uint32_t borrowed_bits = 0;
  uint32_t remaining = n;
  while (remaining > 1) {
    ++borrowed_bits;
    remaining >>= 1;
  }

  uint32_t prefix = block.prefix > 32 ? 32U : block.prefix;
  if (prefix + borrowed_bits > 32) {
    return false;
  }

  uint32_t new_prefix = prefix + borrowed_bits;
  uint32_t host_bits = 32U - new_prefix;
  /* Each index advances by one equally sized subnet. */
  uint64_t subnet_size = UINT64_C(1) << host_bits;
  uint32_t subnet_address = (uint32_t)(block.addr + i * subnet_size);

  out->addr = subnet_address;
  out->prefix = (uint8_t)new_prefix;
  return true;
}

bool route_parse(const char *line, route_t *route) {
  if (line == NULL || route == NULL) {
    return false;
  }

  /* Trim outer whitespace, then keep field slices inside the original line. */
  const char *begin = line;
  while (*begin != '\0' && isspace((unsigned char)*begin)) {
    ++begin;
  }
  const char *end = line + strlen(line);
  while (end > begin && isspace((unsigned char)end[-1])) {
    --end;
  }
  if (begin == end) {
    return false;
  }

  const char *fields[3];
  size_t lengths[3];
  const char *cursor = begin;
  for (size_t i = 0; i < 3; ++i) {
    while (cursor < end && (*cursor == ' ' || *cursor == '\t')) {
      ++cursor;
    }
    if (cursor == end) {
      return false;
    }

    fields[i] = cursor;
    while (cursor < end && *cursor != ' ' && *cursor != '\t') {
      if (isspace((unsigned char)*cursor)) {
        return false;
      }
      ++cursor;
    }
    lengths[i] = (size_t)(cursor - fields[i]);
  }

  if (cursor != end) {
    return false;
  }

  route_t parsed = {0};
  /* Parse into a temporary so invalid input never partially changes route. */
  if (lengths[0] == sizeof("default") - 1 &&
      memcmp(fields[0], "default", sizeof("default") - 1) == 0) {
    parsed.dest = (cidr_t){0, 0};
  } else {
    char destination[CIDR_STR_LEN];
    if (lengths[0] >= sizeof(destination)) {
      return false;
    }
    memcpy(destination, fields[0], lengths[0]);
    destination[lengths[0]] = '\0';
    if (!cidr_parse(destination, &parsed.dest) ||
        !cidr_is_network(parsed.dest)) {
      return false;
    }
  }

  if (lengths[1] == sizeof("direct") - 1 &&
      memcmp(fields[1], "direct", sizeof("direct") - 1) == 0) {
    /* Directly connected routes have no next-hop address. */
    parsed.gateway = 0;
  } else {
    char gateway[IP_STR_LEN];
    if (lengths[1] >= sizeof(gateway)) {
      return false;
    }
    memcpy(gateway, fields[1], lengths[1]);
    gateway[lengths[1]] = '\0';
    if (!ip_parse(gateway, &parsed.gateway)) {
      return false;
    }
  }

  if (lengths[2] == 0 || lengths[2] >= sizeof(parsed.dev)) {
    return false;
  }
  memcpy(parsed.dev, fields[2], lengths[2]);
  parsed.dev[lengths[2]] = '\0';
  *route = parsed;
  return true;
}

fwd_table_t *table_create(void) {
  fwd_table_t *table = calloc(1, sizeof(*table));
  // GCOVR_EXCL_START
  if (table == NULL) {
    return NULL;
  }
  // GCOVR_EXCL_STOP

  table->trie = malloc(TRIE_INITIAL_CAPACITY * sizeof(*table->trie));
  // GCOVR_EXCL_START
  if (table->trie == NULL) {
    free(table);
    return NULL;
  }
  // GCOVR_EXCL_STOP
  table->trie_capacity = TRIE_INITIAL_CAPACITY;
  table->trie_count = 1;
  table->trie[0] = (trie_node_t){{TRIE_INDEX_NONE, TRIE_INDEX_NONE},
                                  TRIE_INDEX_NONE};
  return table;
}

void table_destroy(fwd_table_t *table) {
  if (table != NULL) {
    free(table->routes);
    free(table->trie);
    free(table);
  }
}

size_t table_count(const fwd_table_t *table) {
  return table == NULL ? 0 : table->count;
}

#ifdef TEST
void table_test_set_count(fwd_table_t *table, size_t count) {
  table->count = count;
}

void table_test_set_trie_count(fwd_table_t *table, size_t count) {
  table->trie_count = count;
}
#endif

bool table_add(fwd_table_t *table, const route_t *route) {
  /* Only canonical networks with a usable, terminated device name are valid. */
  if (table == NULL || route == NULL || route->dest.prefix > 32 ||
      !cidr_is_network(route->dest)) {
    return false;
  }

  size_t dev_length = 0;
  while (dev_length < sizeof(route->dev) && route->dev[dev_length] != '\0') {
    ++dev_length;
  }
  if (dev_length == 0 || dev_length == sizeof(route->dev)) {
    return false;
  }

  if (table->count >= TRIE_INDEX_NONE) {
    return false;
  }

  /* Walk the existing prefix path to detect duplicates and find missing nodes. */
  uint32_t node_index = 0;
  uint32_t depth = 0;
  while (depth < route->dest.prefix) {
    uint32_t bit = (route->dest.addr >> (31U - depth)) & 1U;
    uint32_t child = table->trie[node_index].child[bit];
    if (child == TRIE_INDEX_NONE) {
      break;
    }
    node_index = child;
    ++depth;
  }
  if (depth == route->dest.prefix &&
      table->trie[node_index].route_index != TRIE_INDEX_NONE) {
    return false;
  }

  size_t missing_nodes = (size_t)route->dest.prefix - depth;
  if (missing_nodes > (size_t)TRIE_INDEX_NONE - table->trie_count) {
    return false;
  }
  size_t needed_nodes = table->trie_count + missing_nodes;
  if (needed_nodes > table->trie_capacity) {
    size_t new_capacity = table->trie_capacity;
    while (new_capacity < needed_nodes) {
      // Reaching this capacity requires impractically large trie storage.
      // GCOVR_EXCL_START
      if (new_capacity > (size_t)TRIE_INDEX_NONE / 2) {
        new_capacity = (size_t)TRIE_INDEX_NONE;
        break;
      }
      // GCOVR_EXCL_STOP
      new_capacity *= 2;
    } // GCOVR_EXCL_LINE
    // These overflow guards are unreachable with the table's 32-bit index
    // limits on this 64-bit build.
    // GCOVR_EXCL_START
    if (new_capacity < needed_nodes ||
        new_capacity > SIZE_MAX / sizeof(*table->trie)) {
      return false;
    }
    // GCOVR_EXCL_STOP
    trie_node_t *new_trie =
        realloc(table->trie, new_capacity * sizeof(*table->trie));
    // GCOVR_EXCL_START
    if (new_trie == NULL) {
      return false;
    }
    // GCOVR_EXCL_STOP
    table->trie = new_trie;
    table->trie_capacity = new_capacity;
  } // GCOVR_EXCL_LINE

  if (table->count == table->capacity) {
    /* Grow geometrically to keep repeated additions efficient. */
    size_t new_capacity = table->capacity == 0 ? 8 : table->capacity * 2;
    // The route-count limit prevents this size overflow on this 64-bit build.
    // GCOVR_EXCL_START
    if (new_capacity < table->capacity ||
        new_capacity > SIZE_MAX / sizeof(*table->routes)) {
      return false;
    }
    // GCOVR_EXCL_STOP
    route_t *new_routes =
        realloc(table->routes, new_capacity * sizeof(*table->routes));
    // GCOVR_EXCL_START
    if (new_routes == NULL) {
      return false;
    }
    // GCOVR_EXCL_STOP
    table->routes = new_routes;
    table->capacity = new_capacity;
  }

  /* Create any missing path nodes, then store this route at its prefix node. */
  node_index = 0;
  for (depth = 0; depth < route->dest.prefix; ++depth) {
    uint32_t bit = (route->dest.addr >> (31U - depth)) & 1U;
    uint32_t child = table->trie[node_index].child[bit];
    if (child == TRIE_INDEX_NONE) {
      child = (uint32_t)table->trie_count++;
      table->trie[child] = (trie_node_t){{TRIE_INDEX_NONE, TRIE_INDEX_NONE},
                                         TRIE_INDEX_NONE};
      table->trie[node_index].child[bit] = child;
    }
    node_index = child;
  }

  table->routes[table->count] = *route;
  table->trie[node_index].route_index = (uint32_t)table->count;
  ++table->count;
  return true;
}

bool table_load(fwd_table_t *table, FILE *in, size_t *bad_line) {
  if (bad_line != NULL) {
    *bad_line = 0;
  }
  if (table == NULL || in == NULL) {
    return false;
  }

  char *line = NULL;
  size_t capacity = 0;
  size_t line_number = 0;
  ssize_t length;
  /* getline handles arbitrarily long input lines without a fixed-size limit. */
  while ((length = getline(&line, &capacity, in)) != -1) {
    ++line_number;
    if (memchr(line, '\0', (size_t)length) != NULL) {
      if (bad_line != NULL) {
        *bad_line = line_number;
      }
      free(line);
      return false;
    }
    char *comment = memchr(line, '#', (size_t)length);
    if (comment != NULL) {
      /* Strip comments before deciding whether this line contains a route. */
      *comment = '\0';
    }

    const char *content = line;
    while (*content != '\0' && isspace((unsigned char)*content)) {
      ++content;
    }
    if (*content == '\0') {
      continue;
    }

    route_t route;
    /* Keep successfully added earlier routes if this line is invalid. */
    if (!route_parse(line, &route) || !table_add(table, &route)) {
      if (bad_line != NULL) {
        *bad_line = line_number;
      }
      free(line);
      return false;
    }
  }

  free(line);
  /* A read error is distinct from a clean end of file. */
  return feof(in) && !ferror(in);
}

const route_t *table_lookup(const fwd_table_t *table, uint32_t dest) {
  if (table == NULL) {
    return NULL;
  }

  /* Remember each matching route while descending at most 32 address bits. */
  uint32_t route_index = table->trie[0].route_index;
  uint32_t node_index = 0;
  for (uint32_t depth = 0; depth < 32; ++depth) {
    uint32_t bit = (dest >> (31U - depth)) & 1U;
    uint32_t child = table->trie[node_index].child[bit];
    if (child == TRIE_INDEX_NONE) {
      break;
    }
    node_index = child;
    if (table->trie[node_index].route_index != TRIE_INDEX_NONE) {
      route_index = table->trie[node_index].route_index;
    }
  }
  return route_index == TRIE_INDEX_NONE ? NULL : &table->routes[route_index];
}
