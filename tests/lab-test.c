#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "harness/unity.h"
#include "../src/lab.h"

void setUp(void) {}

void tearDown(void) {}

void test_route_parse(void) {
  route_t route = {0};
  TEST_ASSERT_TRUE(route_parse("default\t132.178.227.1 eno1\n", &route));
  TEST_ASSERT_EQUAL_UINT32(0, route.dest.addr);
  TEST_ASSERT_EQUAL_UINT8(0, route.dest.prefix);
  TEST_ASSERT_EQUAL_UINT32(UINT32_C(0x84b2e301), route.gateway);
  TEST_ASSERT_EQUAL_STRING("eno1", route.dev);

  route_t unchanged = route;
  TEST_ASSERT_FALSE(route_parse("10.1.2.3/24 direct eth0", &route));
  TEST_ASSERT_EQUAL_MEMORY(&unchanged, &route, sizeof(route));
  TEST_ASSERT_FALSE(route_parse("default direct eth0 extra", &route));
}

void test_ip_parse_boundaries_and_malformed_inputs(void) {
  uint32_t address = UINT32_C(0x12345678);
  TEST_ASSERT_TRUE(ip_parse("0.0.0.0", &address));
  TEST_ASSERT_EQUAL_UINT32(0, address);
  TEST_ASSERT_TRUE(ip_parse("255.255.255.255", &address));
  TEST_ASSERT_EQUAL_UINT32(UINT32_MAX, address);

  const char *invalid[] = {
      "", "1.2.3", "1.2.3.4.5", "256.1.1.1", "-1.2.3.4",
      "1..2.3", "01.2.3.4", "1.02.3.4", "1.2.3.04",
      "1.2.3.4x", " 1.2.3.4", "1.2.3.4 ", "1.2.3."};
  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
    address = UINT32_C(0x12345678);
    TEST_ASSERT_FALSE(ip_parse(invalid[i], &address));
    TEST_ASSERT_EQUAL_UINT32(UINT32_C(0x12345678), address);
  }
  TEST_ASSERT_FALSE(ip_parse(NULL, &address));
  TEST_ASSERT_FALSE(ip_parse("1.2.3.4", NULL));
}

void test_ip_format_boundaries(void) {
  char text[IP_STR_LEN];
  ip_format(0, text);
  TEST_ASSERT_EQUAL_STRING("0.0.0.0", text);
  ip_format(UINT32_MAX, text);
  TEST_ASSERT_EQUAL_STRING("255.255.255.255", text);
}

void test_cidr_parse_and_format_boundaries(void) {
  cidr_t block = {UINT32_C(0x12345678), 7};
  TEST_ASSERT_TRUE(cidr_parse("0.0.0.0/0", &block));
  TEST_ASSERT_EQUAL_UINT32(0, block.addr);
  TEST_ASSERT_EQUAL_UINT8(0, block.prefix);
  TEST_ASSERT_TRUE(cidr_parse("255.255.255.254/31", &block));
  TEST_ASSERT_EQUAL_UINT32(UINT32_C(0xfffffffe), block.addr);
  TEST_ASSERT_EQUAL_UINT8(31, block.prefix);
  TEST_ASSERT_TRUE(cidr_parse("255.255.255.255/32", &block));
  TEST_ASSERT_EQUAL_UINT32(UINT32_MAX, block.addr);
  TEST_ASSERT_EQUAL_UINT8(32, block.prefix);

  const char *invalid[] = {
      "", "1.2.3.4", "1.2.3.4/", "1.2.3.4/33", "1.2.3.4/-1",
      "1.2.3.4/01", "1.2.3.4/1/2", "256.1.1.1/24", "/24",
      "1.2.3.4/24x", "1.2.3.4/0:", "1234567890123456/24"};
  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
    block = (cidr_t){UINT32_C(0x12345678), 7};
    TEST_ASSERT_FALSE(cidr_parse(invalid[i], &block));
    TEST_ASSERT_EQUAL_UINT32(UINT32_C(0x12345678), block.addr);
    TEST_ASSERT_EQUAL_UINT8(7, block.prefix);
  }
  TEST_ASSERT_FALSE(cidr_parse(NULL, &block));
  TEST_ASSERT_FALSE(cidr_parse("1.2.3.4/24", NULL));

  char text[CIDR_STR_LEN];
  TEST_ASSERT_EQUAL_UINT32(UINT32_MAX, cidr_mask(33));
  cidr_format((cidr_t){UINT32_MAX, 32}, text);
  TEST_ASSERT_EQUAL_STRING("255.255.255.255/32", text);
  cidr_format((cidr_t){UINT32_C(0x01020304), 33}, text);
  TEST_ASSERT_EQUAL_STRING("1.2.3.4/32", text);
}

void test_cidr_arithmetic_at_prefix_boundaries(void) {
  cidr_t block = {0, 0};
  TEST_ASSERT_EQUAL_UINT32(0, cidr_mask(0));
  TEST_ASSERT_EQUAL_UINT32(0, cidr_network(block));
  TEST_ASSERT_EQUAL_UINT32(UINT32_MAX, cidr_broadcast(block));
  TEST_ASSERT_EQUAL_UINT32(1, cidr_first_host(block));
  TEST_ASSERT_EQUAL_UINT32(UINT32_MAX - 1U, cidr_last_host(block));
  TEST_ASSERT_EQUAL_UINT64(UINT64_C(4294967294), cidr_host_count(block));
  TEST_ASSERT_TRUE(cidr_contains(block, 0));
  TEST_ASSERT_TRUE(cidr_contains(block, UINT32_MAX));
  TEST_ASSERT_TRUE(cidr_is_network(block));

  block = (cidr_t){UINT32_C(0xfffffffe), 31};
  TEST_ASSERT_EQUAL_UINT32(UINT32_C(0xfffffffe), cidr_mask(31));
  TEST_ASSERT_EQUAL_UINT32(UINT32_C(0xfffffffe), cidr_network(block));
  TEST_ASSERT_EQUAL_UINT32(UINT32_MAX, cidr_broadcast(block));
  TEST_ASSERT_EQUAL_UINT32(UINT32_C(0xfffffffe), cidr_first_host(block));
  TEST_ASSERT_EQUAL_UINT32(UINT32_MAX, cidr_last_host(block));
  TEST_ASSERT_EQUAL_UINT64(2, cidr_host_count(block));
  TEST_ASSERT_TRUE(cidr_contains(block, UINT32_C(0xfffffffe)));
  TEST_ASSERT_TRUE(cidr_contains(block, UINT32_MAX));
  TEST_ASSERT_FALSE(cidr_contains(block, UINT32_C(0xfffffffd)));

  block = (cidr_t){UINT32_MAX, 32};
  TEST_ASSERT_EQUAL_UINT32(UINT32_MAX, cidr_mask(32));
  TEST_ASSERT_EQUAL_UINT32(UINT32_MAX, cidr_network(block));
  TEST_ASSERT_EQUAL_UINT32(UINT32_MAX, cidr_broadcast(block));
  TEST_ASSERT_EQUAL_UINT32(UINT32_MAX, cidr_first_host(block));
  TEST_ASSERT_EQUAL_UINT32(UINT32_MAX, cidr_last_host(block));
  TEST_ASSERT_EQUAL_UINT64(1, cidr_host_count(block));
  TEST_ASSERT_TRUE(cidr_contains(block, UINT32_MAX));
  TEST_ASSERT_FALSE(cidr_contains(block, UINT32_MAX - 1U));
  TEST_ASSERT_FALSE(cidr_is_network((cidr_t){UINT32_MAX, 31}));
}

void test_cidr_subnet_valid_and_invalid_inputs(void) {
  cidr_t block = {UINT32_C(0xc0a80100), 24};
  cidr_t subnet;
  const uint32_t expected[] = {
      UINT32_C(0xc0a80100), UINT32_C(0xc0a80140),
      UINT32_C(0xc0a80180), UINT32_C(0xc0a801c0)};
  for (uint32_t i = 0; i < 4; ++i) {
    TEST_ASSERT_TRUE(cidr_subnet(block, 4, i, &subnet));
    TEST_ASSERT_EQUAL_UINT32(expected[i], subnet.addr);
    TEST_ASSERT_EQUAL_UINT8(26, subnet.prefix);
  }
  TEST_ASSERT_TRUE(cidr_subnet(block, 1, 0, &subnet));
  TEST_ASSERT_EQUAL_UINT32(block.addr, subnet.addr);
  TEST_ASSERT_EQUAL_UINT8(24, subnet.prefix);

  block = (cidr_t){UINT32_C(0xfffffffe), 31};
  TEST_ASSERT_TRUE(cidr_subnet(block, 2, 1, &subnet));
  TEST_ASSERT_EQUAL_UINT32(UINT32_MAX, subnet.addr);
  TEST_ASSERT_EQUAL_UINT8(32, subnet.prefix);
  TEST_ASSERT_TRUE(cidr_subnet((cidr_t){UINT32_MAX, 32}, 1, 0, &subnet));
  TEST_ASSERT_EQUAL_UINT32(UINT32_MAX, subnet.addr);
  TEST_ASSERT_EQUAL_UINT8(32, subnet.prefix);
  TEST_ASSERT_FALSE(cidr_subnet((cidr_t){UINT32_MAX, 32}, 2, 0, &subnet));

  subnet = (cidr_t){UINT32_C(0x12345678), 9};
  TEST_ASSERT_FALSE(cidr_subnet(block, 0, 0, &subnet));
  TEST_ASSERT_FALSE(cidr_subnet(block, 3, 0, &subnet));
  TEST_ASSERT_FALSE(cidr_subnet(block, 4, 4, &subnet));
  TEST_ASSERT_FALSE(cidr_subnet(block, 512, 0, &subnet));
  TEST_ASSERT_FALSE(cidr_subnet((cidr_t){UINT32_C(0xc0a80101), 24},
                                2, 0, &subnet));
  TEST_ASSERT_FALSE(cidr_subnet(block, 2, 0, NULL));
  TEST_ASSERT_EQUAL_UINT32(UINT32_C(0x12345678), subnet.addr);
  TEST_ASSERT_EQUAL_UINT8(9, subnet.prefix);
}

void test_route_parse_field_validation_and_preserves_output(void) {
  route_t route = {{UINT32_C(0x0a000000), 8}, UINT32_C(0x01020304), "before"};
  TEST_ASSERT_TRUE(route_parse(" \tdefault direct eth0 \t", &route));
  TEST_ASSERT_EQUAL_UINT8(0, route.dest.prefix);
  TEST_ASSERT_EQUAL_STRING("eth0", route.dev);

  const char *invalid[] = {
      "", "10.0.0.1/8 direct eth0", "10.0.0.0/8 999.1.1.1 eth0",
      "default direct", "default direct eth0 extra", "default direct ",
      "default direct device_name_too_long", "default direct eth0\vextra",
      "12345678901234567890 direct eth0",
      "default 1234567890123456 eth0"};
  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
    route_t before = route;
    TEST_ASSERT_FALSE(route_parse(invalid[i], &route));
    TEST_ASSERT_EQUAL_MEMORY(&before, &route, sizeof(route));
  }
  TEST_ASSERT_FALSE(route_parse(NULL, &route));
  TEST_ASSERT_FALSE(route_parse("default direct eth0", NULL));
}

void test_table_load_and_longest_prefix_lookup(void) {
  FILE *input = tmpfile();
  TEST_ASSERT_NOT_NULL(input);
  TEST_ASSERT_TRUE(fputs(
                       "# routes in specific-to-broad order\n"
                       "10.1.2.128/25 10.1.2.1 eth2 # comment\n"
                       "10.1.2.0/24 direct eth2\n"
                       "10.1.0.0/16 direct eth1\n"
                       "10.0.0.0/8 10.1.0.1 eth1\n"
                       "default 132.178.227.1 eno1\n",
                       input) >= 0);
  rewind(input);

  fwd_table_t *table = table_create();
  TEST_ASSERT_NOT_NULL(table);
  size_t bad_line = 99;
  TEST_ASSERT_TRUE(table_load(table, input, &bad_line));
  TEST_ASSERT_EQUAL_UINT(0, bad_line);
  TEST_ASSERT_EQUAL_UINT(5, table_count(table));

  const route_t *route = table_lookup(table, UINT32_C(0x0a0102c8));
  TEST_ASSERT_NOT_NULL(route);
  TEST_ASSERT_EQUAL_UINT8(25, route->dest.prefix);
  TEST_ASSERT_EQUAL_STRING("eth2", route->dev);

  route = table_lookup(table, UINT32_C(0x0a010264));
  TEST_ASSERT_NOT_NULL(route);
  TEST_ASSERT_EQUAL_UINT8(24, route->dest.prefix);

  route = table_lookup(table, UINT32_C(0x08080808));
  TEST_ASSERT_NOT_NULL(route);
  TEST_ASSERT_EQUAL_UINT8(0, route->dest.prefix);

  fclose(input);
  table_destroy(table);
}

void test_lookup_is_order_independent_and_has_no_default_fallback(void) {
  fwd_table_t *table = table_create();
  TEST_ASSERT_NOT_NULL(table);
  route_t broad = {{UINT32_C(0x0a000000), 8}, 0, "broad"};
  route_t medium = {{UINT32_C(0x0a010000), 16}, 0, "medium"};
  route_t specific = {{UINT32_C(0x0a010200), 24}, 0, "specific"};

  TEST_ASSERT_TRUE(table_add(table, &specific));
  TEST_ASSERT_TRUE(table_add(table, &medium));
  TEST_ASSERT_TRUE(table_add(table, &broad));
  const route_t *route = table_lookup(table, UINT32_C(0x0a01020a));
  TEST_ASSERT_NOT_NULL(route);
  TEST_ASSERT_EQUAL_UINT8(24, route->dest.prefix);
  TEST_ASSERT_EQUAL_STRING("specific", route->dev);

  table_destroy(table);
  table = table_create();
  TEST_ASSERT_NOT_NULL(table);
  TEST_ASSERT_TRUE(table_add(table, &broad));
  TEST_ASSERT_TRUE(table_add(table, &medium));
  TEST_ASSERT_TRUE(table_add(table, &specific));
  route = table_lookup(table, UINT32_C(0x0a01020a));
  TEST_ASSERT_NOT_NULL(route);
  TEST_ASSERT_EQUAL_UINT8(24, route->dest.prefix);
  TEST_ASSERT_EQUAL_STRING("specific", route->dev);
  TEST_ASSERT_NULL(table_lookup(table, UINT32_C(0x08080808)));
  TEST_ASSERT_NULL(table_lookup(table, UINT32_C(0x0b000001)));

  table_destroy(table);
}

void test_table_load_bad_middle_line_keeps_only_prior_routes(void) {
  FILE *input = tmpfile();
  TEST_ASSERT_NOT_NULL(input);
  TEST_ASSERT_TRUE(fputs("10.0.0.0/8 direct eth0\n"
                         "172.16.0.0/12 direct eth1\n"
                         "192.168.0.0/16 direct eth2\n"
                         "not a valid route\n",
                         input) >= 0);
  rewind(input);

  fwd_table_t *table = table_create();
  TEST_ASSERT_NOT_NULL(table);
  size_t bad_line = 0;
  TEST_ASSERT_FALSE(table_load(table, input, &bad_line));
  TEST_ASSERT_EQUAL_UINT(4, bad_line);
  TEST_ASSERT_EQUAL_UINT(3, table_count(table));
  TEST_ASSERT_NOT_NULL(table_lookup(table, UINT32_C(0x0a000001)));
  TEST_ASSERT_NOT_NULL(table_lookup(table, UINT32_C(0xac100001)));
  TEST_ASSERT_NOT_NULL(table_lookup(table, UINT32_C(0xc0a80001)));

  fclose(input);
  table_destroy(table);
}

void test_table_load_blank_lines_and_embedded_nul(void) {
  FILE *input = tmpfile();
  TEST_ASSERT_NOT_NULL(input);
  TEST_ASSERT_TRUE(fputs("   \t\n# comment-only line\n"
                         "10.0.0.0/8 direct eth0\n",
                         input) >= 0);
  rewind(input);

  fwd_table_t *table = table_create();
  TEST_ASSERT_NOT_NULL(table);
  size_t bad_line = 99;
  TEST_ASSERT_TRUE(table_load(table, input, &bad_line));
  TEST_ASSERT_EQUAL_UINT(0, bad_line);
  TEST_ASSERT_EQUAL_UINT(1, table_count(table));
  fclose(input);

  input = tmpfile();
  TEST_ASSERT_NOT_NULL(input);
  const unsigned char binary_line[] = {
      'd', 'e', 'f', 'a', 'u', 'l', 't', ' ', '\0',
      'd', 'i', 'r', 'e', 'c', 't', ' ', 'e', 't', 'h', '0', '\n'};
  TEST_ASSERT_EQUAL_UINT(sizeof(binary_line),
                         fwrite(binary_line, 1, sizeof(binary_line), input));
  rewind(input);
  bad_line = 0;
  TEST_ASSERT_FALSE(table_load(table, input, &bad_line));
  TEST_ASSERT_EQUAL_UINT(1, bad_line);
  TEST_ASSERT_EQUAL_UINT(1, table_count(table));
  fclose(input);

  input = tmpfile();
  TEST_ASSERT_NOT_NULL(input);
  TEST_ASSERT_EQUAL_UINT(sizeof(binary_line),
                         fwrite(binary_line, 1, sizeof(binary_line), input));
  rewind(input);
  TEST_ASSERT_FALSE(table_load(table, input, NULL));
  fclose(input);
  table_destroy(table);
}

void test_table_load_empty_file_and_optional_bad_line(void) {
  fwd_table_t *table = table_create();
  TEST_ASSERT_NOT_NULL(table);

  FILE *input = tmpfile();
  TEST_ASSERT_NOT_NULL(input);
  TEST_ASSERT_TRUE(table_load(table, input, NULL));
  fclose(input);
  TEST_ASSERT_EQUAL_UINT(0, table_count(table));

  input = tmpfile();
  TEST_ASSERT_NOT_NULL(input);
  TEST_ASSERT_TRUE(fputs("invalid route\n", input) >= 0);
  rewind(input);
  TEST_ASSERT_FALSE(table_load(table, input, NULL));
  fclose(input);
  TEST_ASSERT_EQUAL_UINT(0, table_count(table));
  table_destroy(table);
}

void test_table_load_read_error(void) {
  fwd_table_t *table = table_create();
  TEST_ASSERT_NOT_NULL(table);
  FILE *input = tmpfile();
  TEST_ASSERT_NOT_NULL(input);
  TEST_ASSERT_EQUAL_INT(0, close(fileno(input)));

  size_t bad_line = 99;
  TEST_ASSERT_FALSE(table_load(table, input, &bad_line));
  TEST_ASSERT_EQUAL_UINT(0, bad_line);
  TEST_ASSERT_EQUAL_UINT(0, table_count(table));
  (void)fclose(input);
  table_destroy(table);
}

void test_table_null_inputs_and_invalid_routes(void) {
  TEST_ASSERT_EQUAL_UINT(0, table_count(NULL));
  TEST_ASSERT_NULL(table_lookup(NULL, 0));
  table_destroy(NULL);
  TEST_ASSERT_FALSE(table_add(NULL, NULL));
  size_t bad_line = 99;
  TEST_ASSERT_FALSE(table_load(NULL, NULL, &bad_line));
  TEST_ASSERT_EQUAL_UINT(0, bad_line);

  fwd_table_t *table = table_create();
  TEST_ASSERT_NOT_NULL(table);
  TEST_ASSERT_FALSE(table_add(table, NULL));
  bad_line = 99;
  TEST_ASSERT_FALSE(table_load(table, NULL, &bad_line));
  TEST_ASSERT_EQUAL_UINT(0, bad_line);
  route_t invalid = {{UINT32_C(0x0a000001), 8}, 0, "eth0"};
  TEST_ASSERT_FALSE(table_add(table, &invalid));
  invalid = (route_t){{UINT32_C(0x0a000000), 33}, 0, "eth0"};
  TEST_ASSERT_FALSE(table_add(table, &invalid));
  invalid = (route_t){{UINT32_C(0x0a000000), 8}, 0, ""};
  TEST_ASSERT_FALSE(table_add(table, &invalid));
  invalid = (route_t){{UINT32_C(0x0a000000), 8}, 0,
                      "0123456789abcde"};
  TEST_ASSERT_TRUE(table_add(table, &invalid));
  invalid = (route_t){{UINT32_C(0x0b000000), 8}, 0,
                      {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                       'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p'}};
  TEST_ASSERT_FALSE(table_add(table, &invalid));
  TEST_ASSERT_EQUAL_UINT(1, table_count(table));
  table_destroy(table);
}

void test_table_rejects_duplicate_routes_and_reports_bad_line(void) {
  fwd_table_t *table = table_create();
  TEST_ASSERT_NOT_NULL(table);
  route_t route = {{UINT32_C(0x0a000000), 8}, 0, "eth0"};
  TEST_ASSERT_TRUE(table_add(table, &route));
  route.gateway = UINT32_C(0x0a000001);
  TEST_ASSERT_FALSE(table_add(table, &route));
  TEST_ASSERT_EQUAL_UINT(1, table_count(table));

  FILE *input = tmpfile();
  TEST_ASSERT_NOT_NULL(input);
  TEST_ASSERT_TRUE(fputs("192.168.0.0/16 direct eth1\n"
                         "192.168.0.0/16 direct eth2\n",
                         input) >= 0);
  rewind(input);
  size_t bad_line = 0;
  TEST_ASSERT_FALSE(table_load(table, input, &bad_line));
  TEST_ASSERT_EQUAL_UINT(2, bad_line);

  fclose(input);
  table_destroy(table);
}

void test_table_grows_for_many_routes(void) {
  fwd_table_t *table = table_create();
  TEST_ASSERT_NOT_NULL(table);
  for (uint32_t i = 0; i < 4096; ++i) {
    route_t route = {{UINT32_C(0x10000000) + i, 32}, 0, "eth0"};
    TEST_ASSERT_TRUE(table_add(table, &route));
  }
  TEST_ASSERT_EQUAL_UINT(4096, table_count(table));
  const route_t *route = table_lookup(table, UINT32_C(0x10000fff));
  TEST_ASSERT_NOT_NULL(route);
  TEST_ASSERT_EQUAL_UINT8(32, route->dest.prefix);
  table_destroy(table);
}

void test_table_rejects_route_count_at_index_limit(void) {
  fwd_table_t *table = table_create();
  TEST_ASSERT_NOT_NULL(table);
  route_t route = {{UINT32_C(0x0a000000), 8}, 0, "eth0"};
  table_test_set_count(table, UINT32_MAX);
  TEST_ASSERT_FALSE(table_add(table, &route));
  TEST_ASSERT_EQUAL_UINT32(UINT32_MAX, table_count(table));
  table_destroy(table);
}

void test_table_rejects_trie_count_at_index_limit(void) {
  fwd_table_t *table = table_create();
  TEST_ASSERT_NOT_NULL(table);
  route_t route = {{0, 1}, 0, "eth0"};
  table_test_set_trie_count(table, UINT32_MAX);
  TEST_ASSERT_FALSE(table_add(table, &route));
  TEST_ASSERT_EQUAL_UINT(0, table_count(table));
  table_destroy(table);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_ip_parse_boundaries_and_malformed_inputs);
  RUN_TEST(test_ip_format_boundaries);
  RUN_TEST(test_cidr_parse_and_format_boundaries);
  RUN_TEST(test_cidr_arithmetic_at_prefix_boundaries);
  RUN_TEST(test_cidr_subnet_valid_and_invalid_inputs);
  RUN_TEST(test_route_parse);
  RUN_TEST(test_route_parse_field_validation_and_preserves_output);
  RUN_TEST(test_table_load_and_longest_prefix_lookup);
  RUN_TEST(test_lookup_is_order_independent_and_has_no_default_fallback);
  RUN_TEST(test_table_load_bad_middle_line_keeps_only_prior_routes);
  RUN_TEST(test_table_load_blank_lines_and_embedded_nul);
  RUN_TEST(test_table_load_empty_file_and_optional_bad_line);
  RUN_TEST(test_table_load_read_error);
  RUN_TEST(test_table_null_inputs_and_invalid_routes);
  RUN_TEST(test_table_rejects_duplicate_routes_and_reports_bad_line);
  RUN_TEST(test_table_grows_for_many_routes);
  RUN_TEST(test_table_rejects_route_count_at_index_limit);
  RUN_TEST(test_table_rejects_trie_count_at_index_limit);
  return UNITY_END();
}
