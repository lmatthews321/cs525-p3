# Makefile Project Template

This is a simple Makefile project template that can be used to build, test, and
debug C projects. It includes support for debug builds, sanitizers, and code
coverage.

## Tools and Dependencies

- GNU Make
- GCC or Clang
- Address Sanitizer (ASan) for memory error detection
- gcov and lcov for code coverage
- gcovr for generating coverage reports
- pandoc for generating docx reports (optional)

## Test Harness

This project uses the Unity Test Framework for unit testing. Refer to the
[Unity Getting Started Guide](https://github.com/ThrowTheSwitch/Unity/blob/master/docs/UnityGettingStartedGuide.md) for more information on how to write and run tests.

## Example Usage

To build the project run:

```bash
make all
```
To run the executable:

```bash
./build/release/myapp
```

## Application Commands

Running `myapp` with no arguments prints the usage text and exits successfully:

```text
Usage: myapp info <address>/<prefix>
       myapp split <network>/<prefix> <count>
       myapp lookup <table-file> <address>...
```

`info` prints the address, prefix, netmask, network, broadcast, first and last
host addresses, and usable host count:

```bash
./build/release/myapp info 132.178.227.11/25
```

`split` prints the requested equal-sized subnets in ascending order. The input
must be a network address and the count must be a positive power of two:

```bash
./build/release/myapp split 192.168.1.0/24 4
```

`lookup` loads a forwarding table and prints one result per address. Matching
routes use `via <gateway>` when a gateway is configured, followed by `dev
<device>`; addresses without a route are reported as `unreachable`:

```bash
./build/release/myapp lookup src/tables/example.txt \
  132.178.227.50 8.8.8.8 10.1.2.5 10.1.2.200
```

The program exits with status 0 on success, 1 for invalid command-line input or
malformed addresses, 2 when a table cannot be opened or contains a bad route,
and 3 when at least one lookup address has no matching route. For lookup
requests containing both malformed and unreachable addresses, all valid
addresses are still reported and status 1 takes precedence.

To run the unit tests:

```bash
make check
```

To see all the configurations, run `make help`

```bash
Usage: make [target]
Available targets:
  debug     - Build the application in debug mode (default)
  release   - Build the application in release mode
  test      - Build the unit tests
  all       - Builds debug, release, and test targets
  check     - Run tests and check results
  report    - Generate coverage report after running tests
  leak      - Check for memory leaks in debug mode
  clean     - Remove build artifacts
  print     - Print build variables for MakeFile debugging
  help      - Show this help message
```

## VS Code Integration

This project is designed to work well with Visual Studio Code. Configurations
for debugging the application and unit tests are provided. Read about how to
use the debugger in the [VS Code documentation](https://code.visualstudio.com/docs/editor/debugging).

## Features

- Build targets for debug and release modes
- Support for Address Sanitizer (ASan)
- Code coverage support and report generation
- Simple structure for organizing source files and build artifacts