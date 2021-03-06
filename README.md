# Sasl

This is a library which implements various Simple Authentication and Security
Layer (SASL -- [RFC 4422](https://tools.ietf.org/html/rfc4422)) mechanisms.

## Usage

The `Sasl::Client::Mechanism` class defines the common interface for all
client-side SASL mechanisms.

The `Sasl::Client::Plain` class implements the client-side PLAIN SASL ([RFC
4616](https://tools.ietf.org/html/rfc4616)) mechanism.

The `Sasl::Client::Login` class implements the client-side LOGIN SASL
([draft-murchison-sasl-login](https://tools.ietf.org/html/draft-murchison-sasl-login-00))
mechanism.

The `Sasl::Client::Scram` class implements the client-side SCRAM SASL ([RFC
5802](https://tools.ietf.org/html/rfc5802)) mechanism.

## Supported platforms / recommended toolchains

This is a portable C++11 application which depends only on the C++11 compiler,
the C and C++ standard libraries, and other C++11 libraries with similar
dependencies, so it should be supported on almost any platform.  The following
are recommended toolchains for popular platforms.

* Windows -- [Visual Studio](https://www.visualstudio.com/) (Microsoft Visual
  C++)
* Linux -- clang or gcc
* MacOS -- Xcode (clang)

## Building

This library is not intended to stand alone.  It is intended to be included in
a larger solution which uses [CMake](https://cmake.org/) to generate the build
system and build applications which will link with the library.

There are two distinct steps in the build process:

1. Generation of the build system, using CMake
2. Compiling, linking, etc., using CMake-compatible toolchain

### Prerequisites

* [CMake](https://cmake.org/) version 3.8 or newer
* C++11 toolchain compatible with CMake for your development platform (e.g.
  [Visual Studio](https://www.visualstudio.com/) on Windows)
* [Hash](https://github.com/rhymu8354/Hash.git) - a library which implements
  various cryptographic hash and message digest functions.
* [SystemAbstractions](https://github.com/rhymu8354/SystemAbstractions.git) - a
  cross-platform adapter library for system services whose APIs vary from one
  operating system to another

### Build system generation

Generate the build system using [CMake](https://cmake.org/) from the solution
root.  For example:

```bash
mkdir build
cd build
cmake -G "Visual Studio 15 2017" -A "x64" ..
```

### Compiling, linking, et cetera

Either use [CMake](https://cmake.org/) or your toolchain's IDE to build.
For [CMake](https://cmake.org/):

```bash
cd build
cmake --build . --config Release
```
