# TPM 2.0 Java Commons
[![pipeline status](https://gitlab.cc-asp.fraunhofer.de/tpm-20-commons/tpm-java/badges/master/pipeline.svg)](https://gitlab.cc-asp.fraunhofer.de/tpm-20-commons/tpm-java/-/commits/master)

This repository contains convenience libraries and tools to use TPM 2.0 in Java environments.
To build all included libraries and tools, use
```
./gradlew build
```


## TPM 2.0 Library
The `tpm` subproject contains a Java library that provides a simple interface to use TPM 2.0 functionalities in Java projects.
The `TpmEngine` interface offers some simplified methods for attestation, key management and PCR operations.
Use the class `TpmEngineFactory` to create engine instances either backed by a TPM simulator, or the platform TPM device.
If you connect to a simulator, make sure to launch the [MSR TPM simulator](https://gitlab.cc-asp.fraunhofer.de/tpm-20-commons/tpm-simulator) first.
The class `TpmValidator` provides convenience methods for validating TPM certifications and quotes.

The `tpm-tester` subproject provides a small test application to execute some of the library functions.
To execute the tests, use
```
./gradlew tpm-tester:run
```
Use the `--args="-t testPcrRead"` option to change the test cases that should be executed.
Use the `--args="-a 127.0.0.1"` option to change the address of the TPM server, or set `--args="--device"` to use the local platform TPM instead.
The option `--args="-h"` displays a list of all available configuration parameters.


## Attestation Library
The `attestation` subproject contains a Java library that provides several TPM-based remote attestation protocol implementations.
Currently the library supports the following protocols:
  - TAP (plaintext)
  - TAP (DHKE)
  - TAP (SSL)
  - MSCP

For each protocol, the library provides server and client socket classes.
Created sockets can be individually configured with uni- or bidirectional attestations and PCR selections.
Attestations and the establishment of encrypted channels is performed automatically on socket connection.

Usage examples of the attestation protocols are provided in the `attestation-tester` subproject.
To execute the examples, use
```
./gradlew attestation-tester:run
```
By default the attestation tester performs a total of 100 socket handshakes with all available attestation protocols.
You can change that behavior with the `--args="-n 1 --type tap-uni --type ..."` option.
Note that the examples require a running [MSR TPM simulator](https://gitlab.cc-asp.fraunhofer.de/tpm-20-commons/tpm-simulator).
You can use the `--args="-a 127.0.0.1"` option to change the address of the TPM server to use, or set `--args="--device"` to use the local platform TPM instead.
The option `--args="-h"` displays a list of all available configuration parameters.


## TTP Server
The `ttp` subproject contains a standalone Trusted Third Party (TTP) providing trustworthy fingerprints for TPM-based remote attestations.
To run the TTP, use
```
./gradlew ttp:run
```
By default the server starts on port 5001 and uses the database file `./ttp.sqlite`.
If the file does not exist, the server will create an empty database, which can be populated using `ttp-tool` (see below).
The option `--args="-h"` displays a list of all available configuration parameters.

The `ttp-tool` subproject contains a small tool that allows to collect fingerprints for the TTP database.
Run the TTP tool with
```
./gradlew ttp-tool:run
```
Use the option `--args="--command createSql --pcrs 0-15"` to create an SQL file that inserts the current PCR configuration of registers 0 to 15 into the set of trusted system configurations.
For this you again need to run the [MSR TPM simulator](https://gitlab.cc-asp.fraunhofer.de/tpm-20-commons/tpm-simulator), or use `--args="--device"` to read the PCR values from the platform TPM.
The option `--args="-h"` displays a list of all available configuration parameters.
