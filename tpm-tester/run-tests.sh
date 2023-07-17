#!/bin/bash
set -e

echo Running TPM tests using the simulator...
./build/install/tpm-tester/bin/tpm-tester --test testTpmSpeed > results-sim.log
echo Running TPM tests using the physical device...
./build/install/tpm-tester/bin/tpm-tester --device --test testTpmSpeed > results-hw.log
