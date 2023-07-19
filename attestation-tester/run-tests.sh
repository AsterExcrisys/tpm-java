#!/bin/bash
set -e

echo Running attestation protocol tests using the simulator...
./build/install/attestation-tester/bin/attestation-tester --type ssl --type tap-uni --type tap --type tap-ssl --type tap-dh --type mscp --type mscp-ext --n 100 > results-sim.log
echo Running attestation protocol tests using the physical device...
./build/install/attestation-tester/bin/attestation-tester --device --type tap-uni --type tap --type tap-ssl --type tap-dh --type mscp --type mscp-ext --n 100 > results-hw.log
