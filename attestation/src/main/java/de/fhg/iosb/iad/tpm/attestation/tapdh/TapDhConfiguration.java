package de.fhg.iosb.iad.tpm.attestation.tapdh;

import java.util.Collection;

import de.fhg.iosb.iad.tpm.TpmEngine;
import de.fhg.iosb.iad.tpm.TpmEngine.TpmEngineException;
import de.fhg.iosb.iad.tpm.TpmEngineFactory;
import de.fhg.iosb.iad.tpm.attestation.tap.TapConfiguration;

public class TapDhConfiguration extends TapConfiguration {

	public TapDhConfiguration() throws TpmEngineException {
		super(TpmEngineFactory.createSimulatorInstance());
	}

	public TapDhConfiguration(TpmEngine tpmEngine) {
		super(tpmEngine);
	}

	public TapDhConfiguration(TpmEngine tpmEngine, Collection<Integer> pcrSelection) {
		super(tpmEngine, pcrSelection);
	}

}
