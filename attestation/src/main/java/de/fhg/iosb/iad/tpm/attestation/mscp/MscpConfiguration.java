package de.fhg.iosb.iad.tpm.attestation.mscp;

import java.util.Collection;

import de.fhg.iosb.iad.tpm.TpmEngine;
import de.fhg.iosb.iad.tpm.TpmEngine.TpmEngineException;
import de.fhg.iosb.iad.tpm.attestation.tap.TapConfiguration;

public class MscpConfiguration extends TapConfiguration {

	public MscpConfiguration() throws TpmEngineException {
		super();
	}

	public MscpConfiguration(TpmEngine tpmEngine) {
		super(tpmEngine);
	}

	public MscpConfiguration(TpmEngine tpmEngine, Collection<Integer> pcrSelection) {
		super(tpmEngine, pcrSelection);
	}

}
