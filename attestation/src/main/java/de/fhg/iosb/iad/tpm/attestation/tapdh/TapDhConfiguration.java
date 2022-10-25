package de.fhg.iosb.iad.tpm.attestation.tapdh;

import java.util.Collection;

import de.fhg.iosb.iad.tpm.TpmEngine;
import de.fhg.iosb.iad.tpm.TpmEngine.TpmLoadedKey;
import de.fhg.iosb.iad.tpm.attestation.tap.TapConfiguration;

public class TapDhConfiguration extends TapConfiguration {

	public TapDhConfiguration(TpmEngine tpmEngine, TpmLoadedKey quotingKey, Collection<Integer> pcrSelection) {
		super(tpmEngine, quotingKey, pcrSelection);
	}

}
