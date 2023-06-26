package de.fhg.iosb.iad.tpm.attestation.mscp;

import java.util.Collection;

import de.fhg.iosb.iad.tpm.TpmEngine;
import de.fhg.iosb.iad.tpm.TpmEngine.TpmLoadedKey;
import de.fhg.iosb.iad.tpm.attestation.tap.TapConfiguration;

public class MscpConfiguration extends TapConfiguration {

	private final TpmLoadedKey rootKey;

	public MscpConfiguration(TpmEngine tpmEngine, TpmLoadedKey quotingKey, TpmLoadedKey rootKey,
			Collection<Integer> pcrSelection) {
		super(tpmEngine, quotingKey, pcrSelection);
		assert (rootKey != null);
		this.rootKey = rootKey;
	}

	public TpmLoadedKey getRootKey() {
		return rootKey;
	}

}
