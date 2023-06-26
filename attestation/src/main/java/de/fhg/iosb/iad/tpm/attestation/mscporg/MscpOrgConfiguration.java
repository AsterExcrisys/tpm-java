package de.fhg.iosb.iad.tpm.attestation.mscporg;

import java.util.Collection;

import de.fhg.iosb.iad.tpm.TpmEngine;
import de.fhg.iosb.iad.tpm.TpmEngine.TpmLoadedKey;
import de.fhg.iosb.iad.tpm.attestation.tap.TapConfiguration;

public class MscpOrgConfiguration extends TapConfiguration {

	private final TpmLoadedKey rootKey;

	public MscpOrgConfiguration(TpmEngine tpmEngine, TpmLoadedKey quotingKey, TpmLoadedKey rootKey,
			Collection<Integer> pcrSelection) {
		super(tpmEngine, quotingKey, pcrSelection);
		assert (rootKey != null);
		this.rootKey = rootKey;
	}

	public TpmLoadedKey getRootKey() {
		return rootKey;
	}

}
