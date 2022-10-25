package de.fhg.iosb.iad.tpm.attestation.tap;

import java.util.Collection;

import de.fhg.iosb.iad.tpm.TpmEngine;
import de.fhg.iosb.iad.tpm.TpmEngine.TpmLoadedKey;

public class TapConfiguration {

	private final TpmEngine tpmEngine;
	private final TpmLoadedKey quotingKey;
	private final Collection<Integer> pcrSelection;

	public TapConfiguration(TpmEngine tpmEngine, TpmLoadedKey quotingKey, Collection<Integer> pcrSelection) {
		assert (tpmEngine != null);
		assert (quotingKey != null);
		assert (pcrSelection != null);
		this.tpmEngine = tpmEngine;
		this.quotingKey = quotingKey;
		this.pcrSelection = pcrSelection;
	}

	public TpmEngine getTpmEngine() {
		return tpmEngine;
	}

	public TpmLoadedKey getQuotingKey() {
		return quotingKey;
	}

	public Collection<Integer> getPcrSelection() {
		return pcrSelection;
	}

}
