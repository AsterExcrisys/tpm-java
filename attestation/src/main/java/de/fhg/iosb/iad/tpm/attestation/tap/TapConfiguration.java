package de.fhg.iosb.iad.tpm.attestation.tap;

import java.util.Collection;

import de.fhg.iosb.iad.tpm.TpmEngine;
import de.fhg.iosb.iad.tpm.TpmEngine.TpmLoadedKey;

public class TapConfiguration {

	private final TpmEngine tpmEngine;
	private final TpmLoadedKey quotingKey;
	private final Collection<Integer> pcrSelection;
	private final boolean attestServer;
	private final boolean attestClient;

	public TapConfiguration(TpmEngine tpmEngine, TpmLoadedKey quotingKey, Collection<Integer> pcrSelection) {
		this(tpmEngine, quotingKey, pcrSelection, true, true);
	}

	public TapConfiguration(TpmEngine tpmEngine, TpmLoadedKey quotingKey, Collection<Integer> pcrSelection,
			boolean attestServer, boolean attestClient) {
		assert (tpmEngine != null);
		assert (quotingKey != null);
		assert (pcrSelection != null);
		this.tpmEngine = tpmEngine;
		this.quotingKey = quotingKey;
		this.pcrSelection = pcrSelection;

		if (!attestServer && !attestClient)
			throw new IllegalArgumentException("TAP configuration requires at least one attested side!");
		this.attestServer = attestServer;
		this.attestClient = attestClient;
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

	public boolean isAttestServer() {
		return attestServer;
	}

	public boolean isAttestClient() {
		return attestClient;
	}

}
