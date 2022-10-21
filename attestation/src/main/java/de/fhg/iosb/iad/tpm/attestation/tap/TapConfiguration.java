package de.fhg.iosb.iad.tpm.attestation.tap;

import java.util.Arrays;
import java.util.Collection;

import de.fhg.iosb.iad.tpm.TpmEngine;
import de.fhg.iosb.iad.tpm.TpmEngine.TpmEngineException;
import de.fhg.iosb.iad.tpm.TpmEngineFactory;

public class TapConfiguration {

	protected static final Collection<Integer> defaultPcrSelection = Arrays.asList(0, 1, 2, 3, 4, 5, 6, 7);

	private final Collection<Integer> pcrSelection;
	private final TpmEngine tpmEngine;

	public TapConfiguration() throws TpmEngineException {
		this(TpmEngineFactory.createSimulatorInstance());
	}

	public TapConfiguration(TpmEngine tpmEngine) {
		this(tpmEngine, defaultPcrSelection);
	}

	public TapConfiguration(TpmEngine tpmEngine, Collection<Integer> pcrSelection) {
		this.pcrSelection = pcrSelection;
		this.tpmEngine = tpmEngine;
	}

	public Collection<Integer> getPcrSelection() {
		return pcrSelection;
	}

	public TpmEngine getTpmEngine() {
		return tpmEngine;
	}

}
