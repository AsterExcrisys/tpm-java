package de.fhg.iosb.iad.tpm.commons;

import de.fhg.iosb.iad.tpm.commons.TpmEngine.TpmEngineException;
import tss.Tpm;
import tss.TpmFactory;

/**
 * Factory for TPM engines. To use these engines, the TPM 2.0 software stack by
 * Microsoft Research has to be running.
 * 
 * @author wagner
 *
 */

public final class TpmEngineFactory {

	private static boolean tssSimInitialized = false;

	public static TpmEngineImpl createSimulatorInstance() throws TpmEngineException {
		return createSimulatorInstance("localhost", 2321);
	}

	public static TpmEngineImpl createSimulatorInstance(String host, int port) throws TpmEngineException {
		try {
			Tpm tpm = tssSimInitialized ? TpmFactory.remoteTpm(host, port) : TpmFactory.localTpmSimulator();
			tssSimInitialized = true;
			return new TpmEngineImpl(tpm);
		} catch (Exception e) {
			throw new TpmEngineException("Failed to connect to TPM simulator!", e);
		}
	}

	public static TpmEngineImpl createPlatformInstance() throws TpmEngineException {
		try {
			return new TpmEngineImpl(TpmFactory.platformTpm());
		} catch (Exception e) {
			throw new TpmEngineException("Failed to connect to platform TPM!", e);
		}
	}

}
