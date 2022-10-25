package de.fhg.iosb.iad.tpm;

import de.fhg.iosb.iad.tpm.TpmEngine.TpmEngineException;
import tss.Tpm;
import tss.TpmDevice;
import tss.TpmDeviceLinux;
import tss.TpmDeviceTbs;
import tss.TpmDeviceTcp;
import tss.tpm.TPM_HANDLE;
import tss.tpm.TPM_RH;
import tss.tpm.TPM_SU;

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
			Tpm tpm = tssSimInitialized ? remoteTpm(host, port) : localTpmSimulator(host, port);
			tssSimInitialized = true;
			return new TpmEngineImpl(tpm);
		} catch (Exception e) {
			throw new TpmEngineException("Failed to connect to TPM simulator!", e);
		}
	}

	public static TpmEngineImpl createPlatformInstance() throws TpmEngineException {
		try {
			return new TpmEngineImpl(platformTpm());
		} catch (Exception e) {
			throw new TpmEngineException("Failed to connect to platform TPM!", e);
		}
	}

	private static Tpm localTpmSimulator(String host, int port) {
		Tpm tpm = new Tpm();
		TpmDevice device = new TpmDeviceTcp(host, port);
		device.connect();
		device.powerCycle();
		tpm = new Tpm();
		tpm._setDevice(device);
		tpm.Startup(TPM_SU.CLEAR);
		tpm.DictionaryAttackLockReset(TPM_HANDLE.from(TPM_RH.LOCKOUT));
		return tpm;
	}

	private static Tpm remoteTpm(String hostName, int port) {
		Tpm tpm = new Tpm();
		TpmDevice device = new TpmDeviceTcp(hostName, port);
		device.connect();
		tpm._setDevice(device);
		return tpm;
	}

	private static Tpm platformTpm() {
		Tpm tpm = new Tpm();
		String osName = System.getProperty("os.name");
		TpmDevice device = null;
		if (osName.contains("Windows"))
			device = new TpmDeviceTbs();
		else {
			// First, try to connect to the kernel mode TRM (TPM resource manager) or system
			// TPM
			try {
				device = new TpmDeviceLinux();
			} catch (Exception e) {
				// Now try to connect to the user mode TRM (TPM resource manager)
				device = new TpmDeviceTcp("localhost", 2323, true);
				// System.out.println("Connected to the user mode TPM Resource Manager");
			}
		}
		if (!device.connect()) {
			device.close();
			return null;
		}
		tpm._setDevice(device);
		return tpm;
	}

}
