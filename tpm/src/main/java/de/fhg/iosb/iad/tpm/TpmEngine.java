package de.fhg.iosb.iad.tpm;

import java.util.Collection;
import java.util.Map;

import tss.Tpm;
import tss.tpm.TPM_ALG_ID;

/**
 * Generic TPM engine to abstract from TPM internals and retrieve some common
 * TPM data types as Java objects.
 * 
 * @author wagner
 *
 */
public interface TpmEngine {

	/**
	 * Get the underlying TPM interface.
	 * 
	 * @return The used TPM interface.
	 */
	public Tpm getTpmInterface();

	/**
	 * Return some random bytes.
	 * 
	 * @param number Number of bytes
	 * @return random bytes
	 */
	byte[] getRandomBytes(int number) throws TpmEngineException;

	/**
	 * Get the value of a single PCR register.
	 * 
	 * @param number Number of the PCR register
	 * @return The value of the PCR register as a hex string
	 */
	String getPcrValue(int number) throws TpmEngineException;

	/**
	 * Get the values of multiple PCR registers at once.
	 * 
	 * @param numbers Numbers of the PCR registers
	 * @returnThe values of the PCR registers as hex strings
	 */
	Map<Integer, String> getPcrValues(Collection<Integer> numbers) throws TpmEngineException;

	/**
	 * Extend a single PCR register with some user data.
	 * 
	 * @param number Number of the PCR register
	 * @param data   The user data to extend the PCR register with. The data will be
	 *               hashed with SHA256 before extending.
	 */
	void extendPcr(int number, byte[] data) throws TpmEngineException;

	/**
	 * Extend multiple PCR registers with some user data.
	 * 
	 * @param data The map of PCR registers and user data. The data will be hashed
	 *             with SHA256.
	 */
	void extendPcrs(Map<Integer, byte[]> data) throws TpmEngineException;

	/**
	 * Calculate the digest of a set of PCR values.
	 * 
	 * @param pcrValues Map of PCR values to create the digest for.
	 * @return Digest of specified PCR values.
	 */
	byte[] calculatePcrDigest(Map<Integer, String> pcrValues);

	/**
	 * Calculate the digest of a PCR policy.
	 * 
	 * @param pcrValues   Map of PCR values to create policy digest for.
	 * @param authHashAlg Hash algorithm to use for the policy digest.
	 * @return Digest of a PCR policy bound to the specified PCR values.
	 */
	byte[] calculatePcrPolicyDigest(Map<Integer, String> pcrValues, TPM_ALG_ID authHashAlg) throws TpmEngineException;

	/**
	 * Start an authorization session using a PCR policy.
	 * 
	 * @param pcrNumbers  Numbers of the PCRs to load in the policy.
	 * @param nonceCaller Nonce of the caller to include in the authorization
	 *                    session.
	 * @return Handle of the started authorization session.
	 */
	int startPcrPolicyAuthSession(Collection<Integer> pcrNumbers, byte[] nonceCaller) throws TpmEngineException;

	/**
	 * Load the quoting key.
	 * 
	 * @return The loaded quoting key.
	 */
	TpmLoadedKey loadQk() throws TpmEngineException;

	/**
	 * Load the storage root key.
	 * 
	 * @return The storage root key.
	 */
	TpmLoadedKey loadSrk() throws TpmEngineException;

	/**
	 * Creates an ephemeral Diffie-Hellman key pair.
	 * 
	 * @param rootKeyHandle Handle of the key to use as root.
	 * @return Created Diffie-Hellman key pair.
	 */
	TpmKey createEphemeralDhKey(int rootKeyHandle) throws TpmEngineException;

	/**
	 * Load a key.
	 * 
	 * @param rootKeyHandle The handle of the root key to use.
	 * @param key           The key to load.
	 * @return Handle of the loaded key.
	 */
	int loadKey(int rootKeyHandle, TpmKey key) throws TpmEngineException;

	/**
	 * Flush a key from the TPM.
	 * 
	 * @param handle Key handle to flush.
	 */
	void flushKey(int handle) throws TpmEngineException;

	/**
	 * Certify the public part of a loaded key by signing it with a signature key.
	 * 
	 * @param keyHandle      Handle of key to certify.
	 * @param signerHandle   Handle of key to use for the certification
	 * @param qualifyingData Nonce to be included in the certificate.
	 * @return Certificate structure signed with the specified signature key.
	 */
	byte[] certifyKey(int keyHandle, int signerHandle, byte[] qualifyingData) throws TpmEngineException;

	/**
	 * Quote some PCR registers.
	 * 
	 * @param quotingKeyHandle Handle of the quoting key to use.
	 * @param qualifyingData   User data like nonces to be included in the quote.
	 * @param pcrNumbers       Numbers of PCR registers to be included in the quote.
	 * @return The quote. The exact structure depends on the implementation, but it
	 *         includes the signature. Transmit this value to verifyQuote() on the
	 *         remote system.
	 */
	byte[] quote(int quotingKeyHandle, byte[] qualifyingData, Collection<Integer> pcrNumbers) throws TpmEngineException;

	/**
	 * Generate a shared secret.
	 * 
	 * @param privateKeyHandle Handle of the private key.
	 * @param publicKey        Public key of the remote party.
	 * @return Shared secret.
	 */
	byte[] generateSharedSecret(int privateKeyHandle, byte[] publicKey) throws TpmEngineException;

	/**
	 * Shut down the TPM and close connection.
	 */
	void shutdownTpm() throws TpmEngineException;

	/**
	 * Frees all volatile objects and closes the connection to the TPM.
	 */
	void close();

	public class TpmLoadedKey {
		public final int handle; // TPM_HANDLE.handle
		public final byte[] outPublic; // TPMT_PUBLIC

		public TpmLoadedKey(int handle, byte[] outPublic) {
			this.handle = handle;
			this.outPublic = outPublic;
		}
	}

	public class TpmKey {
		public final byte[] outPrivate; // TPM2B_PRIVATE
		public final byte[] outPublic; // TPMT_PUBLIC

		public TpmKey(byte[] outPrivate, byte[] outPublic) {
			this.outPrivate = outPrivate;
			this.outPublic = outPublic;
		}

	}

	public class TpmEngineException extends Exception {
		private static final long serialVersionUID = -1351431211024276395L;

		public TpmEngineException(String message) {
			super(message);
		}

		public TpmEngineException(String message, Throwable cause) {
			super(message, cause);
		}
	}

}
