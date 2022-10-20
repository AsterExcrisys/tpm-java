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
	 * Get the public part of the used quoting key.
	 * 
	 * @return Public part of the quoting key. The exact structure depends on the
	 *         implementation. Transmit this value to verifyQuote() on the remote
	 *         system.
	 */
	byte[] getQkPub() throws TpmEngineException;

	/**
	 * Quote some PCR registers.
	 * 
	 * @param qualifyingData User data like nonces to be included in the quote.
	 * @param pcrNumbers     Numbers of PCR registers to be included in the quote.
	 * @return the quote. The exact structure depends on the implementation, but it
	 *         includes the signature. Transmit this value to verifyQuote() on the
	 *         remote system.
	 */
	byte[] quote(byte[] qualifyingData, Collection<Integer> pcrNumbers) throws TpmEngineException;

	/**
	 * Create an ephemeral Diffie-Hellman key pair.
	 * 
	 * @return Wrapped Diffie-Hellman key pair.
	 */
	public byte[] createEphemeralDhKey() throws TpmEngineException;

	/**
	 * Get the public part of a created DH key.
	 * 
	 * @param dhKey Wrapped DH key that has been created by this TPM.
	 * @return Public part of the key.
	 */
	public byte[] getDhKeyPub(byte[] dhKey) throws TpmEngineException;

	/**
	 * Certify the public part of the created Diffie-Hellman key by signing it with
	 * the used quoting key.
	 * 
	 * @param dhKey          Wrapped DH key that has been created by this TPM.
	 * @param qualifyingData Nonce of the verifier to be included in the
	 *                       certificate.
	 * @return Certificate structure signed with the used quoting key.
	 */
	public byte[] certifyEphemeralDhKey(byte[] dhKey, byte[] qualifyingData) throws TpmEngineException;

	/**
	 * Create a Diffie-Hellman shared secret with the remote party.
	 * 
	 * @param dhKey           Wrapped DH key that has been created by this TPM.
	 * @param peerKeyPub      Public key of the remote party.
	 * @param peerCertifyInfo Certificate of the remote party.
	 * @param qualifyingData  My nonce that is expected in the certificate.
	 * @param quotingKeyPub   Public part of the remote quoting key.
	 * @return Shared secret or null, if certificate validation failed.
	 */
	public byte[] calculateSharedDhSecret(byte[] dhKey, byte[] peerKeyPub, byte[] peerCertifyInfo,
			byte[] qualifyingData, byte[] quotingKeyPub) throws TpmEngineException;

	/**
	 * Shut down the TPM and close connection.
	 */
	void shutdownTpm() throws TpmEngineException;

	/**
	 * Frees all volatile objects and closes the connection to the TPM.
	 */
	void close();

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
