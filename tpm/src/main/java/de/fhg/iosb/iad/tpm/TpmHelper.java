package de.fhg.iosb.iad.tpm;

import java.util.Arrays;
import java.util.Collection;
import java.util.Map;

import de.fhg.iosb.iad.tpm.TpmEngine.TpmEngineException;
import tss.tpm.CertifyResponse;
import tss.tpm.QuoteResponse;
import tss.tpm.TPM2B_DIGEST;
import tss.tpm.TPMS_PCR_SELECTION;
import tss.tpm.TPMT_PUBLIC;
import tss.tpm.TPM_ALG_ID;

public final class TpmHelper {

	/**
	 * Create PCR selection.
	 * 
	 * @param numbers Numbers of PCR registers to include in the selection.
	 * @param hashAlg PCR hash algorithm to use.
	 * @return The PCR selection.
	 */
	public static TPMS_PCR_SELECTION createPcrSelection(Collection<Integer> numbers, TPM_ALG_ID hashAlg) {
		int[] numbersArray = numbers.stream().mapToInt(i -> i).toArray();
		return createPcrSelection(numbersArray, hashAlg);
	}

	/**
	 * Create PCR selection.
	 * 
	 * @param numbersArray Numbers of PCR registers to include in the selection.
	 *                     This array will be sorted by calling this method.
	 * @param hashAlg      PCR hash algorithm to use.
	 * @return The PCR selection.
	 */
	public static TPMS_PCR_SELECTION createPcrSelection(int[] numbersArray, TPM_ALG_ID hashAlg) {
		Arrays.sort(numbersArray); // Sort numbers to make result deterministic
		return new TPMS_PCR_SELECTION(hashAlg, numbersArray);
	}

	/**
	 * Create PCR selection array with one element.
	 * 
	 * @param numbers Numbers of PCR registers to include in the first element of
	 *                the selection array. If empty, an empty array will be
	 *                returned.
	 * @param hashAlg PCR hash algorithm to use.
	 * @return The PCR selection array.
	 */
	public static TPMS_PCR_SELECTION[] createPcrSelectionArray(Collection<Integer> numbers, TPM_ALG_ID hashAlg) {
		if (numbers.isEmpty())
			return new TPMS_PCR_SELECTION[0];
		return new TPMS_PCR_SELECTION[] { createPcrSelection(numbers, hashAlg) };
	}

	/**
	 * Create PCR digest.
	 * 
	 * @param pcrValues PCR values to digest.
	 * @return The PCR digest.
	 */
	public static TPM2B_DIGEST[] createPcrDigests(Map<Integer, String> pcrValues) {
		int[] numbersArray = pcrValues.keySet().stream().mapToInt(i -> i).toArray();
		Arrays.sort(numbersArray); // Sort numbers to make result deterministic

		TPM2B_DIGEST[] pcrDigests = new TPM2B_DIGEST[numbersArray.length];
		int i = 0;
		for (int number : numbersArray)
			pcrDigests[i++] = new TPM2B_DIGEST(SecurityHelper.hexToBytes(pcrValues.get(number)));

		return pcrDigests;
	}

	/**
	 * Convert public key provided by this TPM into a printable string.
	 * 
	 * @param publicKey Public key blob provided by this TPM interface.
	 * @return Public key in printable form.
	 */
	public static String prettyPrintPublicKey(byte[] publicKey) throws TpmEngineException {
		TPMT_PUBLIC _publicKey = null;
		try {
			_publicKey = TPMT_PUBLIC.fromBytes(publicKey);
		} catch (Exception e) {
			throw new TpmEngineException("Error while parsing TPM data structures", e);
		}
		return _publicKey.toString();
	}

	/**
	 * Convert quote provided by this TPM into a printable string.
	 * 
	 * @param quote Quote blob provided by this TPM interface.
	 * @return Quote in printable form.
	 */
	public static String prettyPrintQuote(byte[] quote) throws TpmEngineException {
		QuoteResponse _quote = null;
		try {
			_quote = QuoteResponse.fromBytes(quote);
		} catch (Exception e) {
			throw new TpmEngineException("Error while parsing TPM data structures", e);
		}
		return _quote.toString();
	}

	/**
	 * Convert certificate provided by this TPM into a printable string.
	 * 
	 * @param cert Certificate blob provided by this TPM interface.
	 * @return Certificate in printable form.
	 */
	public static String prettyPrintCertificate(byte[] cert) throws TpmEngineException {
		CertifyResponse _cert = null;
		try {
			_cert = CertifyResponse.fromBytes(cert);
		} catch (Exception e) {
			throw new TpmEngineException("Error while parsing TPM data structures", e);
		}
		return _cert.toString();
	}
}
