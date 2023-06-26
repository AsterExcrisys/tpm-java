package de.fhg.iosb.iad.tpm;

import java.util.Arrays;
import java.util.Map;

import tss.Crypto;
import tss.TpmBuffer;
import tss.tpm.CertifyCreationResponse;
import tss.tpm.CertifyResponse;
import tss.tpm.PCR_ReadResponse;
import tss.tpm.QuoteResponse;
import tss.tpm.TPMA_OBJECT;
import tss.tpm.TPMS_CERTIFY_INFO;
import tss.tpm.TPMS_CREATION_DATA;
import tss.tpm.TPMS_CREATION_INFO;
import tss.tpm.TPMT_PUBLIC;
import tss.tpm.TPM_ALG_ID;

public class TpmValidator {

	private static final TPM_ALG_ID pcrHashAlg = TPM_ALG_ID.SHA256;

	/**
	 * Validate a key certification.
	 * 
	 * @param keyPub         Public part of the certified key.
	 * @param certifyInfo    Certification information for the public key to verify.
	 * @param qualifyingData User data like nonces that is expected in the
	 *                       certification.
	 * @param signerKeyPub   Public key of the signer.
	 * @return True if the provided signature validated correctly for this key,
	 *         false otherwise.
	 * @throws TpmValidationException If validation failed.
	 */
	public boolean validateKeyCertification(byte[] keyPub, byte[] certifyInfo, byte[] qualifyingData,
			byte[] signerKeyPub) throws TpmValidationException {

		TPMT_PUBLIC _keyPub = null;
		CertifyResponse _certifyInfo = null;
		TPMT_PUBLIC _signerKeyPub = null;
		try {
			_keyPub = TPMT_PUBLIC.fromBytes(keyPub);
			_certifyInfo = CertifyResponse.fromBytes(certifyInfo);
			_signerKeyPub = TPMT_PUBLIC.fromBytes(signerKeyPub);
		} catch (Exception e) {
			throw new TpmValidationException("Error while parsing TPM data structures", e);
		}

		// Verify that certifyInfo contains the expected qualifyingData
		if (!Arrays.equals(_certifyInfo.certifyInfo.extraData, qualifyingData))
			throw new TpmValidationException("Provided certification does not contain the expected qualifying data!");

		// Verify that certifyInfo contains the claimed public key
		if (!Arrays.equals(((TPMS_CERTIFY_INFO) _certifyInfo.certifyInfo.attested).name, _keyPub.getName()))
			throw new TpmValidationException("Provided certification does not certify the expected public key!");

		// Verify signature of certifyInfo
		return _signerKeyPub.validateSignature(_certifyInfo.certifyInfo.toBytes(), _certifyInfo.signature);
	}

	/**
	 * Validate a creation certification.
	 * 
	 * @param keyPub         Public part of the certified key.
	 * @param certifyInfo    Certification information for the public key to verify.
	 * @param qualifyingData User data like nonces that is expected in the
	 *                       certification.
	 * @param signerKeyPub   Public key of the signer.
	 * @param creationData   Creation data of the certified key.
	 * @param pcrValues      Map of PCR values as hex strings that are expected in
	 *                       the creation data.
	 * @return True if the provided signature validated correctly for this key,
	 *         false otherwise.
	 * @throws TpmValidationException If validation failed.
	 */
	public boolean validateCreationCertification(byte[] keyPub, byte[] certifyInfo, byte[] qualifyingData,
			byte[] signerKeyPub, byte[] creationData, Map<Integer, String> pcrValues) throws TpmValidationException {

		TPMT_PUBLIC _keyPub = null;
		CertifyCreationResponse _certifyInfo = null;
		TPMT_PUBLIC _signerKeyPub = null;
		TPMS_CREATION_DATA _creationData = null;
		try {
			_keyPub = TPMT_PUBLIC.fromBytes(keyPub);
			_certifyInfo = CertifyCreationResponse.fromBytes(certifyInfo);
			_signerKeyPub = TPMT_PUBLIC.fromBytes(signerKeyPub);
			_creationData = TPMS_CREATION_DATA.fromBytes(creationData);
		} catch (Exception e) {
			throw new TpmValidationException("Error while parsing TPM data structures", e);
		}

		// Verify that certifyInfo contains the expected qualifyingData
		if (!Arrays.equals(_certifyInfo.certifyInfo.extraData, qualifyingData))
			throw new TpmValidationException("Provided certification does not contain the expected qualifying data!");

		// Verify that certifyInfo contains the claimed public key
		if (!Arrays.equals(((TPMS_CREATION_INFO) _certifyInfo.certifyInfo.attested).objectName, _keyPub.getName()))
			throw new TpmValidationException("Provided certification does not certify the expected public key!");

		// Verify that certifyInfo contains the claimed creationData
		byte[] expectedCreationHash = Crypto.hash(_keyPub.nameAlg, creationData);
		if (!Arrays.equals(((TPMS_CREATION_INFO) _certifyInfo.certifyInfo.attested).creationHash, expectedCreationHash))
			throw new TpmValidationException("Provided certification does not certify the expected creation data!");

		// Verify that creationData contains the claimed PCRs
		PCR_ReadResponse expectedPcrs = new PCR_ReadResponse();
		expectedPcrs.pcrSelectionOut = TpmHelper.createPcrSelectionArray(pcrValues.keySet(), pcrHashAlg);
		expectedPcrs.pcrValues = TpmHelper.createPcrDigests(pcrValues);
		expectedPcrs.pcrUpdateCounter = 0;
		TpmBuffer pcrBuf = new TpmBuffer();
		for (int j = 0; j < expectedPcrs.pcrValues.length; j++) {
			pcrBuf.writeByteBuf(expectedPcrs.pcrValues[j].buffer);
		}
		byte[] expectedPcrDigest = Crypto.hash(_creationData.parentNameAlg, pcrBuf.trim());
		if (!Arrays.equals(_creationData.pcrDigest, expectedPcrDigest))
			throw new TpmValidationException("Provided certification does not contain the expected PCR values!");

		// Verify signature of certifyInfo
		return _signerKeyPub.validateSignature(_certifyInfo.certifyInfo.toBytes(), _certifyInfo.signature);
	}

	/**
	 * Validate a received quote.
	 * 
	 * @param quote          The received quote, which has been generated by quote()
	 *                       on the remote system.
	 * @param qualifyingData User data like nonces that are expected in the quote.
	 * @param quotingKeyPub  Public part of the key that has been used to generate
	 *                       the quote (i.e. that can verify the signature of the
	 *                       quote's data part).
	 * @param pcrValues      Map of PCR values as hex strings that are expected in
	 *                       this quote.
	 * @return True if the quote signature validated correctly, false otherwise.
	 * @throws TpmValidationException If quote validation failed.
	 */
	public boolean validateQuote(byte[] quote, byte[] qualifyingData, byte[] quotingKeyPub,
			Map<Integer, String> pcrValues) throws TpmValidationException {
		TPMT_PUBLIC remoteQk = null;
		QuoteResponse remoteQuote = null;
		try {
			remoteQuote = QuoteResponse.fromBytes(quote);
			remoteQk = TPMT_PUBLIC.fromBytes(quotingKeyPub);
		} catch (Exception e) {
			throw new TpmValidationException("Error while parsing TPM data structures", e);
		}
		// Verify attributes of remote quoting key
		if (!remoteQk.objectAttributes.hasAttr(TPMA_OBJECT.restricted))
			throw new TpmValidationException("Provided quoting key is not restricted!");
		if (!remoteQk.objectAttributes.hasAttr(TPMA_OBJECT.sign))
			throw new TpmValidationException("Provided quoting key is not a signing key!");

		// Validate quote
		PCR_ReadResponse expectedPcrs = new PCR_ReadResponse();
		expectedPcrs.pcrSelectionOut = TpmHelper.createPcrSelectionArray(pcrValues.keySet(), pcrHashAlg);
		expectedPcrs.pcrValues = TpmHelper.createPcrDigests(pcrValues);
		expectedPcrs.pcrUpdateCounter = 0;
		return remoteQk.validateQuote(expectedPcrs, qualifyingData, remoteQuote);
	}

	public class TpmValidationException extends Exception {
		private static final long serialVersionUID = -716724242433504311L;

		public TpmValidationException(String message) {
			super(message);
		}

		public TpmValidationException(String message, Throwable cause) {
			super(message, cause);
		}
	}
}
