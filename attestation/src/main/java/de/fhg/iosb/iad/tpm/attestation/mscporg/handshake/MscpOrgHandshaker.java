package de.fhg.iosb.iad.tpm.attestation.mscporg.handshake;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.google.protobuf.ByteString;

import de.fhg.iosb.iad.tpm.TpmEngine;
import de.fhg.iosb.iad.tpm.TpmEngine.TpmEngineException;
import de.fhg.iosb.iad.tpm.TpmEngine.TpmKey;
import de.fhg.iosb.iad.tpm.TpmEngine.TpmLoadedKey;
import de.fhg.iosb.iad.tpm.TpmValidator;
import de.fhg.iosb.iad.tpm.TpmValidator.TpmValidationException;
import de.fhg.iosb.iad.tpm.attestation.AbortMessage.ErrorCode;
import de.fhg.iosb.iad.tpm.attestation.mscporg.MscpOrgConfiguration;
import de.fhg.iosb.iad.tpm.attestation.AttestationMessage;
import de.fhg.iosb.iad.tpm.attestation.FinishMessage;
import de.fhg.iosb.iad.tpm.attestation.ProtocolType;
import de.fhg.iosb.iad.tpm.attestation.tap.handshake.TapHandshaker;

public abstract class MscpOrgHandshaker extends TapHandshaker {

	protected final String hmacString = "MSCP key exchange protocol";
	protected TpmKey selfDhKey;
	protected byte[] generatedSecret;
	protected byte[] hmac;
	protected byte[] randomIv;

	protected final MscpOrgConfiguration config;

	protected MscpOrgHandshaker(InputStream inputStream, OutputStream outputStream, MscpOrgConfiguration config) {
		super(inputStream, outputStream, config);
		assert (config != null);
		this.config = config;
	}

	@Override
	public ProtocolType getProtocolType() {
		return ProtocolType.TPM_MSCP_ORG;
	}

	public byte[] getGeneratedSecret() {
		return generatedSecret;
	}

	public byte[] getRandomIv() {
		return randomIv;
	}

	@Override
	protected void createAttestation(AttestationMessage.Builder builder) throws HandshakeException {
		TpmEngine tpmEngine = config.getTpmEngine();
		synchronized (tpmEngine) {
			try {
				// Create quote
				TpmLoadedKey qk = config.getQuotingKey();
				selfQk = qk.outPublic;
				builder.setQuotingKey(ByteString.copyFrom(selfQk));
				builder.putAllPcrValues(tpmEngine.getPcrValues(peerPcrSelection));
				byte[] quote = tpmEngine.quote(qk.handle, peerNonce, peerPcrSelection);
				builder.setQuote(ByteString.copyFrom(quote));

				// Create and certify DH key
				TpmLoadedKey srk = config.getRootKey();
				selfDhKey = tpmEngine.createEphemeralDhKey(srk.handle);
				builder.setPublicKey(ByteString.copyFrom(selfDhKey.outPublic));
				int selfDhKeyHandle = tpmEngine.loadKey(srk.handle, selfDhKey);
				try {
					byte[] cert = tpmEngine.certifyKey(selfDhKeyHandle, qk.handle, peerNonce);
					builder.setCertificate(ByteString.copyFrom(cert));
				} finally {
					tpmEngine.flushKey(selfDhKeyHandle);
				}
			} catch (TpmEngineException e) {
				throw new HandshakeException("Error while using the TPM.", e);
			}
		}
	}

	@Override
	protected void handleAttestation(AttestationMessage message) throws HandshakeException {
		peerQk = message.getQuotingKey().toByteArray();
		peerPcrValues = message.getPcrValuesMap();
		byte[] peerQuote = message.getQuote().toByteArray();

		// Validate PCR selection
		if (!peerPcrValues.keySet().containsAll(config.getPcrSelection())) {
			throw new HandshakeException(ErrorCode.BAD_PCR_SELECTION,
					"Requested PCR selection " + config.getPcrSelection() + " but got " + peerPcrValues.keySet());
		}

		// Validate quote
		try {
			if (!new TpmValidator().validateQuote(peerQuote, selfNonce, peerQk, peerPcrValues))
				throw new HandshakeException(ErrorCode.BAD_QUOTE, "Validation of peer quote failed!");
		} catch (TpmValidationException e) {
			throw new HandshakeException(ErrorCode.BAD_QUOTE, "Validation of peer quote failed!", e);
		}

		// Validate certificate
		byte[] peerDhKeyPub = message.getPublicKey().toByteArray();
		byte[] peerDhCert = message.getCertificate().toByteArray();
		try {
			if (!new TpmValidator().validateKeyCertification(peerDhKeyPub, peerDhCert, selfNonce, peerQk))
				throw new HandshakeException(ErrorCode.BAD_CERT, "Validation of presented certificate failed!");
		} catch (TpmValidationException e) {
			throw new HandshakeException(ErrorCode.BAD_CERT, "Validation of presented certificate failed!", e);
		}

		// Generate shared secret
		TpmEngine tpmEngine = config.getTpmEngine();
		synchronized (tpmEngine) {
			try {
				TpmLoadedKey srk = config.getRootKey();
				int selfDhKeyHandle = tpmEngine.loadKey(srk.handle, selfDhKey);
				try {
					generatedSecret = tpmEngine.generateSharedSecret(selfDhKeyHandle, peerDhKeyPub);
				} finally {
					tpmEngine.flushKey(selfDhKeyHandle);
				}
			} catch (TpmEngineException e) {
				throw new HandshakeException("Error while using the TPM.", e);
			}
		}
	}

	private void generateHmac() throws HandshakeException {
		try {
			SecretKeySpec secretKeySpec = new SecretKeySpec(generatedSecret, "HmacSHA256");
			Mac mac = Mac.getInstance("HmacSHA256");
			mac.init(secretKeySpec);
			hmac = mac.doFinal(new String(hmacString).getBytes());
		} catch (GeneralSecurityException e) {
			throw new HandshakeException(ErrorCode.INTERNAL_ERROR, "Failed to generate HMAC!", e);
		}
	}

	protected void createFinish(FinishMessage.Builder builder) throws HandshakeException {
		if (hmac == null) {
			generateHmac();
		}
		builder.setHmac(ByteString.copyFrom(hmac));

		if (randomIv == null) {
			randomIv = new byte[16];
			new SecureRandom().nextBytes(randomIv);
			builder.setIv(ByteString.copyFrom(randomIv));
		}
	}

	protected void handleFinish(FinishMessage message) throws HandshakeException {
		if (hmac == null) {
			generateHmac();
		}

		if (!Arrays.equals(hmac, message.getHmac().toByteArray())) {
			throw new HandshakeException(ErrorCode.BAD_HMAC, "HMACs do not match!");
		}

		if (randomIv == null) {
			randomIv = message.getIv().toByteArray();
		}
	}

}
