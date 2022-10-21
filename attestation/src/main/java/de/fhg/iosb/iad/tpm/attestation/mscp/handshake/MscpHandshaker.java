package de.fhg.iosb.iad.tpm.attestation.mscp.handshake;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.google.protobuf.ByteString;

import de.fhg.iosb.iad.tpm.TpmEngine.TpmEngineException;
import de.fhg.iosb.iad.tpm.TpmValidator;
import de.fhg.iosb.iad.tpm.attestation.AbortMessage.ErrorCode;
import de.fhg.iosb.iad.tpm.attestation.AttestationMessage;
import de.fhg.iosb.iad.tpm.attestation.FinishMessage;
import de.fhg.iosb.iad.tpm.attestation.KeyEstablishmentMessage;
import de.fhg.iosb.iad.tpm.attestation.ProtocolType;
import de.fhg.iosb.iad.tpm.attestation.mscp.MscpConfiguration;
import de.fhg.iosb.iad.tpm.attestation.tap.handshake.TapHandshaker;

public abstract class MscpHandshaker extends TapHandshaker {

	protected final String hmacString = "MSCP key exchange protocol";
	protected byte[] selfDhKey;
	protected byte[] generatedDhZ;
	protected byte[] hmac;
	protected byte[] randomIv;

	private final MscpConfiguration config;

	protected MscpHandshaker(InputStream inputStream, OutputStream outputStream, MscpConfiguration config) {
		super(inputStream, outputStream, config);
		assert (config != null);
		this.config = config;
	}

	@Override
	public ProtocolType getProtocolType() {
		return ProtocolType.TPM_MSCP;
	}

	public byte[] getGeneratedDhZ() {
		return generatedDhZ;
	}

	public byte[] getRandomIv() {
		return randomIv;
	}

	protected void createAttestation(AttestationMessage.Builder builder) throws HandshakeException {
		try {
			builder.putAllPcrValues(config.getTpmEngine().getPcrValues(peerPcrSelection));
			byte[] quote = config.getTpmEngine().quote(peerNonce, peerPcrSelection);
			builder.setQuote(ByteString.copyFrom(quote));
		} catch (TpmEngineException e) {
			throw new HandshakeException("Error while using the TPM.", e);
		}
	}

	protected void handleAttestation(AttestationMessage message) throws HandshakeException {
		peerPcrValues = message.getPcrValuesMap();
		byte[] peerQuote = message.getQuote().toByteArray();

		if (!peerPcrValues.keySet().containsAll(config.getPcrSelection())) {
			throw new HandshakeException(ErrorCode.BAD_PCR_SELECTION,
					"Requested PCR selection " + config.getPcrSelection() + " but got " + peerPcrValues.keySet());
		}

		try {
			if (!new TpmValidator().validateQuote(peerQuote, selfNonce, peerQk, peerPcrValues))
				throw new HandshakeException(ErrorCode.BAD_QUOTE, "Verification of peer quote failed!");
		} catch (TpmEngineException e) {
			throw new HandshakeException("Error while using the TPM.", e);
		}
	}

	protected void createKeyEstablishment(KeyEstablishmentMessage.Builder builder) throws HandshakeException {
		try {
			selfDhKey = config.getTpmEngine().createEphemeralDhKey();
			builder.setPublicKey(ByteString.copyFrom(config.getTpmEngine().getDhKeyPub(selfDhKey)));
			builder.setCertificate(
					ByteString.copyFrom(config.getTpmEngine().certifyEphemeralDhKey(selfDhKey, peerNonce)));
		} catch (TpmEngineException e) {
			throw new HandshakeException("Error while using the TPM.", e);
		}
	}

	protected void handleKeyEstablishment(KeyEstablishmentMessage message) throws HandshakeException {
		byte[] peerDhKeyPub = message.getPublicKey().toByteArray();
		byte[] peerDhCert = message.getCertificate().toByteArray();

		try {
			generatedDhZ = config.getTpmEngine().calculateSharedDhSecret(selfDhKey, peerDhKeyPub, peerDhCert, selfNonce,
					peerQk);
		} catch (TpmEngineException e) {
			throw new HandshakeException("Error while using the TPM.", e);
		}

		if (generatedDhZ == null)
			throw new HandshakeException(ErrorCode.BAD_CERT, "Verification of peer Diffie-Hellman certificate failed!");
	}

	private void generateHmac() throws HandshakeException {
		try {
			SecretKeySpec secretKeySpec = new SecretKeySpec(generatedDhZ, "HmacSHA256");
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
