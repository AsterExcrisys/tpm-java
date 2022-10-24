package de.fhg.iosb.iad.tpm.attestation.tapdh.handshake;

import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.google.protobuf.ByteString;

import de.fhg.iosb.iad.tpm.TpmEngine;
import de.fhg.iosb.iad.tpm.TpmEngine.TpmEngineException;
import de.fhg.iosb.iad.tpm.TpmEngine.TpmLoadedKey;
import de.fhg.iosb.iad.tpm.TpmValidator;
import de.fhg.iosb.iad.tpm.TpmValidator.TpmValidationException;
import de.fhg.iosb.iad.tpm.attestation.AbortMessage.ErrorCode;
import de.fhg.iosb.iad.tpm.attestation.AttestationMessage;
import de.fhg.iosb.iad.tpm.attestation.FinishMessage;
import de.fhg.iosb.iad.tpm.attestation.ProtocolType;
import de.fhg.iosb.iad.tpm.attestation.tap.handshake.TapHandshaker;
import de.fhg.iosb.iad.tpm.attestation.tapdh.TapDhConfiguration;

public abstract class TapDhHandshaker extends TapHandshaker {

	protected final String hmacString = "TAP key exchange protocol";
	protected KeyPair selfDhKey;
	protected KeyAgreement keyAgreement;
	protected byte[] generatedSecret;
	protected byte[] hmac;
	protected byte[] randomIv;

	protected final TapDhConfiguration config;

	protected TapDhHandshaker(InputStream inputStream, OutputStream outputStream, TapDhConfiguration config) {
		super(inputStream, outputStream, config);
		assert (config != null);
		this.config = config;
	}

	@Override
	public ProtocolType getProtocolType() {
		return ProtocolType.TPM_TAP_DH;
	}

	public byte[] getGeneratedSecret() {
		return generatedSecret;
	}

	public byte[] getRandomIv() {
		return randomIv;
	}

	private static ECPublicKey decodeEcPublicKey(ECParameterSpec params, final byte[] pubkey)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		int keySizeBytes = params.getOrder().bitLength() / Byte.SIZE;

		int offset = 0;
		BigInteger x = new BigInteger(1, Arrays.copyOfRange(pubkey, offset, offset + keySizeBytes));
		offset += keySizeBytes;
		BigInteger y = new BigInteger(1, Arrays.copyOfRange(pubkey, offset, offset + keySizeBytes));
		ECPoint w = new ECPoint(x, y);

		ECPublicKeySpec otherKeySpec = new ECPublicKeySpec(w, params);
		KeyFactory keyFactory = KeyFactory.getInstance("EC");
		ECPublicKey otherKey = (ECPublicKey) keyFactory.generatePublic(otherKeySpec);
		return otherKey;
	}

	private static byte[] encodeEcPublicKey(ECPublicKey pubKey) {
		int keyLengthBytes = pubKey.getParams().getOrder().bitLength() / Byte.SIZE;
		byte[] publicKeyEncoded = new byte[2 * keyLengthBytes];

		int offset = 0;

		BigInteger x = pubKey.getW().getAffineX();
		byte[] xba = x.toByteArray();
		if (xba.length > keyLengthBytes + 1 || xba.length == keyLengthBytes + 1 && xba[0] != 0) {
			throw new IllegalStateException("X coordinate of EC public key has wrong size");
		}

		if (xba.length == keyLengthBytes + 1) {
			System.arraycopy(xba, 1, publicKeyEncoded, offset, keyLengthBytes);
		} else {
			System.arraycopy(xba, 0, publicKeyEncoded, offset + keyLengthBytes - xba.length, xba.length);
		}
		offset += keyLengthBytes;

		BigInteger y = pubKey.getW().getAffineY();
		byte[] yba = y.toByteArray();
		if (yba.length > keyLengthBytes + 1 || yba.length == keyLengthBytes + 1 && yba[0] != 0) {
			throw new IllegalStateException("Y coordinate of EC public key has wrong size");
		}

		if (yba.length == keyLengthBytes + 1) {
			System.arraycopy(yba, 1, publicKeyEncoded, offset, keyLengthBytes);
		} else {
			System.arraycopy(yba, 0, publicKeyEncoded, offset + keyLengthBytes - yba.length, yba.length);
		}

		return publicKeyEncoded;
	}

	@Override
	protected void createAttestation(AttestationMessage.Builder builder) throws HandshakeException {
		byte[] qualifyingData = null;
		try {
			// Create DH key
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
			ECGenParameterSpec spec = new ECGenParameterSpec("secp256r1");
			kpg.initialize(spec);
			selfDhKey = kpg.generateKeyPair();

			byte[] selfDhKeyPub = encodeEcPublicKey((ECPublicKey) selfDhKey.getPublic());
			builder.setPublicKey(ByteString.copyFrom(selfDhKeyPub));
			keyAgreement = KeyAgreement.getInstance("ECDH");
			keyAgreement.init(selfDhKey.getPrivate());

			// Calculate qualifying data
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			digest.update(peerNonce);
			digest.update(selfDhKeyPub);
			qualifyingData = digest.digest();
		} catch (GeneralSecurityException e) {
			throw new HandshakeException(ErrorCode.INTERNAL_ERROR, "Failed to generate ECDH key!", e);
		}

		TpmEngine tpmEngine = config.getTpmEngine();
		synchronized (tpmEngine) {
			TpmLoadedKey qk = null;
			try {
				// Create quote
				qk = tpmEngine.loadQk();
				selfQk = qk.outPublic;
				builder.setQuotingKey(ByteString.copyFrom(selfQk));
				builder.putAllPcrValues(tpmEngine.getPcrValues(peerPcrSelection));
				byte[] quote = tpmEngine.quote(qk.handle, qualifyingData, peerPcrSelection);
				builder.setQuote(ByteString.copyFrom(quote));
			} catch (TpmEngineException e) {
				throw new HandshakeException("Error while using the TPM.", e);
			} finally {
				try {
					if (qk != null)
						tpmEngine.flushKey(qk.handle);
				} catch (TpmEngineException e) {
				}
			}
		}
	}

	@Override
	protected void handleAttestation(AttestationMessage message) throws HandshakeException {
		peerQk = message.getQuotingKey().toByteArray();
		peerPcrValues = message.getPcrValuesMap();
		byte[] peerQuote = message.getQuote().toByteArray();
		byte[] peerDhKeyPub = message.getPublicKey().toByteArray();

		// Validate PCR selection
		if (!peerPcrValues.keySet().containsAll(config.getPcrSelection())) {
			throw new HandshakeException(ErrorCode.BAD_PCR_SELECTION,
					"Requested PCR selection " + config.getPcrSelection() + " but got " + peerPcrValues.keySet());
		}

		// Calculate qualifying data
		byte[] qualifyingData = null;
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			digest.update(selfNonce);
			digest.update(peerDhKeyPub);
			qualifyingData = digest.digest();
		} catch (GeneralSecurityException e) {
			throw new HandshakeException(ErrorCode.INTERNAL_ERROR, "Failed to calculate qualifying data!", e);
		}

		// Validate quote
		try {
			if (!new TpmValidator().validateQuote(peerQuote, qualifyingData, peerQk, peerPcrValues))
				throw new HandshakeException(ErrorCode.BAD_QUOTE, "Validation of peer quote failed!");
		} catch (TpmValidationException e) {
			throw new HandshakeException(ErrorCode.BAD_QUOTE, "Validation of peer quote failed!", e);
		}

		// Generate shared secret
		try {
			ECParameterSpec spec = ((ECPublicKey) selfDhKey.getPublic()).getParams();
			keyAgreement.doPhase(decodeEcPublicKey(spec, peerDhKeyPub), true);
			generatedSecret = keyAgreement.generateSecret();
		} catch (GeneralSecurityException e) {
			throw new HandshakeException(ErrorCode.INTERNAL_ERROR, "Failed to generate key agreement!", e);
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
