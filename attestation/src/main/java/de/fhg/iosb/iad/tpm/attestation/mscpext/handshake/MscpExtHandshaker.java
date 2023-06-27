package de.fhg.iosb.iad.tpm.attestation.mscpext.handshake;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;

import javax.crypto.KeyAgreement;

import com.google.protobuf.ByteString;

import de.fhg.iosb.iad.tpm.SecurityHelper;
import de.fhg.iosb.iad.tpm.TpmEngine;
import de.fhg.iosb.iad.tpm.TpmEngine.TpmEngineException;
import de.fhg.iosb.iad.tpm.TpmEngine.TpmLoadedKey;
import de.fhg.iosb.iad.tpm.TpmValidator;
import de.fhg.iosb.iad.tpm.TpmValidator.TpmValidationException;
import de.fhg.iosb.iad.tpm.attestation.AbortMessage.ErrorCode;
import de.fhg.iosb.iad.tpm.attestation.AttestationMessage;
import de.fhg.iosb.iad.tpm.attestation.InitMessage;
import de.fhg.iosb.iad.tpm.attestation.ProtocolType;
import de.fhg.iosb.iad.tpm.attestation.tapdh.TapDhConfiguration;
import de.fhg.iosb.iad.tpm.attestation.tapdh.handshake.TapDhHandshaker;

public abstract class MscpExtHandshaker extends TapDhHandshaker {

	protected MscpExtHandshaker(InputStream inputStream, OutputStream outputStream, TapDhConfiguration config) {
		super(inputStream, outputStream, config);
	}

	@Override
	public ProtocolType getProtocolType() {
		return ProtocolType.TPM_MSCP_EXT;
	}

	public byte[] getGeneratedSecret() {
		return generatedSecret;
	}

	public byte[] getRandomIv() {
		return randomIv;
	}

	@Override
	protected void createInit(InitMessage.Builder builder) throws HandshakeException {
		super.createInit(builder);
		builder.addPcrSelection(16);
	}

	@Override
	protected void createAttestation(AttestationMessage.Builder builder) throws HandshakeException {
		byte[] selfDhKeyPub = null;
		try {
			// Create DH key
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
			ECGenParameterSpec spec = new ECGenParameterSpec("secp256r1");
			kpg.initialize(spec);
			selfDhKey = kpg.generateKeyPair();

			selfDhKeyPub = encodeEcPublicKey((ECPublicKey) selfDhKey.getPublic());
			builder.setPublicKey(ByteString.copyFrom(selfDhKeyPub));
			keyAgreement = KeyAgreement.getInstance("ECDH");
			keyAgreement.init(selfDhKey.getPrivate());
		} catch (GeneralSecurityException e) {
			throw new HandshakeException(ErrorCode.INTERNAL_ERROR, "Failed to generate ECDH key!", e);
		}

		TpmEngine tpmEngine = config.getTpmEngine();
		synchronized (tpmEngine) {
			try {
				// Create quote
				TpmLoadedKey qk = config.getQuotingKey();
				selfQk = qk.outPublic;
				builder.setQuotingKey(ByteString.copyFrom(selfQk));
				tpmEngine.resetPcr(16);
				tpmEngine.extendPcr(16, selfDhKeyPub);
				byte[] quote = tpmEngine.quote(qk.handle, peerNonce, peerPcrSelection);
				builder.putAllPcrValues(tpmEngine.getPcrValues(peerPcrSelection));
				builder.setQuote(ByteString.copyFrom(quote));
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
		byte[] peerDhKeyPub = message.getPublicKey().toByteArray();

		// Validate PCR selection
		if (!peerPcrValues.keySet().containsAll(config.getPcrSelection())) {
			throw new HandshakeException(ErrorCode.BAD_PCR_SELECTION,
					"Requested PCR selection " + config.getPcrSelection() + " but got " + peerPcrValues.keySet());
		}
		if (!peerPcrValues.keySet().contains(16)) {
			throw new HandshakeException(ErrorCode.BAD_PCR_SELECTION,
					"Necessary PCR 16 not included in peer PCR selection! Got: " + peerPcrValues.keySet());
		}

		// Validate quote
		try {
			if (!new TpmValidator().validateQuote(peerQuote, selfNonce, peerQk, peerPcrValues))
				throw new HandshakeException(ErrorCode.BAD_QUOTE, "Validation of peer quote failed!");
		} catch (TpmValidationException e) {
			throw new HandshakeException(ErrorCode.BAD_QUOTE, "Validation of peer quote failed!", e);
		}

		// Validate DH public key
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			digest.update(peerDhKeyPub);
			byte[] dataToExtend = digest.digest();
			digest.reset();
			digest.update(new byte[32]);
			digest.update(dataToExtend);
			if (!peerPcrValues.get(16).equalsIgnoreCase(SecurityHelper.bytesToHex(digest.digest())))
				throw new HandshakeException(ErrorCode.BAD_CERT, "Peer public DH key is not contained in PCR 16!");
		} catch (GeneralSecurityException e) {
			throw new HandshakeException(ErrorCode.INTERNAL_ERROR, "Failed to recalculate PCR 16!", e);
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

}
