package de.fhg.iosb.iad.tpm.attestation.tapssl.handshake;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;

import com.google.protobuf.ByteString;

import de.fhg.iosb.iad.tpm.SecurityHelper;
import de.fhg.iosb.iad.tpm.TpmEngine;
import de.fhg.iosb.iad.tpm.TpmEngine.TpmEngineException;
import de.fhg.iosb.iad.tpm.TpmEngine.TpmLoadedKey;
import de.fhg.iosb.iad.tpm.TpmValidator;
import de.fhg.iosb.iad.tpm.TpmValidator.TpmValidationException;
import de.fhg.iosb.iad.tpm.attestation.AbortMessage.ErrorCode;
import de.fhg.iosb.iad.tpm.attestation.AttestationMessage;
import de.fhg.iosb.iad.tpm.attestation.ProtocolType;
import de.fhg.iosb.iad.tpm.attestation.tap.handshake.TapHandshaker;
import de.fhg.iosb.iad.tpm.attestation.tapssl.TapSslConfiguration;

public abstract class TapSslHandshaker extends TapHandshaker {

	private final TapSslConfiguration config;

	protected TapSslHandshaker(InputStream inputStream, OutputStream outputStream, TapSslConfiguration config) {
		super(inputStream, outputStream, config);
		assert (config != null);
		this.config = config;
	}

	@Override
	public ProtocolType getProtocolType() {
		return ProtocolType.TPM_TAP_SSL;
	}

	protected void createAttestation(AttestationMessage.Builder builder) throws HandshakeException {
		TpmEngine tpmEngine = config.getTpmEngine();
		synchronized (tpmEngine) {
			TpmLoadedKey qk = null;
			try {
				qk = tpmEngine.loadQk();
				selfQk = qk.outPublic;
				builder.setQuotingKey(ByteString.copyFrom(selfQk));
				builder.putAllPcrValues(tpmEngine.getPcrValues(peerPcrSelection));

				Certificate[] peerCertificates = config.getPeerCertificates();
				if (peerCertificates == null || peerCertificates.length == 0)
					throw new HandshakeException(ErrorCode.BAD_CERT, "Failed to get peer certificate!");
				byte[] peerCertificate = peerCertificates[0].getEncoded();

				ByteBuffer bufferToHash = ByteBuffer.allocate(peerNonce.length + peerCertificate.length);
				bufferToHash.put(peerNonce).put(peerCertificate);
				byte[] qualifyingData = SecurityHelper.sha256(bufferToHash.array());

				byte[] quote = tpmEngine.quote(qk.handle, qualifyingData, peerPcrSelection);
				builder.setQuote(ByteString.copyFrom(quote));
			} catch (TpmEngineException e) {
				throw new HandshakeException("Error while using the TPM.", e);
			} catch (CertificateEncodingException e) {
				throw new HandshakeException(ErrorCode.BAD_CERT, "Failed to encode peer certificate.", e);
			} finally {
				try {
					if (qk != null)
						tpmEngine.flushKey(qk.handle);
				} catch (TpmEngineException e) {
				}
			}
		}
	}

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
			Certificate[] localCertificates = config.getLocalCertificates();
			if (localCertificates == null || localCertificates.length == 0)
				throw new HandshakeException(ErrorCode.INTERNAL_ERROR, "Failed to get local certificate!");
			byte[] localCertificate = localCertificates[0].getEncoded();

			ByteBuffer bufferToHash = ByteBuffer.allocate(selfNonce.length + localCertificate.length);
			bufferToHash.put(selfNonce).put(localCertificate);
			byte[] qualifyingData = SecurityHelper.sha256(bufferToHash.array());

			if (!new TpmValidator().validateQuote(peerQuote, qualifyingData, peerQk, peerPcrValues))
				throw new HandshakeException(ErrorCode.BAD_QUOTE, "Validation of peer quote failed!");
		} catch (TpmValidationException e) {
			throw new HandshakeException(ErrorCode.BAD_QUOTE, "Validation of peer quote failed!", e);
		} catch (CertificateEncodingException e) {
			throw new HandshakeException(ErrorCode.INTERNAL_ERROR, "Failed to encode local certificate.", e);
		}
	}

}
