package de.fhg.iosb.iad.tpm.attestation.tap.handshake;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.Map;

import com.google.protobuf.ByteString;

import de.fhg.iosb.iad.tpm.TpmEngine;
import de.fhg.iosb.iad.tpm.TpmEngine.TpmEngineException;
import de.fhg.iosb.iad.tpm.TpmEngine.TpmLoadedKey;
import de.fhg.iosb.iad.tpm.TpmValidator;
import de.fhg.iosb.iad.tpm.TpmValidator.TpmValidationException;
import de.fhg.iosb.iad.tpm.attestation.AbortMessage.ErrorCode;
import de.fhg.iosb.iad.tpm.attestation.AttestationMessage;
import de.fhg.iosb.iad.tpm.attestation.Handshaker;
import de.fhg.iosb.iad.tpm.attestation.InitMessage;
import de.fhg.iosb.iad.tpm.attestation.ProtocolType;
import de.fhg.iosb.iad.tpm.attestation.tap.TapConfiguration;

public abstract class TapHandshaker extends Handshaker {

	protected byte[] selfNonce = new byte[16], peerNonce = new byte[16];
	protected byte[] selfQk, peerQk;
	protected Collection<Integer> peerPcrSelection;
	protected Map<Integer, String> peerPcrValues;

	private final TapConfiguration config;

	protected TapHandshaker(InputStream inputStream, OutputStream outputStream, TapConfiguration config) {
		super(inputStream, outputStream);
		assert (config != null);
		this.config = config;
	}

	@Override
	public ProtocolType getProtocolType() {
		return ProtocolType.TPM_TAP;
	}

	public Map<Integer, String> getPeerPcrValues() {
		return peerPcrValues;
	}

	protected void createInit(InitMessage.Builder builder) throws HandshakeException {
		builder.setProtocolType(getProtocolType());
		SecureRandom r = new SecureRandom();
		r.nextBytes(selfNonce);
		builder.setNonce(ByteString.copyFrom(selfNonce));
		builder.addAllPcrSelection(config.getPcrSelection());
	}

	protected void handleInit(InitMessage message) throws HandshakeException {
		if (message.getProtocolType() != getProtocolType())
			throw new HandshakeException(ErrorCode.BAD_PROTOCOL_TYPE,
					"Expected protocol type " + getProtocolType() + ", but got " + message.getProtocolType());

		peerNonce = message.getNonce().toByteArray();
		peerPcrSelection = message.getPcrSelectionList();
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
				byte[] quote = tpmEngine.quote(qk.handle, peerNonce, peerPcrSelection);
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
	}

}
