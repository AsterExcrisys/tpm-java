package de.fhg.iosb.iad.tpm.attestation.tap.handshake;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.Map;

import com.google.protobuf.ByteString;

import de.fhg.iosb.iad.tpm.TpmEngine.TpmEngineException;
import de.fhg.iosb.iad.tpm.TpmValidator;
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

	public Map<Integer, String> getPeerPcrValues() {
		return peerPcrValues;
	}

	@Override
	public ProtocolType getProtocolType() {
		return ProtocolType.TPM_TAP;
	}

	protected void createInit(InitMessage.Builder builder) throws HandshakeException {
		System.out.println("Protocol type is: " + getProtocolType());
		builder.setProtocolType(getProtocolType());
		SecureRandom r = new SecureRandom();
		r.nextBytes(selfNonce);
		builder.setNonce(ByteString.copyFrom(selfNonce));
		builder.addAllPcrSelection(config.getPcrSelection());

		try {
			selfQk = config.getTpmEngine().getQkPub();
			builder.setQuotingKey(ByteString.copyFrom(selfQk));
		} catch (TpmEngineException e) {
			throw new HandshakeException("Error while using the TPM.", e);
		}
	}

	protected void handleInit(InitMessage message) throws HandshakeException {
		if (message.getProtocolType() != getProtocolType())
			throw new HandshakeException(ErrorCode.BAD_PROTOCOL_TYPE,
					"Expected protocol type " + getProtocolType() + ", but got " + message.getProtocolType());

		peerNonce = message.getNonce().toByteArray();
		peerQk = message.getQuotingKey().toByteArray();
		peerPcrSelection = message.getPcrSelectionList();
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

}
