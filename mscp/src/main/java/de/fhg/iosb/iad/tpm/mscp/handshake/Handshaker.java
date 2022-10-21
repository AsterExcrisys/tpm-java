package de.fhg.iosb.iad.tpm.mscp.handshake;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.google.protobuf.ByteString;

import de.fhg.iosb.iad.tpm.TpmEngine.TpmEngineException;
import de.fhg.iosb.iad.tpm.TpmQuoteVerifier;
import de.fhg.iosb.iad.tpm.mscp.AbortMessage;
import de.fhg.iosb.iad.tpm.mscp.AbortMessage.ErrorCode;
import de.fhg.iosb.iad.tpm.mscp.AttestationMessage;
import de.fhg.iosb.iad.tpm.mscp.FinishMessage;
import de.fhg.iosb.iad.tpm.mscp.InitMessage;
import de.fhg.iosb.iad.tpm.mscp.KeyEstablishmentMessage;
import de.fhg.iosb.iad.tpm.mscp.MscpConfiguration;
import de.fhg.iosb.iad.tpm.mscp.ProtocolMessage;
import de.fhg.iosb.iad.tpm.mscp.ProtocolMessageType;
import de.fhg.iosb.iad.tpm.mscp.ProtocolType;

public abstract class Handshaker {

	protected final InputStream inputStream;
	protected final OutputStream outputStream;
	protected ProtocolMessageType expectedMessageType = ProtocolMessageType.UNKNOWN_MESSAGE;

	private final MscpConfiguration config;
	private final String hmacString = "MSCP key exchange protocol";
	private byte[] selfNonce = new byte[16], peerNonce = new byte[16];
	private byte[] selfQk, peerQk;
	private Collection<Integer> peerPcrSelection;
	private Map<Integer, String> peerPcrValues;
	private byte[] selfDhKey;
	private byte[] generatedDhZ;
	private byte[] hmac;
	private byte[] randomIv;

	Handshaker(InputStream inputStream, OutputStream outputStream, MscpConfiguration config) {
		assert (inputStream != null);
		assert (outputStream != null);
		assert (config != null);
		this.inputStream = inputStream;
		this.outputStream = outputStream;
		this.config = config;
	}

	public byte[] getGeneratedDhZ() {
		return generatedDhZ;
	}

	public byte[] getRandomIv() {
		return randomIv;
	}

	public Map<Integer, String> getPeerPcrValues() {
		return peerPcrValues;
	}

	public abstract void performHandshake() throws IOException;

	public abstract State handleNextMessage(ProtocolMessage inputMessage, ProtocolMessage.Builder outputMessage)
			throws HandshakeException;

	protected State parseNextMessage() throws HandshakeException, IOException {
		// Read next message
		ProtocolMessage inputMessage = ProtocolMessage.getDefaultInstance();
		try {
			inputMessage = ProtocolMessage.parseDelimitedFrom(inputStream);
		} catch (IOException e) {
			throw new HandshakeException("Error while parsing input message!", e);
		}

		// Validate message type
		if (isAbortMessage(inputMessage) && !inputMessage.hasAbort()
				|| isInitMessage(inputMessage) && !inputMessage.hasInit()
				|| isAttestationMessage(inputMessage) && !inputMessage.hasAttestation()
				|| isKeyEstablishmentMessage(inputMessage) && !inputMessage.hasKeyEstablishment()
				|| isFinishMessage(inputMessage) && !inputMessage.hasFinish()) {
			throw new HandshakeException(ErrorCode.BAD_MESSAGE,
					"Message has missing field for type: " + inputMessage.getType().toString());
		}

		// Check abort message
		if (isAbortMessage(inputMessage)) {
			throw new IOException(
					"Remote peer aborted the handshake. Reason: " + inputMessage.getAbort().getCode().toString(),
					new HandshakeException(inputMessage.getAbort()));
		}

		// Handle the message
		ProtocolMessage.Builder outputMessageBuilder = ProtocolMessage.newBuilder();
		State state = handleNextMessage(inputMessage, outputMessageBuilder);

		// Write output
		try {
			if (outputMessageBuilder.getType() != ProtocolMessageType.UNKNOWN_MESSAGE)
				outputMessageBuilder.build().writeDelimitedTo(outputStream);
		} catch (IOException e) {
			throw new HandshakeException(
					"Error while parsing output message of type " + outputMessageBuilder.getType().toString(), e);
		}

		return state;
	}

	protected void createInit(InitMessage.Builder builder) throws HandshakeException {
		builder.setProtocolType(ProtocolType.TPM_MSCP);
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
		if (message.getProtocolType() != ProtocolType.TPM_MSCP)
			throw new HandshakeException(ErrorCode.BAD_PROTOCOL_TYPE,
					"Expected protocol type TPM_MSCP, but got " + message.getProtocolType().toString());

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
			if (!new TpmQuoteVerifier().verifyQuote(peerQuote, selfNonce, peerQk, peerPcrValues))
				throw new HandshakeException(ErrorCode.BAD_QUOTE, "Verification of peer quote failed!");
		} catch (TpmEngineException e) {
			throw new HandshakeException("Error while using the TPM.", e);
		}
	}

	protected void createKeyEstablishment(KeyEstablishmentMessage.Builder builder) throws HandshakeException {
		try {
			selfDhKey = config.getTpmEngine().createEphemeralDhKey();
			builder.setDhPublic(ByteString.copyFrom(config.getTpmEngine().getDhKeyPub(selfDhKey)));
			builder.setDhCert(ByteString.copyFrom(config.getTpmEngine().certifyEphemeralDhKey(selfDhKey, peerNonce)));
		} catch (TpmEngineException e) {
			throw new HandshakeException("Error while using the TPM.", e);
		}
	}

	protected void handleKeyEstablishment(KeyEstablishmentMessage message) throws HandshakeException {
		byte[] peerDhKeyPub = message.getDhPublic().toByteArray();
		byte[] peerDhCert = message.getDhCert().toByteArray();

		try {
			generatedDhZ = config.getTpmEngine().calculateSharedDhSecret(selfDhKey, peerDhKeyPub, peerDhCert, selfNonce,
					peerQk);
		} catch (TpmEngineException e) {
			throw new HandshakeException("Error while using the TPM.", e);
		}

		if (generatedDhZ == null)
			throw new HandshakeException(ErrorCode.BAD_DH_CERT,
					"Verification of peer Diffie-Hellman certificate failed!");
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

	private boolean isAbortMessage(ProtocolMessage message) {
		return (message.getType() == ProtocolMessageType.ABORT_MESSAGE);
	}

	private boolean isInitMessage(ProtocolMessage message) {
		return (message.getType() == ProtocolMessageType.CLIENT_INIT
				|| message.getType() == ProtocolMessageType.SERVER_INIT);
	}

	private boolean isAttestationMessage(ProtocolMessage message) {
		return (message.getType() == ProtocolMessageType.CLIENT_ATTESTATION
				|| message.getType() == ProtocolMessageType.SERVER_ATTESTATION);
	}

	private boolean isKeyEstablishmentMessage(ProtocolMessage message) {
		return (message.getType() == ProtocolMessageType.CLIENT_KEY_ESTABLISHMENT
				|| message.getType() == ProtocolMessageType.SERVER_KEY_ESTABLISHMENT);
	}

	private boolean isFinishMessage(ProtocolMessage message) {
		return (message.getType() == ProtocolMessageType.CLIENT_FINISH
				|| message.getType() == ProtocolMessageType.SERVER_FINISH);
	}

	protected enum State {
		IN_PROGRESS, COMPLETED
	};

	protected class HandshakeException extends Exception {

		private static final long serialVersionUID = 6960570628956683561L;

		private final AbortMessage abortMessage;

		public HandshakeException(AbortMessage abortMessage) {
			this.abortMessage = abortMessage;
		}

		public HandshakeException(ErrorCode code, String message) {
			this.abortMessage = AbortMessage.newBuilder().setCode(code).setMessage(message).build();
		}

		public HandshakeException(ErrorCode code, String message, Throwable cause) {
			super(cause);
			this.abortMessage = AbortMessage.newBuilder().setCode(code).setMessage(message).build();
		}

		public HandshakeException(String message, IOException cause) {
			super(cause);
			this.abortMessage = AbortMessage.newBuilder().setCode(ErrorCode.IO_ERROR).setMessage(message).build();
		}

		public HandshakeException(String message, TpmEngineException cause) {
			super(cause);
			this.abortMessage = AbortMessage.newBuilder().setCode(ErrorCode.TPM_ERROR).setMessage(message).build();
		}

		public AbortMessage getAbortMessage() {
			return abortMessage;
		}

		public IOException toIOException() {
			return new IOException("MSCP handshake failed! Reason: " + abortMessage.getCode().toString(), this);
		}
	}

}
