package de.fhg.iosb.iad.tpm.attestation;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import de.fhg.iosb.iad.tpm.TpmEngine.TpmEngineException;
import de.fhg.iosb.iad.tpm.attestation.AbortMessage.ErrorCode;

public abstract class Handshaker {

	protected final InputStream inputStream;
	protected final OutputStream outputStream;
	protected ProtocolMessageType expectedMessageType = ProtocolMessageType.UNKNOWN_MESSAGE;

	protected Handshaker(InputStream inputStream, OutputStream outputStream) {
		assert (inputStream != null);
		assert (outputStream != null);
		this.inputStream = inputStream;
		this.outputStream = outputStream;
	}

	public abstract ProtocolType getProtocolType();

	public abstract void performHandshake() throws IOException;

	protected abstract State handleNextMessage(ProtocolMessage inputMessage, ProtocolMessage.Builder outputMessage)
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
					"Message has missing field for type: " + inputMessage.getType());
		}

		// Check abort message
		if (isAbortMessage(inputMessage)) {
			throw new IOException("Remote peer aborted the handshake. Reason: " + inputMessage.getAbort().getCode(),
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
			throw new HandshakeException("Error while parsing output message of type " + outputMessageBuilder.getType(),
					e);
		}

		return state;
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
			return new IOException(getProtocolType() + " handshake failed! Reason: " + abortMessage.getCode(), this);
		}
	}

}
