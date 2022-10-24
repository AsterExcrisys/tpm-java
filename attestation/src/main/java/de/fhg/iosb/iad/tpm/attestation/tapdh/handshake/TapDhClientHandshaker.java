package de.fhg.iosb.iad.tpm.attestation.tapdh.handshake;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.fhg.iosb.iad.tpm.attestation.AbortMessage.ErrorCode;
import de.fhg.iosb.iad.tpm.attestation.AttestationMessage;
import de.fhg.iosb.iad.tpm.attestation.FinishMessage;
import de.fhg.iosb.iad.tpm.attestation.InitMessage;
import de.fhg.iosb.iad.tpm.attestation.ProtocolMessage;
import de.fhg.iosb.iad.tpm.attestation.ProtocolMessageType;
import de.fhg.iosb.iad.tpm.attestation.SuccessMessage;
import de.fhg.iosb.iad.tpm.attestation.tapdh.TapDhConfiguration;

public class TapDhClientHandshaker extends TapDhHandshaker {

	private static final Logger LOG = LoggerFactory.getLogger(TapDhClientHandshaker.class);

	public TapDhClientHandshaker(InputStream inputStream, OutputStream outputStream, TapDhConfiguration config) {
		super(inputStream, outputStream, config);
	}

	@Override
	public void performHandshake() throws IOException {
		try {
			// First step of handshake: Client writes CLIENT_INIT
			writeClientInit();
			expectedMessageType = ProtocolMessageType.SERVER_INIT;

			// Loop through next states until result is COMPLETED or
			// an exception occurs and the handshake is aborted.
			State state = State.IN_PROGRESS;
			while (state == State.IN_PROGRESS) {
				state = parseNextMessage();
			}
		} catch (HandshakeException e) {
			LOG.error("Error during {} handshake: {}", getProtocolType(), e.getMessage());
			// Write abort message to notify peer
			e.getAbortMessage().writeDelimitedTo(outputStream);
			// Throw exception to notify caller
			throw e.toIOException();
		}

		LOG.debug("Client-side {} handshake successful.", getProtocolType());
	}

	@Override
	public State handleNextMessage(ProtocolMessage inputMessage, ProtocolMessage.Builder outputMessage)
			throws HandshakeException {

		// Check expected message type
		if (inputMessage.getType() != expectedMessageType) {
			throw new HandshakeException(ErrorCode.BAD_MESSAGE,
					"Expected message type " + expectedMessageType + ". Got: " + inputMessage.getType());
		}

		// Handle messages
		switch (inputMessage.getType()) {
		case SERVER_INIT: {
			handleServerInit(inputMessage.getInit(), outputMessage.getAttestationBuilder());
			outputMessage.setType(ProtocolMessageType.CLIENT_ATTESTATION);
			expectedMessageType = ProtocolMessageType.SERVER_ATTESTATION;
			return State.IN_PROGRESS;
		}
		case SERVER_ATTESTATION: {
			handleServerAttestation(inputMessage.getAttestation(), outputMessage.getFinishBuilder());
			outputMessage.setType(ProtocolMessageType.CLIENT_FINISH);
			expectedMessageType = ProtocolMessageType.SERVER_FINISH;
			return State.IN_PROGRESS;
		}
		case SERVER_FINISH: {
			handleServerFinish(inputMessage.getFinish(), outputMessage.getSuccessBuilder());
			outputMessage.setType(ProtocolMessageType.CLIENT_SUCCESS);
			return State.COMPLETED;
		}
		default: {
			// Should not happen since the types have already been checked
			throw new HandshakeException(ErrorCode.INTERNAL_ERROR, "Invalid message type: " + inputMessage.getType());
		}
		}
	}

	private void writeClientInit() throws HandshakeException {
		ProtocolMessage.Builder builder = ProtocolMessage.newBuilder();
		builder.setType(ProtocolMessageType.CLIENT_INIT);

		createInit(builder.getInitBuilder());
		try {
			builder.build().writeDelimitedTo(outputStream);
		} catch (IOException e) {
			throw new HandshakeException("Error while parsing output message of type " + builder.getType(), e);
		}
	}

	private void handleServerInit(InitMessage initMessage, AttestationMessage.Builder outputMessage)
			throws HandshakeException {
		LOG.debug("Received SERVER_INIT\n{}", initMessage);
		handleInit(initMessage);
		createAttestation(outputMessage);
	}

	private void handleServerAttestation(AttestationMessage attestationMessage, FinishMessage.Builder outputMessage)
			throws HandshakeException {
		LOG.debug("Received SERVER_ATTESTATION\n{}", attestationMessage);
		handleAttestation(attestationMessage);
		createFinish(outputMessage);
		LOG.debug("SERVER_ATTESTATION succesfully verified");
	}

	private void handleServerFinish(FinishMessage finishMessage, SuccessMessage.Builder outputMessage)
			throws HandshakeException {
		LOG.debug("Received SERVER_FINISH\n{}", finishMessage);
		handleFinish(finishMessage);
	}

}
