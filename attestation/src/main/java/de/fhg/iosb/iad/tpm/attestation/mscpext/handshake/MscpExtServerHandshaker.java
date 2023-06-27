package de.fhg.iosb.iad.tpm.attestation.mscpext.handshake;

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

public class MscpExtServerHandshaker extends MscpExtHandshaker {

	private static final Logger LOG = LoggerFactory.getLogger(MscpExtServerHandshaker.class);

	public MscpExtServerHandshaker(InputStream inputStream, OutputStream outputStream, TapDhConfiguration config) {
		super(inputStream, outputStream, config);
	}

	@Override
	public void performHandshake() throws IOException {
		try {
			// Expect the client to send the first message
			expectedMessageType = ProtocolMessageType.CLIENT_INIT;

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

		LOG.debug("Server-side {} handshake successful.", getProtocolType());
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
		case CLIENT_INIT: {
			handleClientInit(inputMessage.getInit(), outputMessage.getInitBuilder());
			outputMessage.setType(ProtocolMessageType.SERVER_INIT);
			expectedMessageType = ProtocolMessageType.CLIENT_ATTESTATION;
			return State.IN_PROGRESS;
		}
		case CLIENT_ATTESTATION: {
			handleClientAttestation(inputMessage.getAttestation(), outputMessage.getAttestationBuilder());
			outputMessage.setType(ProtocolMessageType.SERVER_ATTESTATION);
			expectedMessageType = ProtocolMessageType.CLIENT_FINISH;
			return State.IN_PROGRESS;
		}
		case CLIENT_FINISH: {
			handleClientFinish(inputMessage.getFinish(), outputMessage.getFinishBuilder());
			outputMessage.setType(ProtocolMessageType.SERVER_FINISH);
			expectedMessageType = ProtocolMessageType.CLIENT_SUCCESS;
			return State.IN_PROGRESS;
		}
		case CLIENT_SUCCESS: {
			handleClientSuccess(inputMessage.getSuccess());
			return State.COMPLETED;
		}
		default: {
			// Should not happen since the types have already been checked
			throw new HandshakeException(ErrorCode.INTERNAL_ERROR, "Invalid message type: " + inputMessage.getType());
		}
		}
	}

	private void handleClientInit(InitMessage initMessage, InitMessage.Builder outputMessage)
			throws HandshakeException {
		LOG.debug("Received CLIENT_INIT\n{}", initMessage);
		handleInit(initMessage);
		createInit(outputMessage);
	}

	private void handleClientAttestation(AttestationMessage attestationMessage,
			AttestationMessage.Builder outputMessage) throws HandshakeException {
		LOG.debug("Received CLIENT_ATTESTATION\n{}", attestationMessage);
		createAttestation(outputMessage); // Create the attestation first to generate DH key for the validation
		handleAttestation(attestationMessage);
		LOG.debug("CLIENT_ATTESTATION succesfully verified");
	}

	private void handleClientFinish(FinishMessage finishMessage, FinishMessage.Builder outputMessage)
			throws HandshakeException {
		LOG.debug("Received CLIENT_FINISH\n{}", finishMessage);
		handleFinish(finishMessage);
		createFinish(outputMessage);
	}

	private void handleClientSuccess(SuccessMessage successMessage) throws HandshakeException {
		LOG.debug("Received CLIENT_SUCCESS\n{}", successMessage);
		// Nothing further to do here...
	}

}
