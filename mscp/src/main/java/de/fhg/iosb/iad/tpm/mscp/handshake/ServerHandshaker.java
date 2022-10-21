package de.fhg.iosb.iad.tpm.mscp.handshake;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.fhg.iosb.iad.tpm.mscp.AbortMessage.ErrorCode;
import de.fhg.iosb.iad.tpm.mscp.AttestationMessage;
import de.fhg.iosb.iad.tpm.mscp.FinishMessage;
import de.fhg.iosb.iad.tpm.mscp.InitMessage;
import de.fhg.iosb.iad.tpm.mscp.KeyEstablishmentMessage;
import de.fhg.iosb.iad.tpm.mscp.MscpConfiguration;
import de.fhg.iosb.iad.tpm.mscp.ProtocolMessage;
import de.fhg.iosb.iad.tpm.mscp.ProtocolMessageType;
import de.fhg.iosb.iad.tpm.mscp.SuccessMessage;

public class ServerHandshaker extends Handshaker {

	private static final Logger LOG = LoggerFactory.getLogger(ServerHandshaker.class);

	public ServerHandshaker(InputStream inputStream, OutputStream outputStream, MscpConfiguration config) {
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
			LOG.error("Error during MSCP handshake: {}", e.getMessage());
			// Write abort message to notify peer
			e.getAbortMessage().writeDelimitedTo(outputStream);
			// Throw exception to notify caller
			throw e.toIOException();
		}

		LOG.debug("Server-side handshake successful.");
	}

	@Override
	public State handleNextMessage(ProtocolMessage inputMessage, ProtocolMessage.Builder outputMessage)
			throws HandshakeException {

		// Check expected message type
		if (inputMessage.getType() != expectedMessageType) {
			throw new HandshakeException(ErrorCode.BAD_MESSAGE, "Expected message type "
					+ expectedMessageType.toString() + ". Got: " + inputMessage.getType().toString());
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
			expectedMessageType = ProtocolMessageType.CLIENT_KEY_ESTABLISHMENT;
			return State.IN_PROGRESS;
		}
		case CLIENT_KEY_ESTABLISHMENT: {
			handleClientKeyEstablishment(inputMessage.getKeyEstablishment(),
					outputMessage.getKeyEstablishmentBuilder());
			outputMessage.setType(ProtocolMessageType.SERVER_KEY_ESTABLISHMENT);
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
			throw new HandshakeException(ErrorCode.INTERNAL_ERROR, "Inconsistent state!");
		}
		}
	}

	private void handleClientInit(InitMessage initMessage, InitMessage.Builder outputMessage)
			throws HandshakeException {
		LOG.debug("Received CLIENT_INIT\n{}", initMessage.toString());
		handleInit(initMessage);
		createInit(outputMessage);
	}

	private void handleClientAttestation(AttestationMessage attestationMessage,
			AttestationMessage.Builder outputMessage) throws HandshakeException {
		LOG.debug("Received CLIENT_ATTESTATION\n{}", attestationMessage.toString());
		handleAttestation(attestationMessage);
		createAttestation(outputMessage);
		LOG.debug("CLIENT_ATTESTATION succesfully verified");
	}

	private void handleClientKeyEstablishment(KeyEstablishmentMessage keyEstablishmentMessage,
			KeyEstablishmentMessage.Builder outputMessage) throws HandshakeException {
		LOG.debug("Received CLIENT_KEY_ESTABLISHMENT\n{}", keyEstablishmentMessage.toString());
		createKeyEstablishment(outputMessage); // Create key establishment first to generate Diffie-Hellman key pair
		handleKeyEstablishment(keyEstablishmentMessage);
	}

	private void handleClientFinish(FinishMessage finishMessage, FinishMessage.Builder outputMessage)
			throws HandshakeException {
		LOG.debug("Received CLIENT_FINISH\n{}", finishMessage.toString());
		handleFinish(finishMessage);
		createFinish(outputMessage);
	}

	private void handleClientSuccess(SuccessMessage successMessage) throws HandshakeException {
		LOG.debug("Received CLIENT_SUCCESS\n{}", successMessage.toString());
		// Nothing further to do here...
	}

}
