package de.fhg.iosb.iad.tpm.attestation.tapssl.handshake;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.fhg.iosb.iad.tpm.attestation.AbortMessage.ErrorCode;
import de.fhg.iosb.iad.tpm.attestation.AttestationMessage;
import de.fhg.iosb.iad.tpm.attestation.InitMessage;
import de.fhg.iosb.iad.tpm.attestation.ProtocolMessage;
import de.fhg.iosb.iad.tpm.attestation.ProtocolMessageType;
import de.fhg.iosb.iad.tpm.attestation.SuccessMessage;
import de.fhg.iosb.iad.tpm.attestation.tapssl.TapSslConfiguration;

public class TapSslServerHandshaker extends TapSslHandshaker {

	private static final Logger LOG = LoggerFactory.getLogger(TapSslServerHandshaker.class);

	public TapSslServerHandshaker(InputStream inputStream, OutputStream outputStream, TapSslConfiguration config) {
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
		handleAttestation(attestationMessage);
		createAttestation(outputMessage);
		LOG.debug("CLIENT_ATTESTATION succesfully verified");
	}

	private void handleClientSuccess(SuccessMessage successMessage) throws HandshakeException {
		LOG.debug("Received CLIENT_SUCCESS\n{}", successMessage);
		// Nothing further to do here...
	}

}
