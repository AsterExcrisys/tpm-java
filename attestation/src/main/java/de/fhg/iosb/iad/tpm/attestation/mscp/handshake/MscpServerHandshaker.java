package de.fhg.iosb.iad.tpm.attestation.mscp.handshake;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.protobuf.ByteString;

import de.fhg.iosb.iad.tpm.TpmEngine;
import de.fhg.iosb.iad.tpm.TpmEngine.TpmEngineException;
import de.fhg.iosb.iad.tpm.TpmEngine.TpmLoadedKey;
import de.fhg.iosb.iad.tpm.TpmValidator;
import de.fhg.iosb.iad.tpm.TpmValidator.TpmValidationException;
import de.fhg.iosb.iad.tpm.attestation.AbortMessage.ErrorCode;
import de.fhg.iosb.iad.tpm.attestation.AttestationMessage;
import de.fhg.iosb.iad.tpm.attestation.FinishMessage;
import de.fhg.iosb.iad.tpm.attestation.InitMessage;
import de.fhg.iosb.iad.tpm.attestation.ProtocolMessage;
import de.fhg.iosb.iad.tpm.attestation.ProtocolMessageType;
import de.fhg.iosb.iad.tpm.attestation.SuccessMessage;
import de.fhg.iosb.iad.tpm.attestation.mscp.MscpConfiguration;

public class MscpServerHandshaker extends MscpHandshaker {

	private static final Logger LOG = LoggerFactory.getLogger(MscpServerHandshaker.class);

	public MscpServerHandshaker(InputStream inputStream, OutputStream outputStream, MscpConfiguration config) {
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
		attestationServerOptimized(attestationMessage, outputMessage);
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

	/*
	 * Optimized attestation handling for the server. The server can do the DH key
	 * generation and the shared secret generation in one session. This saves us two
	 * TPM key re-loads (SRK and DH).
	 */
	private void attestationServerOptimized(AttestationMessage inputMessage, AttestationMessage.Builder outputBuilder)
			throws HandshakeException {
		TpmEngine tpmEngine = config.getTpmEngine();
		synchronized (tpmEngine) {
			try {
				// Create quote
				TpmLoadedKey qk = config.getQuotingKey();
				selfQk = qk.outPublic;
				outputBuilder.setQuotingKey(ByteString.copyFrom(selfQk));
				outputBuilder.putAllPcrValues(tpmEngine.getPcrValues(peerPcrSelection));
				byte[] quote = tpmEngine.quote(qk.handle, peerNonce, peerPcrSelection);
				outputBuilder.setQuote(ByteString.copyFrom(quote));

				// Create DH key
				TpmLoadedKey srk = config.getRootKey();
				selfDhKey = tpmEngine.createEphemeralDhKey(srk.handle);
				outputBuilder.setPublicKey(ByteString.copyFrom(selfDhKey.outPublic));

				peerQk = inputMessage.getQuotingKey().toByteArray();
				peerPcrValues = inputMessage.getPcrValuesMap();
				byte[] peerQuote = inputMessage.getQuote().toByteArray();

				// Validate PCR selection
				if (!peerPcrValues.keySet().containsAll(config.getPcrSelection())) {
					throw new HandshakeException(ErrorCode.BAD_PCR_SELECTION, "Requested PCR selection "
							+ config.getPcrSelection() + " but got " + peerPcrValues.keySet());
				}

				// Validate quote
				try {
					if (!new TpmValidator().validateQuote(peerQuote, selfNonce, peerQk, peerPcrValues))
						throw new HandshakeException(ErrorCode.BAD_QUOTE, "Validation of peer quote failed!");
				} catch (TpmValidationException e) {
					throw new HandshakeException(ErrorCode.BAD_QUOTE, "Validation of peer quote failed!", e);
				}

				// Validate certificate
				byte[] peerDhKeyPub = inputMessage.getPublicKey().toByteArray();
				byte[] peerDhCert = inputMessage.getCertificate().toByteArray();
				try {
					if (!new TpmValidator().validateKeyCertification(peerDhKeyPub, peerDhCert, selfNonce, peerQk))
						throw new HandshakeException(ErrorCode.BAD_CERT, "Validation of presented certificate failed!");
				} catch (TpmValidationException e) {
					throw new HandshakeException(ErrorCode.BAD_CERT, "Validation of presented certificate failed!", e);
				}

				// Certify DH secret and generate secret
				int selfDhKeyHandle = tpmEngine.loadKey(srk.handle, selfDhKey);
				try {
					byte[] cert = tpmEngine.certifyKey(selfDhKeyHandle, qk.handle, peerNonce);
					outputBuilder.setCertificate(ByteString.copyFrom(cert));
					generatedSecret = tpmEngine.generateSharedSecret(selfDhKeyHandle, peerDhKeyPub);
				} finally {
					tpmEngine.flushKey(selfDhKeyHandle);
				}
			} catch (TpmEngineException e) {
				throw new HandshakeException("Error while using the TPM.", e);
			}
		}
	}

}
