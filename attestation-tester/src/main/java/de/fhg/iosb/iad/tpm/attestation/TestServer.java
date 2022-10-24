package de.fhg.iosb.iad.tpm.attestation;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TestServer extends Thread {

	private static final Logger LOG = LoggerFactory.getLogger(TestServer.class);

	private boolean running = false;
	private final boolean attestable;
	private final ServerSocket serverSocket;

	public TestServer(ServerSocket serverSocket, boolean attestable) {
		assert (serverSocket != null);
		this.serverSocket = serverSocket;
		this.attestable = attestable;
	}

	public boolean isRunning() {
		return running;
	}

	public void shutdown() {
		running = false;
	}

	@Override
	public void run() {
		running = true;
		try {
			serverSocket.setSoTimeout(500);
			while (running) {
				try {
					// Wait for client
					Socket clientSocket = serverSocket.accept();

					if (attestable) {
						LOG.info("Client has these PCR values: {}", ((AttestedSocket) clientSocket).getPeerPcrValues());
						// You should further check the validity of the PCR values...
					}

					// Receive greeting
					Greeting g = Greeting.parseDelimitedFrom(clientSocket.getInputStream());
					LOG.debug("Received greeting from client: {}", g.getMessage());

					// Respond with greeting
					g = Greeting.newBuilder().setMessage("Hello world from the server ;)").build();
					g.writeDelimitedTo(clientSocket.getOutputStream());

					// Close connection
					clientSocket.close();
				} catch (SocketTimeoutException e) {
					continue;
				}
			}
			serverSocket.close();
		} catch (IOException e) {
			LOG.error("Failed to handle client!", e);
		}

		LOG.debug("Server thread terminated.");
	}

}