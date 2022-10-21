package de.fhg.iosb.iad.tpm.mscp;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MscpServer extends Thread {

	private static final Logger LOG = LoggerFactory.getLogger(MscpServer.class);

	private boolean running = false;
	private final ServerSocket serverSocket;

	public MscpServer(ServerSocket serverSocket) {
		assert (serverSocket != null);
		this.serverSocket = serverSocket;
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