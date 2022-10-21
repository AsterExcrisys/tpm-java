package de.fhg.iosb.iad.tpm.attestation;

import java.io.IOException;
import java.net.Socket;

public class TestClient {

	private final Socket socket;

	public TestClient(Socket socket) throws IOException {
		assert (socket != null);
		this.socket = socket;
	}

	public String greetServer(String message) throws IOException {
		Greeting g = Greeting.newBuilder().setMessage(message).build();
		g.writeDelimitedTo(socket.getOutputStream());

		g = Greeting.parseDelimitedFrom(socket.getInputStream());
		return g.getMessage();
	}

}
