package de.fhg.iosb.iad.tpm.mscp;

import java.io.IOException;
import java.net.Socket;

public class MscpClient {

	private final Socket socket;

	public MscpClient(Socket socket) throws IOException {
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
