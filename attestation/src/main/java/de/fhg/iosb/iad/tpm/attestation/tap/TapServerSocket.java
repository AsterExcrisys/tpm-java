package de.fhg.iosb.iad.tpm.attestation.tap;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketImpl;

import de.fhg.iosb.iad.tpm.TpmEngine.TpmEngineException;

public class TapServerSocket extends ServerSocket {

	private final TapConfiguration config;

	public TapServerSocket(int port, TapConfiguration config) throws IOException, TpmEngineException {
		super(port);
		assert (config != null);
		this.config = config;
	}

	public TapServerSocket(int port, int backlog, TapConfiguration config) throws IOException {
		super(port, backlog);
		assert (config != null);
		this.config = config;
	}

	public TapServerSocket(int port, int backlog, InetAddress bindAddr, TapConfiguration config) throws IOException {
		super(port, backlog, bindAddr);
		assert (config != null);
		this.config = config;
	}

	@Override
	public Socket accept() throws IOException {
		if (isClosed())
			throw new SocketException("Socket is closed");
		if (!isBound())
			throw new SocketException("Socket is not bound yet");
		TapSocket s = new TapSocket((SocketImpl) null, config);
		implAccept(s);
		s.performHandshake(true);
		return s;
	}

}
