package de.fhg.iosb.iad.tpm.attestation.mscp;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketImpl;

import de.fhg.iosb.iad.tpm.TpmEngine.TpmEngineException;

public class MscpServerSocket extends ServerSocket {

	private final MscpConfiguration config;

	public MscpServerSocket(int port) throws IOException, TpmEngineException {
		this(port, new MscpConfiguration());
	}

	public MscpServerSocket(int port, MscpConfiguration config) throws IOException, TpmEngineException {
		super(port);
		this.config = config;
	}

	public MscpServerSocket(int port, int backlog) throws IOException, TpmEngineException {
		this(port, backlog, new MscpConfiguration());
	}

	public MscpServerSocket(int port, int backlog, MscpConfiguration config) throws IOException {
		super(port, backlog);
		this.config = config;
	}

	public MscpServerSocket(int port, int backlog, InetAddress bindAddr) throws IOException, TpmEngineException {
		this(port, backlog, bindAddr, new MscpConfiguration());
	}

	public MscpServerSocket(int port, int backlog, InetAddress bindAddr, MscpConfiguration config) throws IOException {
		super(port, backlog, bindAddr);
		this.config = config;
	}

	@Override
	public Socket accept() throws IOException {
		if (isClosed())
			throw new SocketException("Socket is closed");
		if (!isBound())
			throw new SocketException("Socket is not bound yet");
		MscpSocket s = new MscpSocket((SocketImpl) null, config);
		implAccept(s);
		s.performHandshake(true);
		return s;
	}

}
