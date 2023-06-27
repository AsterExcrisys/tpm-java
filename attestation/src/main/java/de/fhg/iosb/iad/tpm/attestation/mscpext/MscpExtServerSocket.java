package de.fhg.iosb.iad.tpm.attestation.mscpext;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketImpl;

import de.fhg.iosb.iad.tpm.TpmEngine.TpmEngineException;
import de.fhg.iosb.iad.tpm.attestation.tapdh.TapDhConfiguration;

public class MscpExtServerSocket extends ServerSocket {

	private final TapDhConfiguration config;

	public MscpExtServerSocket(int port, TapDhConfiguration config) throws IOException, TpmEngineException {
		super(port);
		this.config = config;
	}

	public MscpExtServerSocket(int port, int backlog, TapDhConfiguration config) throws IOException {
		super(port, backlog);
		this.config = config;
	}

	public MscpExtServerSocket(int port, int backlog, InetAddress bindAddr, TapDhConfiguration config)
			throws IOException {
		super(port, backlog, bindAddr);
		this.config = config;
	}

	@Override
	public Socket accept() throws IOException {
		if (isClosed())
			throw new SocketException("Socket is closed");
		if (!isBound())
			throw new SocketException("Socket is not bound yet");
		MscpExtSocket s = new MscpExtSocket((SocketImpl) null, config);
		implAccept(s);
		s.performHandshake(true);
		return s;
	}

}
