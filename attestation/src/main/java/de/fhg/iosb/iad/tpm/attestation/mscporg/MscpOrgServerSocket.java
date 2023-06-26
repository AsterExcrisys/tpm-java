package de.fhg.iosb.iad.tpm.attestation.mscporg;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketImpl;

import de.fhg.iosb.iad.tpm.TpmEngine.TpmEngineException;

public class MscpOrgServerSocket extends ServerSocket {

	private final MscpOrgConfiguration config;

	public MscpOrgServerSocket(int port, MscpOrgConfiguration config) throws IOException, TpmEngineException {
		super(port);
		this.config = config;
	}

	public MscpOrgServerSocket(int port, int backlog, MscpOrgConfiguration config) throws IOException {
		super(port, backlog);
		this.config = config;
	}

	public MscpOrgServerSocket(int port, int backlog, InetAddress bindAddr, MscpOrgConfiguration config) throws IOException {
		super(port, backlog, bindAddr);
		this.config = config;
	}

	@Override
	public Socket accept() throws IOException {
		if (isClosed())
			throw new SocketException("Socket is closed");
		if (!isBound())
			throw new SocketException("Socket is not bound yet");
		MscpOrgSocket s = new MscpOrgSocket((SocketImpl) null, config);
		implAccept(s);
		s.performHandshake(true);
		return s;
	}

}
