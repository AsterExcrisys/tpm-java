package de.fhg.iosb.iad.tpm.attestation.tap;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketImpl;
import java.util.Map;

import de.fhg.iosb.iad.tpm.attestation.AttestedSocket;
import de.fhg.iosb.iad.tpm.attestation.tap.handshake.TapClientHandshaker;
import de.fhg.iosb.iad.tpm.attestation.tap.handshake.TapHandshaker;
import de.fhg.iosb.iad.tpm.attestation.tap.handshake.TapServerHandshaker;

public class TapSocket extends Socket implements AttestedSocket {

	private final TapConfiguration config;

	private TapHandshaker handshaker;

	protected TapSocket(SocketImpl socketImpl, TapConfiguration config) throws IOException {
		super(socketImpl);
		assert (config != null);
		this.config = config;
	}

	public TapSocket(InetAddress address, int port, TapConfiguration config) throws IOException {
		super(address, port);
		assert (config != null);
		this.config = config;
		performHandshake(false);
	}

	public TapSocket(String host, int port, TapConfiguration config) throws IOException {
		super(host, port);
		assert (config != null);
		this.config = config;
		performHandshake(false);
	}

	protected void performHandshake(boolean server) throws IOException {
		this.handshaker = server ? new TapServerHandshaker(super.getInputStream(), super.getOutputStream(), config)
				: new TapClientHandshaker(super.getInputStream(), super.getOutputStream(), config);
		this.handshaker.performHandshake();
	}

	@Override
	public Map<Integer, String> getPeerPcrValues() {
		return handshaker.getPeerPcrValues();
	}

}
