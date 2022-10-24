package de.fhg.iosb.iad.tpm.attestation.tapssl;

import java.io.IOException;
import java.net.InetAddress;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

import de.fhg.iosb.iad.tpm.TpmEngine.TpmEngineException;

public class TapSslServerSocketFactory extends SSLServerSocketFactory {

	private final SSLServerSocketFactory socketFactory;
	private final TapSslConfiguration config;

	public TapSslServerSocketFactory(SSLContext sslContext) throws TpmEngineException {
		this(sslContext, new TapSslConfiguration());
	}

	public TapSslServerSocketFactory(SSLContext sslContext, TapSslConfiguration config) {
		assert (sslContext != null);
		assert (config != null);
		this.socketFactory = sslContext.getServerSocketFactory();
		this.config = config;
	}

	@Override
	public String[] getDefaultCipherSuites() {
		return socketFactory.getDefaultCipherSuites();
	}

	@Override
	public String[] getSupportedCipherSuites() {
		return socketFactory.getSupportedCipherSuites();
	}

	@Override
	public TapSslServerSocket createServerSocket() throws IOException {
		SSLServerSocket s = (SSLServerSocket) socketFactory.createServerSocket();
		return new TapSslServerSocket(s, config);
	}

	@Override
	public TapSslServerSocket createServerSocket(int port) throws IOException {
		SSLServerSocket s = (SSLServerSocket) socketFactory.createServerSocket(port);
		return new TapSslServerSocket(s, config);
	}

	@Override
	public TapSslServerSocket createServerSocket(int port, int backlog) throws IOException {
		SSLServerSocket s = (SSLServerSocket) socketFactory.createServerSocket(port, backlog);
		return new TapSslServerSocket(s, config);
	}

	@Override
	public TapSslServerSocket createServerSocket(int port, int backlog, InetAddress ifAddress) throws IOException {
		SSLServerSocket s = (SSLServerSocket) socketFactory.createServerSocket(port, backlog, ifAddress);
		return new TapSslServerSocket(s, config);
	}

}
