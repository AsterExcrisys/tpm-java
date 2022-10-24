package de.fhg.iosb.iad.tpm.attestation.tapssl;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import de.fhg.iosb.iad.tpm.TpmEngine.TpmEngineException;

public class TapSslSocketFactory extends SSLSocketFactory {

	private final SSLSocketFactory socketFactory;
	private final TapSslConfiguration config;

	public TapSslSocketFactory(SSLContext sslContext) throws TpmEngineException {
		this(sslContext, new TapSslConfiguration());
	}

	public TapSslSocketFactory(SSLContext sslContext, TapSslConfiguration config) {
		assert (sslContext != null);
		assert (config != null);
		this.socketFactory = sslContext.getSocketFactory();
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
	public TapSslSocket createSocket(Socket sock, String host, int port, boolean autoClose) throws IOException {
		SSLSocket s = (SSLSocket) socketFactory.createSocket(sock, host, port, autoClose);
		return new TapSslSocket(s, config, false);
	}

	@Override
	public TapSslSocket createSocket(String host, int port) throws IOException, UnknownHostException {
		SSLSocket s = (SSLSocket) socketFactory.createSocket(host, port);
		return new TapSslSocket(s, config, false);
	}

	@Override
	public TapSslSocket createSocket(String host, int port, InetAddress localHost, int localPort)
			throws IOException, UnknownHostException {
		SSLSocket s = (SSLSocket) socketFactory.createSocket(host, port, localHost, localPort);
		return new TapSslSocket(s, config, false);
	}

	@Override
	public TapSslSocket createSocket(InetAddress host, int port) throws IOException {
		SSLSocket s = (SSLSocket) socketFactory.createSocket(host, port);
		return new TapSslSocket(s, config, false);
	}

	@Override
	public TapSslSocket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
			throws IOException {
		SSLSocket s = (SSLSocket) socketFactory.createSocket(address, port, localAddress, localPort);
		return new TapSslSocket(s, config, false);
	}

}
