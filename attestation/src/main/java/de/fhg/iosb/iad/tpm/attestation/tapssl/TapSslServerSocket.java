package de.fhg.iosb.iad.tpm.attestation.tapssl;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketOption;
import java.nio.channels.ServerSocketChannel;
import java.util.Set;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

public class TapSslServerSocket extends ServerSocket {

	private final SSLServerSocket serverSocket;
	private final TapSslConfiguration config;

	TapSslServerSocket(SSLServerSocket serverSocket, TapSslConfiguration config) throws IOException {
		this.serverSocket = serverSocket;
		this.serverSocket.setNeedClientAuth(true);
		this.serverSocket.setEnabledProtocols(new String[] { "TLSv1.2" });
		
		this.config = config;
	}

	@Override
	public void bind(SocketAddress endpoint) throws IOException {
		serverSocket.bind(endpoint);
	}

	@Override
	public void bind(SocketAddress endpoint, int backlog) throws IOException {
		serverSocket.bind(endpoint, backlog);
	}

	@Override
	public InetAddress getInetAddress() {
		return serverSocket.getInetAddress();
	}

	@Override
	public int getLocalPort() {
		return serverSocket.getLocalPort();
	}

	@Override
	public SocketAddress getLocalSocketAddress() {
		return serverSocket.getLocalSocketAddress();
	}

	@Override
	public Socket accept() throws IOException {
		SSLSocket s = (SSLSocket) serverSocket.accept();
		return new TapSslSocket(s, config, true);
	}

	@Override
	public void close() throws IOException {
		serverSocket.close();
	}

	@Override
	public ServerSocketChannel getChannel() {
		return serverSocket.getChannel();
	}

	@Override
	public boolean isBound() {
		return serverSocket.isBound();
	}

	@Override
	public boolean isClosed() {
		return serverSocket.isClosed();
	}

	@Override
	public synchronized void setSoTimeout(int timeout) throws SocketException {
		serverSocket.setSoTimeout(timeout);
	}

	@Override
	public synchronized int getSoTimeout() throws IOException {
		return serverSocket.getSoTimeout();
	}

	@Override
	public void setReuseAddress(boolean on) throws SocketException {
		serverSocket.setReuseAddress(on);
	}

	@Override
	public boolean getReuseAddress() throws SocketException {
		return serverSocket.getReuseAddress();
	}

	@Override
	public String toString() {
		return serverSocket.toString();
	}

	@Override
	public synchronized void setReceiveBufferSize(int size) throws SocketException {
		serverSocket.setReceiveBufferSize(size);
	}

	@Override
	public synchronized int getReceiveBufferSize() throws SocketException {
		return serverSocket.getReceiveBufferSize();
	}

	@Override
	public void setPerformancePreferences(int connectionTime, int latency, int bandwidth) {
		serverSocket.setPerformancePreferences(connectionTime, latency, bandwidth);
	}

	@Override
	public <T> ServerSocket setOption(SocketOption<T> name, T value) throws IOException {
		return serverSocket.setOption(name, value);
	}

	@Override
	public <T> T getOption(SocketOption<T> name) throws IOException {
		return serverSocket.getOption(name);
	}

	@Override
	public Set<SocketOption<?>> supportedOptions() {
		return serverSocket.supportedOptions();
	}
}
