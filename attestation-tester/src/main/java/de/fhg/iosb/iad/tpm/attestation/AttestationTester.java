package de.fhg.iosb.iad.tpm.attestation;

import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;

import de.fhg.iosb.iad.tpm.TpmEngine;
import de.fhg.iosb.iad.tpm.TpmEngine.TpmEngineException;
import de.fhg.iosb.iad.tpm.TpmEngine.TpmLoadedKey;
import de.fhg.iosb.iad.tpm.TpmEngineFactory;
import de.fhg.iosb.iad.tpm.attestation.mscp.MscpConfiguration;
import de.fhg.iosb.iad.tpm.attestation.mscp.MscpServerSocket;
import de.fhg.iosb.iad.tpm.attestation.mscp.MscpSocket;
import de.fhg.iosb.iad.tpm.attestation.tap.TapConfiguration;
import de.fhg.iosb.iad.tpm.attestation.tap.TapServerSocket;
import de.fhg.iosb.iad.tpm.attestation.tap.TapSocket;
import de.fhg.iosb.iad.tpm.attestation.tapdh.TapDhConfiguration;
import de.fhg.iosb.iad.tpm.attestation.tapdh.TapDhServerSocket;
import de.fhg.iosb.iad.tpm.attestation.tapdh.TapDhSocket;
import de.fhg.iosb.iad.tpm.attestation.tapssl.TapSslConfiguration;
import de.fhg.iosb.iad.tpm.attestation.tapssl.TapSslServerSocket;
import de.fhg.iosb.iad.tpm.attestation.tapssl.TapSslServerSocketFactory;
import de.fhg.iosb.iad.tpm.attestation.tapssl.TapSslSocket;
import de.fhg.iosb.iad.tpm.attestation.tapssl.TapSslSocketFactory;

public class AttestationTester {

	private static final Logger LOG = LoggerFactory.getLogger(AttestationTester.class);

	private static final Collection<Integer> pcrSelection = Arrays.asList(0, 1, 2, 3);

	private static SSLContext sslContext;
	private static final String certificatePass = "pass1234";

	private static TpmEngine tpmEngine = null;
	private static TpmLoadedKey qk = null;
	private static TpmLoadedKey srk = null;

	private static Socket createSocket(String type, String host, int port) throws IOException, TpmEngineException {
		if (type.equalsIgnoreCase("plain")) {
			return new Socket(host, port);
		} else if (type.equalsIgnoreCase("ssl")) {
			SSLSocketFactory socketFactory = sslContext.getSocketFactory();
			SSLSocket socket = (SSLSocket) socketFactory.createSocket(host, port);
			socket.setEnabledProtocols(new String[] { "TLSv1.2" });
			return socket;
		} else if (type.equalsIgnoreCase("tap")) {
			return new TapSocket(host, port, new TapConfiguration(tpmEngine, qk, pcrSelection));
		} else if (type.equalsIgnoreCase("tap-uni")) {
			return new TapSocket(host, port, new TapConfiguration(tpmEngine, qk, pcrSelection, true, false));
		} else if (type.equalsIgnoreCase("tap-ssl")) {
			SSLSocketFactory socketFactory = new TapSslSocketFactory(sslContext,
					new TapSslConfiguration(tpmEngine, qk, pcrSelection));
			return (TapSslSocket) socketFactory.createSocket(host, port);
		} else if (type.equalsIgnoreCase("tap-dh")) {
			return new TapDhSocket(host, port, new TapDhConfiguration(tpmEngine, qk, pcrSelection));
		} else if (type.equalsIgnoreCase("mscp")) {
			return new MscpSocket(host, port, new MscpConfiguration(tpmEngine, qk, srk, pcrSelection));
		} else {
			LOG.error("Invalid protocol type: {}", type);
			System.exit(-1);
		}
		return null;
	}

	private static ServerSocket createServerSocket(String type, int port) throws IOException, TpmEngineException {
		if (type.equalsIgnoreCase("plain")) {
			return new ServerSocket(port);
		} else if (type.equalsIgnoreCase("ssl")) {
			SSLServerSocketFactory serverSocketFactory = sslContext.getServerSocketFactory();
			SSLServerSocket serverSocket = (SSLServerSocket) serverSocketFactory.createServerSocket(port);
			serverSocket.setNeedClientAuth(true);
			serverSocket.setEnabledProtocols(new String[] { "TLSv1.2" });
			return serverSocket;
		} else if (type.equalsIgnoreCase("tap")) {
			return new TapServerSocket(port, new TapConfiguration(tpmEngine, qk, pcrSelection));
		} else if (type.equalsIgnoreCase("tap-uni")) {
			return new TapServerSocket(port, new TapConfiguration(tpmEngine, qk, pcrSelection, true, false));
		} else if (type.equalsIgnoreCase("tap-ssl")) {
			SSLServerSocketFactory serverSocketFactory = new TapSslServerSocketFactory(sslContext,
					new TapSslConfiguration(tpmEngine, qk, pcrSelection));
			return (TapSslServerSocket) serverSocketFactory.createServerSocket(port);
		} else if (type.equalsIgnoreCase("tap-dh")) {
			return new TapDhServerSocket(port, new TapDhConfiguration(tpmEngine, qk, pcrSelection));
		} else if (type.equalsIgnoreCase("mscp")) {
			return new MscpServerSocket(port, new MscpConfiguration(tpmEngine, qk, srk, pcrSelection));
		} else {
			LOG.error("Invalid protocol type: {}", type);
			System.exit(-1);
		}
		return null;
	}

	private static void initializeSslContext() throws GeneralSecurityException, IOException {
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		InputStream certificate = AttestationTester.class.getClassLoader().getResourceAsStream("certificate.p12");
		keyStore.load(certificate, certificatePass.toCharArray());
		KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509", "SunJSSE");
		keyManagerFactory.init(keyStore, certificatePass.toCharArray());
		X509KeyManager x509KeyManager = null;
		for (KeyManager keyManager : keyManagerFactory.getKeyManagers()) {
			if (keyManager instanceof X509KeyManager) {
				x509KeyManager = (X509KeyManager) keyManager;
				break;
			}
		}
		if (x509KeyManager == null)
			throw new IOException("Failed to load X.509 key manager!");

		KeyStore trustStore = KeyStore.getInstance("PKCS12");
		certificate = AttestationTester.class.getClassLoader().getResourceAsStream("certificate.p12");
		trustStore.load(certificate, certificatePass.toCharArray());
		TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("PKIX", "SunJSSE");
		trustManagerFactory.init(trustStore);
		X509TrustManager x509TrustManager = null;
		for (TrustManager trustManager : trustManagerFactory.getTrustManagers()) {
			if (trustManager instanceof X509TrustManager) {
				x509TrustManager = (X509TrustManager) trustManager;
				break;
			}
		}
		if (x509TrustManager == null)
			throw new IOException("Failed to load X.509 trust manager!");

		sslContext = SSLContext.getInstance("TLS");
		sslContext.init(new KeyManager[] { x509KeyManager }, new TrustManager[] { x509TrustManager }, null);
	}

	private static void flushTpmKeys() {
		if (tpmEngine == null)
			return;
		try {
			if (qk != null)
				tpmEngine.flushKey(qk.handle);
			if (srk != null)
				tpmEngine.flushKey(srk.handle);
		} catch (TpmEngineException e) {
			LOG.error("Failed to flush TPM keys!", e);
		}
	}

	public static void main(String[] argv) {
		Args args = new Args();
		JCommander argsParser = JCommander.newBuilder().addObject(args).build();
		try {
			argsParser.parse(argv);
		} catch (ParameterException | NumberFormatException e) {
			System.out.println(e.getMessage() + "\n");
			argsParser.usage();
			return;
		}
		if (args.isHelp()) {
			argsParser.usage();
			return;
		}

		// Check the configured protocol type
		boolean usesSsl = args.getTypes().contains("ssl") || args.getTypes().contains("tap-ssl");
		boolean usesTpm = args.getTypes().contains("tap") || args.getTypes().contains("tap-uni")
				|| args.getTypes().contains("tap-ssl") || args.getTypes().contains("tap-dh")
				|| args.getTypes().contains("mscp");

		// Load SSL certificates
		if (usesSsl) {
			try {
				initializeSslContext();
			} catch (GeneralSecurityException | IOException e) {
				LOG.error("Failed to initialize SSL context!", e);
				System.exit(-1);
			}
		}

		// Connect to TPM
		if (usesTpm) {
			try {
				if (args.isDevice())
					tpmEngine = TpmEngineFactory.createPlatformInstance();
				else
					tpmEngine = TpmEngineFactory.createSimulatorInstance(args.getAddress(), args.getPort());
				LOG.info("Loading TPM keys...");
				qk = tpmEngine.loadQk();
				srk = tpmEngine.loadSrk();
				LOG.info("TPM keys loaded");
			} catch (TpmEngineException e) {
				LOG.error("Failed to connect to TPM!", e);
				flushTpmKeys();
				System.exit(-1);
			}
		}

		for (String type : args.getTypes()) {
			// Start server
			TestServer server = null;
			try {
				ServerSocket serverSocket = createServerSocket(type.toUpperCase(), args.getServerPort());
				server = new TestServer(serverSocket);
				server.start();
			} catch (IOException | TpmEngineException e) {
				LOG.error("Failed to create {} server!", type.toUpperCase(), e);
				continue;
			}
			LOG.info("##### START ###################################");
			LOG.info("Started {} server on port {}...", type.toUpperCase(), args.getServerPort());
			LOG.info("Connecting to server {} times...", args.getN());

			// Connect to the server
			LinkedList<Duration> durations = new LinkedList<>();
			for (int i = 0; i < args.getN() + 1; i++) {
				Socket clientSocket = null;
				try {
					// Create new client and connect
					Instant startTime = Instant.now();
					clientSocket = createSocket(type.toUpperCase(), "127.0.0.1", args.getServerPort());

					if (clientSocket instanceof AttestedSocket) {
						LOG.info("Server has these PCR values: {}", ((AttestedSocket) clientSocket).getPeerPcrValues());
						// You should further check the validity of the PCR values...
					}

					// Send message
					TestClient client = new TestClient(clientSocket);
					String response = client.greetServer("Hello world :)");
					LOG.debug("Server responded with: {}", response);

					// Measure time
					Duration d = Duration.between(startTime, Instant.now());
					if (i > 0) { // Remove first run as outlier
						durations.add(d);
						LOG.info("Connection {}/{} took {}ms", i, args.getN(), d.toMillis());
					}
				} catch (IOException | TpmEngineException e) {
					LOG.error("Failed to connect to server!", e);
					break;
				} finally {
					try {
						if (clientSocket != null)
							clientSocket.close();
					} catch (IOException e) {
						LOG.error("Failed to close client connection!", e);
					}
				}
			}

			// Shutdown server
			try {
				if (server != null) {
					server.shutdown();
					server.join();
				}
			} catch (InterruptedException e) {
				LOG.error("Failed to shutdown server!", e);
			}

			// Calculate results
			double meanMicros = 0;
			for (Duration d : durations)
				meanMicros += (double) d.toNanos() / 1000.0d;
			meanMicros = meanMicros / durations.size();

			double sddMicros = 0;
			for (Duration d : durations)
				sddMicros += (((double) d.toNanos() / 1000.0d) - meanMicros)
						* (((double) d.toNanos() / 1000.0d) - meanMicros);
			double varMicros = sddMicros / (durations.size() - 1);

			LOG.info("##### RESULTS ################################");
			LOG.info("Type:   {}", type.toUpperCase());
			LOG.info("n     = {}", durations.size());
			LOG.info("min   = {}ms", Collections.min(durations).toMillis());
			LOG.info("max   = {}ms", Collections.max(durations).toMillis());
			LOG.info("mean  = {}ms", meanMicros / 1000.0);
			LOG.info("sigma = {}us", Math.sqrt(varMicros));
			LOG.info("##############################################");
		}

		flushTpmKeys();
	}

}
