package de.fhg.iosb.iad.tpm.mscp;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedList;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;

import de.fhg.iosb.iad.tpm.TpmEngine;
import de.fhg.iosb.iad.tpm.TpmEngine.TpmEngineException;
import de.fhg.iosb.iad.tpm.TpmEngineFactory;

public class MscpTester {

	private static final Logger LOG = LoggerFactory.getLogger(MscpTester.class);

	private static Socket createSocket(String type, String host, int port, TpmEngine tpmEngine) throws IOException, TpmEngineException {
		if (type.equalsIgnoreCase("plain")) {
			return new Socket(host, port);
		} else if (type.equalsIgnoreCase("mscp")) {
			return new MscpSocket(host, port, new MscpConfiguration(tpmEngine));
		} else {
			LOG.error("Invalid protocol type: {}", type);
			System.exit(-1);
		}
		return null;
	}

	private static ServerSocket createServerSocket(String type, int port, TpmEngine tpmEngine) throws IOException, TpmEngineException {
		if (type.equalsIgnoreCase("plain")) {
			return new ServerSocket(port);
		} else if (type.equalsIgnoreCase("mscp")) {
			return new MscpServerSocket(port, new MscpConfiguration(tpmEngine));
		} else {
			LOG.error("Invalid protocol type: {}", type);
			System.exit(-1);
		}
		return null;
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

		// Connect to TPM
		TpmEngine tpmEngine = null;
		try {
		if (args.isSimulator())
			tpmEngine = TpmEngineFactory.createSimulatorInstance(args.getAddress(), args.getPort());
		else
			tpmEngine = TpmEngineFactory.createPlatformInstance();
		} catch (TpmEngineException e) {
			LOG.error("Failed to connect to TPM!", e);
			System.exit(-1);
		}
		
		// Start server
		MscpServer server = null;
		try {
			ServerSocket serverSocket = createServerSocket(args.getType().toUpperCase(), args.getServerPort(), tpmEngine);
			server = new MscpServer(serverSocket);
			server.start();
		} catch (IOException | TpmEngineException e) {
			LOG.error("Failed to create {} server!", args.getType().toUpperCase(), e);
			System.exit(-1);
		}
		LOG.info("Started {} server on port {}...", args.getType().toUpperCase(), args.getServerPort());

		LOG.info("Connecting to server {} times...", args.getN());
		LOG.info("##### START ###################################");

		// Connect to the server
		LinkedList<Duration> durations = new LinkedList<>();
		for (int i = 0; i < args.getN() /*+ 1*/; i++) {
			Socket clientSocket = null;
			try {
				// Create new client and connect
				Instant startTime = Instant.now();
				clientSocket = createSocket(args.getType().toUpperCase(), "127.0.0.1", args.getServerPort(), tpmEngine);
				Duration d = Duration.between(startTime, Instant.now());
				//if (i > 0) { // Remove first run as outlier
					durations.add(d);
					LOG.info("Connection {}/{} took {}ms", i, args.getN(), d.toMillis());
				//}

				// Send message
				MscpClient client = new MscpClient(clientSocket);
				String response = client.greetServer("Hello world :)");
				LOG.debug("Server responded with: {}", response);
			} catch (IOException | TpmEngineException e) {
				LOG.error("Failed to connect to server!", e);
				if (server != null)
					server.shutdown();
				System.exit(-1);
			} finally {
				if (clientSocket != null) {
					try {
						clientSocket.close();
					} catch (IOException e) {
						LOG.error("Failed to close client connection!", e);
					}
				}
			}
		}

		// Shutdown server
		if (server != null) {
			try {
				server.shutdown();
				server.join();
			} catch (InterruptedException e) {
				LOG.error("Failed to shutdown server!", e);
			}
		}

		// Caculate results
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
		LOG.info("Type:   {}", args.getType().toUpperCase());
		LOG.info("n     = {}", durations.size());
		LOG.info("min   = {}ms", Collections.min(durations).toMillis());
		LOG.info("max   = {}ms", Collections.max(durations).toMillis());
		LOG.info("mean  = {}ms", meanMicros / 1000.0);
		LOG.info("sigma = {}us", Math.sqrt(varMicros));
		LOG.info("##############################################");
	}

}
