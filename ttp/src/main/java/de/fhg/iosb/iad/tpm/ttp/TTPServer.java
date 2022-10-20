package de.fhg.iosb.iad.tpm.ttp;

import java.io.IOException;
import java.io.InputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.beust.jcommander.JCommander;

import io.grpc.Server;
import io.grpc.ServerBuilder;

public class TTPServer {

	private static final Logger LOG = LoggerFactory.getLogger(TTPServer.class);

	public static void main(String[] argv) throws IOException, InterruptedException {
		Args args = new Args();
		JCommander argsParser = JCommander.newBuilder().addObject(args).build();
		argsParser.parse(argv);
		if (args.help) {
			argsParser.usage();
			return;
		}

		LOG.info("Using database file {}{}{}...", System.getProperty("user.dir"), System.getProperty("file.separator"),
				args.dbFile);
		ServerBuilder<?> builder = ServerBuilder.forPort(args.port).addService(new TTPService(args.dbFile));
		if (!args.noTLS) {
			InputStream certChain = TTPServer.class.getResourceAsStream("/ttp.crt");
			InputStream privateKey = TTPServer.class.getResourceAsStream("/ttp.pem");
			builder.useTransportSecurity(certChain, privateKey);
		}
		Server server = builder.build();
		server.start();
		LOG.info("Started {} TTP service on port {}...", args.noTLS ? "INSECURE" : "TLS-secured", args.port);
		server.awaitTermination();
	}
}
