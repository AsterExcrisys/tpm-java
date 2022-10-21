package de.fhg.iosb.iad.tpm.mscp;

import com.beust.jcommander.Parameter;

public class Args {

	@Parameter(names = { "-s", "--simulator" }, description = "Use TPM simulator instead of the real thing.")
	private boolean simulator = true;

	@Parameter(names = { "-a",
			"--address" }, description = "Address of the TPM service.", validateWith = ArgsValidator.class)
	private String address = "127.0.0.1";

	@Parameter(names = { "-p", "--port" }, description = "Port of the TPM service.", validateWith = ArgsValidator.class)
	private int port = 2321;

	@Parameter(names = { "-t",
			"--type" }, description = "Protocol type to use. Available types are ['plain', 'ssl', 'tap', 'mscp'].")
	private String type = "mscp";

	@Parameter(names = {
			"--serverPort" }, description = "Port to bind the test server to.", validateWith = ArgsValidator.class)
	private int serverPort = 1501;

	@Parameter(names = { "-n", "--n" }, description = "Number of handshakes to perform.")
	private int n = 1;

	@Parameter(names = { "-h", "--help" }, help = true)
	private boolean help;

	protected boolean isSimulator() {
		return simulator;
	}

	protected String getAddress() {
		return address;
	}

	protected int getPort() {
		return port;
	}

	protected String getType() {
		return type;
	}

	protected int getN() {
		return n;
	}

	protected int getServerPort() {
		return serverPort;
	}

	protected boolean isHelp() {
		return help;
	}

}
