package de.fhg.iosb.iad.tpm.attestation;

import java.util.Arrays;
import java.util.List;

import com.beust.jcommander.Parameter;

public class Args {

	@Parameter(names = { "-d", "--device" }, description = "Use physical TPM device instead of the simulator.")
	private boolean device = false;

	@Parameter(names = { "-a",
			"--address" }, description = "Address of the TPM service.", validateWith = ArgsValidator.class)
	private String address = "127.0.0.1";

	@Parameter(names = { "-p", "--port" }, description = "Port of the TPM service.", validateWith = ArgsValidator.class)
	private int port = 2321;

	@Parameter(names = { "-t",
			"--type" }, description = "Protocol types to test. Available types are ['plain', 'ssl', 'tap', 'tap-uni', 'tap-ssl', 'tap-dh', 'mscp'].")
	private List<String> types = Arrays.asList("mscp");

	@Parameter(names = {
			"--serverPort" }, description = "Port to bind the test server to.", validateWith = ArgsValidator.class)
	private int serverPort = 1501;

	@Parameter(names = { "-n", "--n" }, description = "Number of handshakes to perform.")
	private int n = 100;

	@Parameter(names = { "-h", "--help" }, help = true)
	private boolean help;

	protected boolean isDevice() {
		return device;
	}

	protected String getAddress() {
		return address;
	}

	protected int getPort() {
		return port;
	}

	protected List<String> getTypes() {
		return types;
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
