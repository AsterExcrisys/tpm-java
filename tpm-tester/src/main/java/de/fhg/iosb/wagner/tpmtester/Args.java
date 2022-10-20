package de.fhg.iosb.wagner.tpmtester;

import java.util.Arrays;
import java.util.List;

import com.beust.jcommander.Parameter;

public class Args {

	@Parameter(names = { "-s", "--simulator" }, description = "Use TPM simulator instead of the real thing.")
	private boolean simulator = true;

	@Parameter(names = { "-a", "--address" }, description = "Address of the TPM service.")
	private String address = "127.0.0.1";

	@Parameter(names = { "-p", "--port" }, description = "Port of the TPM service.")
	private int port = 2321;

	@Parameter(names = { "-t", "--test" }, description = "Tests to run.")
	private List<String> tests = Arrays.asList("testPcrRead", "testImplicitAttestation");

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

	protected List<String> getTests() {
		return tests;
	}

	protected boolean isHelp() {
		return help;
	}

}
