package de.fhg.iosb.iad.tpm.tester;

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

	@Parameter(names = { "-t", "--test" }, description = "Tests to run.")
	private List<String> tests = Arrays.asList("testPcrRead", "testImplicitAttestation");

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

	protected List<String> getTests() {
		return tests;
	}

	protected boolean isHelp() {
		return help;
	}

}
