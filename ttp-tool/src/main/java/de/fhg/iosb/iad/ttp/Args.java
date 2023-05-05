package de.fhg.iosb.iad.ttp;

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

	@Parameter(names = { "-c",
			"--command" }, description = "Command to run. One or more of ['getFingerprint', 'readPcrs', 'createSql'].")
	private List<String> commands = Arrays.asList("getFingerprint", "readPcrs");

	@Parameter(names = {
			"--pcrs" }, description = "Range of PCRs to include. Used for commands 'readPcrs' and 'createSql'.", listConverter = ArgsIntRangeParser.class)
	private List<Integer> pcrs = Arrays.asList(0, 1, 2, 3, 4, 5, 6);

	@Parameter(names = { "-f",
			"--file" }, description = "Sql file to write. Used for command 'createSql'", validateWith = ArgsValidator.class)
	private String file = "script.sql";

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

	protected List<String> getCommands() {
		return commands;
	}

	protected List<Integer> getPcrs() {
		return pcrs;
	}

	protected String getFile() {
		return file;
	}

	protected boolean isHelp() {
		return help;
	}

}
