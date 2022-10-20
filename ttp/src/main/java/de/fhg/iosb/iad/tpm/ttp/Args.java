package de.fhg.iosb.iad.tpm.ttp;

import com.beust.jcommander.Parameter;

public class Args {

	@Parameter(names = { "-p", "--port" }, description = "Server port.", validateWith = ArgsValidator.class)
	protected int port = 5001;

	@Parameter(names = { "-d", "--dbFile" }, description = "Database file.", validateWith = ArgsValidator.class)
	protected String dbFile = "ttp.sqlite";

	@Parameter(names = { "-n", "--noTLS" }, description = "Offer insecure plaintext connections instead of using TLS.")
	protected boolean noTLS = false;

	@Parameter(names = "--help", help = true)
	protected boolean help;

}
