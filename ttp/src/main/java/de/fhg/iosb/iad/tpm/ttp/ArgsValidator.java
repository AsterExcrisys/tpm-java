package de.fhg.iosb.iad.tpm.ttp;

import com.beust.jcommander.IParameterValidator;
import com.beust.jcommander.ParameterException;

public class ArgsValidator implements IParameterValidator {

	public void validate(String name, String value) throws ParameterException {
		if (name.equalsIgnoreCase("-p") || name.equalsIgnoreCase("--port")) {
			if (Integer.parseInt(value) <= 0)
				throw new ParameterException("Invalid port. Found: " + value);
		}

		if (name.equalsIgnoreCase("-d") || name.equalsIgnoreCase("--dbFile")) {
			if (value.isEmpty())
				throw new ParameterException("Invalid database file. Found: " + value);
		}
	}

}