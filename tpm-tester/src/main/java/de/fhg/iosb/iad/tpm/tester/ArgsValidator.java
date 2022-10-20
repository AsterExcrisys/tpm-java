package de.fhg.iosb.iad.tpm.tester;

import com.beust.jcommander.IParameterValidator;
import com.beust.jcommander.ParameterException;

public class ArgsValidator implements IParameterValidator {

	public void validate(String name, String value) throws ParameterException {
		if (name.equalsIgnoreCase("-a") || name.equalsIgnoreCase("--address")) {
			if (value.isEmpty())
				throw new ParameterException("Invalid address. Found: " + value);
		}

		if (name.equalsIgnoreCase("-p") || name.equalsIgnoreCase("--port")) {
			if (Integer.parseInt(value) <= 0)
				throw new ParameterException("Invalid port. Found: " + value);
		}
	}

}