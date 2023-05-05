package de.fhg.iosb.iad.ttp;

import com.beust.jcommander.IParameterValidator;
import com.beust.jcommander.ParameterException;

public class ArgsValidator implements IParameterValidator {

	public void validate(String name, String value) throws ParameterException {
		if (name.equalsIgnoreCase("-p") || name.equalsIgnoreCase("--port")) {
			if (Integer.parseInt(value) <= 0)
				throw new ParameterException("Invalid port. Found: " + value);
		}

		if (name.equalsIgnoreCase("-d") || name.equalsIgnoreCase("--db")) {
			if (value.isBlank())
				throw new ParameterException("Database file cannot be empty!");
		}
	}

}