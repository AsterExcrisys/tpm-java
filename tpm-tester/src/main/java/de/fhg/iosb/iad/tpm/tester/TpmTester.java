package de.fhg.iosb.iad.tpm.tester;

import java.time.Duration;
import java.time.Instant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;

import de.fhg.iosb.iad.tpm.TpmEngine.TpmEngineException;
import de.fhg.iosb.iad.tpm.TpmEngineFactory;
import de.fhg.iosb.iad.tpm.TpmEngineImpl;
import de.fhg.iosb.iad.tpm.TpmValidator.TpmValidationException;
import de.fhg.iosb.iad.tpm.test.TpmEngineImplTest;

public class TpmTester {

	private static final Logger LOG = LoggerFactory.getLogger(TpmTester.class);

	public static void main(String[] argv) {
		Args args = new Args();
		JCommander argsParser = JCommander.newBuilder().addObject(args).build();
		try {
			argsParser.parse(argv);
		} catch (ParameterException | NumberFormatException e) {
			System.out.println(e.getMessage() + "\n");
			argsParser.usage();
			return;
		}
		if (args.isHelp()) {
			argsParser.usage();
			return;
		}

		try {
			TpmEngineImpl tpmEngine;
			if (args.isDevice())
				tpmEngine = TpmEngineFactory.createPlatformInstance();
			else
				tpmEngine = TpmEngineFactory.createSimulatorInstance(args.getAddress(), args.getPort());

			TpmEngineImplTest tpmTest = new TpmEngineImplTest(tpmEngine);
			for (String test : args.getTests()) {
				LOG.info("************* Running {} *************", test);
				Instant startTime = Instant.now();
				if (test.equalsIgnoreCase("testPcrRead"))
					tpmTest.testPcrRead();
				else if (test.equalsIgnoreCase("testQuote"))
					tpmTest.testQuote();
				else if (test.equalsIgnoreCase("testKeyExchange"))
					tpmTest.testKeyExchange();
				else if (test.equalsIgnoreCase("testImplicitAttestation"))
					tpmTest.testImplicitAttestation();
				else
					LOG.error("Test {} not found!", test);

				LOG.info("********* Finished test in {}ms *********",
						Duration.between(startTime, Instant.now()).toMillis());
			}
		} catch (TpmEngineException | TpmValidationException e) {
			LOG.error("Failed to run tests!", e);
		}

		LOG.info("Done.");
	}

}
