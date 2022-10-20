package de.fhg.iosb.iad.ttp;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.util.List;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;

import de.fhg.iosb.iad.tpm.SecurityHelper;
import de.fhg.iosb.iad.tpm.TpmEngineFactory;
import de.fhg.iosb.iad.tpm.TpmEngineImpl;
import de.fhg.iosb.iad.tpm.TpmEngine.TpmEngineException;

public class TTPTool {

	private static final Logger LOG = LoggerFactory.getLogger(TTPTool.class);

	private static void getFingerprint(TpmEngineImpl tpmEngine) throws TpmEngineException {
		LOG.info("###################### QK (SHA-256) ############################");
		LOG.info(SecurityHelper.sha256String(tpmEngine.getQkPub()));
		LOG.info("################################################################");
	}

	private static void readPcrs(TpmEngineImpl tpmEngine, List<Integer> pcrNumbers) throws TpmEngineException {
		LOG.info("############################## PCR ####################################");
		for (int pcr : pcrNumbers)
			LOG.info("PCR {}: {}", pcr, tpmEngine.getPcrValue(pcr));
		LOG.info("########################################################################");
	}

	private static void createSql(TpmEngineImpl tpmEngine, String file, List<Integer> pcrNumbers)
			throws TpmEngineException, IOException {
		Writer writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file, true), "UTF-8"));
		try {
			// Insert a new trusted state
			String systemFingerprint = SecurityHelper.sha256String(tpmEngine.getQkPub());
			String trustedState = UUID.randomUUID().toString();
			String sql = String.format("INSERT INTO TrustedStates(systemFingerprint, trustedState) VALUES('%s', '%s');",
					systemFingerprint, trustedState);
			writer.write(sql + "\n");

			// Insert current PCR values
			for (int pcr : pcrNumbers) {
				String pcrValue = tpmEngine.getPcrValue(pcr);
				sql = String.format(
						"INSERT INTO PCRValues(TrustedState, PCRRegister, PCRValue) VALUES('%s', '%s', '%s');",
						trustedState, pcr, pcrValue);
				writer.write(sql + "\n");
			}
		} finally {
			writer.close();
		}
		LOG.info("Successfully written {}", file);
	}

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
			if (args.isSimulator())
				tpmEngine = TpmEngineFactory.createSimulatorInstance(args.getAddress(), args.getPort());
			else
				tpmEngine = TpmEngineFactory.createPlatformInstance();

			for (String command : args.getCommands()) {
				if (command.equalsIgnoreCase("getFingerprint"))
					getFingerprint(tpmEngine);
				else if (command.equalsIgnoreCase("readPcrs"))
					readPcrs(tpmEngine, args.getPcrs());
				else if (command.equalsIgnoreCase("createSql"))
					createSql(tpmEngine, args.getFile(), args.getPcrs());
				else
					LOG.error("Invalid command {}!", command);
			}
		} catch (TpmEngineException | IOException e) {
			LOG.error("Failed to run command!", e);
		}

		LOG.info("Done.");
	}

}
