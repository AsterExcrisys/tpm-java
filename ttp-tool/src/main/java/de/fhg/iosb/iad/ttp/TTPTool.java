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
import de.fhg.iosb.iad.tpm.TpmEngine.TpmEngineException;
import de.fhg.iosb.iad.tpm.TpmEngine.TpmLoadedKey;
import de.fhg.iosb.iad.tpm.TpmEngineFactory;
import de.fhg.iosb.iad.tpm.TpmEngineImpl;

public class TTPTool {

	private static final Logger LOG = LoggerFactory.getLogger(TTPTool.class);

	private static String calculateFingerprint(TpmEngineImpl tpmEngine) throws TpmEngineException {
		TpmLoadedKey qk = tpmEngine.loadQk();
		String fingerprint = SecurityHelper.sha256String(qk.outPublic);
		tpmEngine.flushKey(qk.handle);
		return fingerprint;
	}

	private static void getFingerprint(TpmEngineImpl tpmEngine) throws TpmEngineException {
		LOG.info("###################### QK (SHA-256) ############################");
		LOG.info(calculateFingerprint(tpmEngine));
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
			String systemFingerprint = calculateFingerprint(tpmEngine);
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
			if (args.isDevice())
				tpmEngine = TpmEngineFactory.createPlatformInstance();
			else
				tpmEngine = TpmEngineFactory.createSimulatorInstance(args.getAddress(), args.getPort());

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
