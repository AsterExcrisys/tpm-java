package de.fhg.iosb.duc.rat.tpm.main;

import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import de.fhg.iosb.duc.rat.general.SecurityHelper;
import de.fhg.iosb.duc.rat.general.tpm.TPM;
import de.fhg.iosb.duc.rat.tpm.TPMFactory;

public class TPMTool {

	private static final String usage = "Usage: TPMTool (MSRTSS|MSRTSSSim) (GetQKHash|GetPCRs|CreateTTPSql) [PCRSelection] [SystemName] [ConfigName] [SqlFile]";

	public static void main(String[] args) {

		if (args.length < 2) {
			System.out.println(usage);
			System.exit(-1);
		}

		String engine = args[0];
		String cmd = args[1];
		String arg1 = (args.length >= 3) ? args[2] : "0-15";
		String arg2 = (args.length >= 4) ? args[3] : "System Name";
		String arg3 = (args.length >= 5) ? args[4] : "Config Name";
		String arg4 = (args.length >= 6) ? args[5] : "script.sql";

		TPM tpm = TPMFactory.createTPMInstance(engine);
		if (cmd.equals("GetQKHash")) {
			// Print hash
			System.out.println("################# QK (SHA-256) #######################");
			System.out.println(SecurityHelper.sha256String(tpm.getQKPub()));
			System.out.println("######################################################");
		} else if (cmd.equals("GetPCRs")) {
			List<Integer> numbers = rangeToIntList(arg1);
			for (Integer i : numbers) {
				String pcr = tpm.getPCRValue(i);
				System.out.println("PCR " + i + ": " + pcr);
			}
		} else if (cmd.equals("CreateTTPSql")) {
			String sysName = arg2;
			String configName = arg3;
			// Create output file
			PrintWriter out = null;
			try {
				out = new PrintWriter(arg4);
			} catch (FileNotFoundException e) {
				System.err.println("SQL file cannot be created!");
				e.printStackTrace();
				System.exit(-1);
			}

			// Insert a new system entry to database
			String qkhash = SecurityHelper.sha256String(tpm.getQKPub());
			String sql = String.format(
					"DELETE FROM SYSTEM WHERE NAME='%s'; INSERT INTO SYSTEM(NAME, QKHASH) VALUES('%s', '%s');", sysName,
					sysName, qkhash);
			out.println(sql);

			// Insert IP address for new system
			try {
				String ip = InetAddress.getLocalHost().getHostAddress();
				sql = String.format(
						"INSERT INTO IP(ADDRESS, SYSID) VALUES('%s', (SELECT ID FROM SYSTEM WHERE NAME='%s'));", ip,
						sysName);
				out.println(sql);
			} catch (UnknownHostException e) {
				System.err.println("Failed to get local IP address.");
				e.printStackTrace();
				System.exit(-1);
			}

			// Insert new configuration
			sql = String.format(
					"DELETE FROM CONFIG WHERE NAME='%s'; INSERT INTO CONFIG(NAME, SYSID) VALUES('%s', (SELECT ID FROM SYSTEM WHERE NAME='%s'));",
					configName, configName, sysName);
			out.println(sql);

			// Insert PCRs
			List<Integer> numbers = rangeToIntList(arg1);
			for (Integer i : numbers) {
				String pcr = tpm.getPCRValue(i);
				sql = String.format(
						"INSERT INTO PCR(NUMBER, VALUE, CID) VALUES(%d, '%s', (SELECT ID FROM CONFIG WHERE NAME='%s'));",
						i, pcr, configName);
				out.println(sql);
				sql = String.format(
						"INSERT INTO HASPCR(CID, PID) VALUES((SELECT ID FROM CONFIG WHERE NAME='%s'), (SELECT ID FROM PCR WHERE CID=(SELECT ID FROM CONFIG WHERE NAME='%s') AND NUMBER=%d AND VALUE='%s'));",
						configName, configName, i, pcr);
				out.println(sql);
			}

			out.close();
			System.out.println("SQL file created successfully.");
		} else {
			System.out.println(usage);
			System.exit(-1);

		}
	}

	private static List<Integer> rangeToIntList(String range) {
		List<Integer> result = new LinkedList<Integer>();
		// First, split string by comma
		List<String> s_l = new ArrayList<String>();
		for (String s : range.split(","))
			s_l.add(s.trim());
		// Then iterate ranges and parse them, if necessary
		try {
			for (String s : s_l) {
				if (s.contains("-")) {
					String[] r_l = s.split("-");
					if (r_l.length != 2)
						throw new IllegalArgumentException("Invalid format of PCR range!");
					int begin = Integer.parseInt(r_l[0]);
					int end = Integer.parseInt(r_l[1]);
					for (int i = begin; i <= end; i++)
						result.add(i);
				} else {
					result.add(Integer.parseInt(s));
				}
			}
		} catch (NumberFormatException e) {
			throw new IllegalArgumentException("Couldn't parse integer value for PCR range!", e);
		}
		return result;
	}

}
