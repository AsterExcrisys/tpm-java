package de.fhg.iosb.iad.srat.ttp.database;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.sql.SQLException;
import java.util.Map;
import java.util.Set;

import org.junit.BeforeClass;
import org.junit.Test;

import de.fhg.iosb.iad.tpm.ttp.database.Database;

public class DatabaseTest {

	private static Database database = null;

	@BeforeClass
	public static void beforeClass() throws SQLException {
		database = new Database("test.sqlite");
	}

	@Test
	public void testGetTrustedStates() throws SQLException {
		String systemFingerprint = "63CF26DFA30590A9C5EEC51630DAA0D84E1D50536E4250AF8D139BEEC3F4F6C7";
		Set<Integer> trustedStates = database.getTrustedStatesForSystem(systemFingerprint);

		assertEquals(1, trustedStates.size());
		assertTrue(trustedStates.contains(1));
	}

	@Test
	public void testGetPCRValues() throws SQLException {
		Map<Integer, String> pcrValues = database.getPCRValuesForTrustedState(1);

		assertEquals(3, pcrValues.size());
		assertEquals("07CD877F1286496295ABDF54BCEC329C4B3DF21412C66B4B9B30E36EC204D91D", pcrValues.get(5));
		assertEquals("7E507FF21ABB1CC5E20826C7FB6DC9F0887A3B7623D36CBE6E720645EB795283", pcrValues.get(7));
		assertEquals("460DD0A2AEB1583EDBF379ADBD75CC7E35F94FC4FD9EC96E66130AAEBBC15CB9", pcrValues.get(13));
	}

}
