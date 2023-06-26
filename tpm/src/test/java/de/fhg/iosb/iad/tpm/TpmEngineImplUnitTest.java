package de.fhg.iosb.iad.tpm;

import java.io.IOException;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import de.fhg.iosb.iad.tpm.TpmEngine.TpmEngineException;
import de.fhg.iosb.iad.tpm.TpmValidator.TpmValidationException;
import de.fhg.iosb.iad.tpm.test.Asserter;
import de.fhg.iosb.iad.tpm.test.TpmEngineImplTest;

/**
 * JUnit Test cases for the TPM engine. For this test suite the MSR.TSS
 * simulator has to be launched manually.
 * 
 * @author wagner
 *
 */
public class TpmEngineImplUnitTest {

	private TpmEngineImpl tpm = null;
	private TpmEngineImplTest tpmTest = null;

	@BeforeEach
	public void before() throws TpmEngineException {
		tpm = TpmEngineFactory.createSimulatorInstance();
		tpmTest = new TpmEngineImplTest(tpm, new Asserter() {
			@Override
			public void assertTrue(boolean b) {
				Assertions.assertTrue(b);
			}

			@Override
			public void assertFalse(boolean b) {
				Assertions.assertFalse(b);
			}

			@Override
			public void assertEquals(Object expected, Object actual) {
				Assertions.assertEquals(expected, actual);
			}

			@Override
			public void assertNotEquals(Object expected, Object actual) {
				Assertions.assertNotEquals(expected, actual);
			}

			@Override
			public void assertNull(Object actual) {
				Assertions.assertNull(actual);
			}

			@Override
			public void assertNotNull(Object actual) {
				Assertions.assertNotNull(actual);
			}
		});
	}

	@AfterEach
	public void after() {
		tpm.close();
	}

	@Test
	@Disabled
	public void testPcrRead() throws TpmEngineException {
		tpmTest.testPcrRead();
	}

	@Test
	@Disabled
	public void testPcrReset() throws TpmEngineException {
		tpmTest.testPcrReset();
	}

	@Test
	@Disabled
	public void testQuote() throws TpmEngineException, TpmValidationException {
		tpmTest.testQuote();
	}

	@Test
	@Disabled
	public void testEphemeralDhKeysAreNotStatic() throws TpmEngineException {
		tpmTest.testEphemeralDhKeysAreNotStatic();
	}

	@Test
	@Disabled
	public void testKeyExchange() throws TpmEngineException, TpmValidationException {
		tpmTest.testKeyExchange();
	}

	@Test
	@Disabled
	public void testCreationCertification() throws TpmEngineException, TpmValidationException {
		tpmTest.testCreationCertification();
	}

	@Test
	@Disabled
	public void testImplicitAttestation() throws TpmEngineException, IOException {
		tpmTest.testImplicitAttestation();
	}

}
