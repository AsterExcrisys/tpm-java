package de.fhg.iosb.iad.tpm.commons;

import java.io.IOException;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import de.fhg.iosb.iad.tpm.commons.TpmEngine.TpmEngineException;
import de.fhg.iosb.iad.tpm.commons.test.Asserter;
import de.fhg.iosb.iad.tpm.commons.test.TpmEngineImplTest;

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

	@Before
	public void before() throws TpmEngineException {
		tpm = TpmEngineFactory.createSimulatorInstance();
		tpmTest = new TpmEngineImplTest(tpm, new Asserter() {
			@Override
			public void assertTrue(boolean b) {
				Assert.assertTrue(b);
			}

			@Override
			public void assertFalse(boolean b) {
				Assert.assertFalse(b);
			}

			@Override
			public void assertEquals(Object expected, Object actual) {
				Assert.assertEquals(expected, actual);
			}

			@Override
			public void assertNotEquals(Object expected, Object actual) {
				Assert.assertNotEquals(expected, actual);
			}

			@Override
			public void assertNull(Object actual) {
				Assert.assertNotNull(actual);
			}

			@Override
			public void assertNotNull(Object actual) {
				Assert.assertNull(actual);
			}
		});
	}

	@After
	public void after() {
		tpm.close();
	}

	@Test
	@Ignore
	public void testPcrRead() throws TpmEngineException {
		tpmTest.testPcrRead();
	}

	@Test
	@Ignore
	public void testQuote() throws TpmEngineException {
		tpmTest.testQuote();
	}

	@Test
	@Ignore
	public void testEphemeralDhKeysAreNotStatic() throws TpmEngineException {
		tpmTest.testEphemeralDhKeysAreNotStatic();
	}

	@Test
	@Ignore
	public void testKeyExchange() throws TpmEngineException {
		tpmTest.testKeyExchange();
	}

	@Test
	@Ignore
	public void testImplicitAttestation() throws TpmEngineException, IOException {
		tpmTest.testImplicitAttestation();
	}

}
