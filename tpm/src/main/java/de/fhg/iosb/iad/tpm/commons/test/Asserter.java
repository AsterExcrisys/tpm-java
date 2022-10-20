package de.fhg.iosb.iad.tpm.commons.test;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Asserter {

	private static final Logger LOG = LoggerFactory.getLogger(Asserter.class);

	public void assertTrue(boolean b) {
		if (!b)
			LOG.warn("Assertion failed! Expected true, was: {}", b);
	}

	public void assertFalse(boolean b) {
		if (b)
			LOG.warn("Assertion failed! Expected false, was: {}", b);
	}

	public void assertEquals(Object expected, Object actual) {
		if (!expected.equals(actual))
			LOG.warn("Assertion failed! Expected {}, was: {}", expected, actual);
	}

	public void assertNotEquals(Object expected, Object actual) {
		if (expected == actual || expected.equals(actual))
			LOG.warn("Assertion failed! Expected {}, was: {}", expected, actual);
	}

	public void assertNull(Object actual) {
		if (actual != null)
			LOG.warn("Assertion failed! Expected null, was: {}", actual);
	}

	public void assertNotNull(Object actual) {
		if (actual == null)
			LOG.warn("Assertion failed! Expected not null, was: {}", actual);
	}

}
