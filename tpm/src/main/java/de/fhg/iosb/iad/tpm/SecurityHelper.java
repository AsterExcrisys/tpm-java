package de.fhg.iosb.iad.tpm;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Some cryptographic helper functions.
 * 
 * @author wagner
 *
 */
public final class SecurityHelper {

	private static final Logger LOG = LoggerFactory.getLogger(SecurityHelper.class);

	private static final char[] hexArray = "0123456789ABCDEF".toCharArray();

	private SecurityHelper() {
	}

	public static byte[] sha1(byte[] data) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-1");
			return digest.digest(data);
		} catch (NoSuchAlgorithmException e) {
			LOG.warn("Could not get SHA-1 instance!", e);
			return null;
		}
	}

	public static String sha1String(byte[] data) {
		return bytesToHex(sha1(data));
	}

	public static byte[] sha256(byte[] data) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			return digest.digest(data);
		} catch (NoSuchAlgorithmException e) {
			LOG.warn("Could not get SHA-256 instance!", e);
			return null;
		}
	}

	public static String sha256String(byte[] data) {
		return bytesToHex(sha256(data));
	}

	public static String bytesToHex(byte[] bytes) {
		char[] hexChars = new char[bytes.length * 2];
		for (int j = 0; j < bytes.length; j++) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}

	public static byte[] hexToBytes(String hex) {
		byte[] result = new byte[hex.length() / 2];
		for (int i = 0; i < result.length; i++) {
			int index = i * 2;
			int j = Integer.parseInt(hex.substring(index, index + 2), 16);
			result[i] = (byte) j;
		}
		return result;
	}

	public static String bytesToLogMsg(byte[] data) {
		return String.format("<%s bytes, SHA1: %s>", data.length, sha1String(data));
	}

}
