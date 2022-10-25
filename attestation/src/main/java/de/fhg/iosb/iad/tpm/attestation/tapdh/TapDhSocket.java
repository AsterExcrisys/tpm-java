package de.fhg.iosb.iad.tpm.attestation.tapdh;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketImpl;
import java.security.GeneralSecurityException;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import de.fhg.iosb.iad.tpm.attestation.AttestedSocket;
import de.fhg.iosb.iad.tpm.attestation.tapdh.handshake.TapDhClientHandshaker;
import de.fhg.iosb.iad.tpm.attestation.tapdh.handshake.TapDhHandshaker;
import de.fhg.iosb.iad.tpm.attestation.tapdh.handshake.TapDhServerHandshaker;

public class TapDhSocket extends Socket implements AttestedSocket {

	private final TapDhConfiguration config;

	private TapDhHandshaker handshaker;
	private Cipher encryptCipher, decryptCipher;

	protected TapDhSocket(SocketImpl socketImpl, TapDhConfiguration config) throws IOException {
		super(socketImpl);
		assert (config != null);
		this.config = config;
	}

	public TapDhSocket(InetAddress address, int port, TapDhConfiguration config) throws IOException {
		super(address, port);
		assert (config != null);
		this.config = config;
		performHandshake(false);
	}

	public TapDhSocket(String host, int port, TapDhConfiguration config) throws IOException {
		super(host, port);
		assert (config != null);
		this.config = config;
		performHandshake(false);
	}

	protected void performHandshake(boolean server) throws IOException {
		this.handshaker = server ? new TapDhServerHandshaker(super.getInputStream(), super.getOutputStream(), config)
				: new TapDhClientHandshaker(super.getInputStream(), super.getOutputStream(), config);
		this.handshaker.performHandshake();

		initializeCiphers();
	}

	private void initializeCiphers() throws IOException {
		try {
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			byte[] keyBytes = keyFactory
					.generateSecret(new PBEKeySpec(new String(handshaker.getGeneratedSecret()).toCharArray(),
							handshaker.getRandomIv(), 1024, 128))
					.getEncoded();
			SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
			encryptCipher = Cipher.getInstance("AES/CFB8/NoPadding");
			encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(handshaker.getRandomIv()));
			decryptCipher = Cipher.getInstance("AES/CFB8/NoPadding");
			decryptCipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(handshaker.getRandomIv()));
		} catch (GeneralSecurityException e) {
			throw new IOException("Failed to initialize encryption!", e);
		}
	}

	@Override
	public Map<Integer, String> getPeerPcrValues() {
		return handshaker.getPeerPcrValues();
	}

	@Override
	public InputStream getInputStream() throws IOException {
		if (decryptCipher == null)
			throw new IOException("Uninitialized decryption cipher.");
		return new CipherInputStream(super.getInputStream(), decryptCipher);
	}

	@Override
	public OutputStream getOutputStream() throws IOException {
		if (encryptCipher == null)
			throw new IOException("Uninitialized encryption cipher.");
		return new CipherOutputStream(super.getOutputStream(), encryptCipher);
	}

}
