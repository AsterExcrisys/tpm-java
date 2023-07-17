package de.fhg.iosb.iad.tpm.test;

import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.fhg.iosb.iad.tpm.SecurityHelper;
import de.fhg.iosb.iad.tpm.Timer;
import de.fhg.iosb.iad.tpm.TpmEngine.TpmEngineException;
import de.fhg.iosb.iad.tpm.TpmEngine.TpmKey;
import de.fhg.iosb.iad.tpm.TpmEngine.TpmLoadedKey;
import de.fhg.iosb.iad.tpm.TpmEngineImpl;
import de.fhg.iosb.iad.tpm.TpmValidator;
import de.fhg.iosb.iad.tpm.TpmValidator.TpmValidationException;
import tss.Helpers;
import tss.Tpm;
import tss.TpmException;
import tss.tpm.CreatePrimaryResponse;
import tss.tpm.TPM2B_PUBLIC_KEY_RSA;
import tss.tpm.TPMA_OBJECT;
import tss.tpm.TPMS_NULL_SIG_SCHEME;
import tss.tpm.TPMS_PCR_SELECTION;
import tss.tpm.TPMS_RSA_PARMS;
import tss.tpm.TPMS_SENSITIVE_CREATE;
import tss.tpm.TPMS_SIG_SCHEME_RSASSA;
import tss.tpm.TPMT_HA;
import tss.tpm.TPMT_PUBLIC;
import tss.tpm.TPMT_SYM_DEF_OBJECT;
import tss.tpm.TPMT_TK_HASHCHECK;
import tss.tpm.TPMU_SIGNATURE;
import tss.tpm.TPM_ALG_ID;
import tss.tpm.TPM_HANDLE;
import tss.tpm.TPM_RH;

/**
 * Test cases for the TPM engine.
 * 
 * @author wagner
 *
 */
public class TpmEngineImplTest {

	private static final Logger LOG = LoggerFactory.getLogger(TpmEngineImplTest.class);

	private final TpmEngineImpl tpmEngine;
	private final Asserter a;

	public TpmEngineImplTest(TpmEngineImpl tpm) throws TpmEngineException {
		this(tpm, new Asserter());
	}

	public TpmEngineImplTest(TpmEngineImpl tpm, Asserter a) throws TpmEngineException {
		this.a = a;
		this.tpmEngine = tpm;
	}

	public void extendPcrsWithRandomData(List<Integer> pcrSelection) throws TpmEngineException {
		for (int pcr : pcrSelection)
			tpmEngine.extendPcr(pcr, Helpers.RandomBytes(16));
	}

	public void testPcrRead() throws TpmEngineException {
		// Put something into the PCRs
		List<Integer> pcrSelection = Arrays.asList(0, 1, 2, 3, 4);
		extendPcrsWithRandomData(pcrSelection);

		// Read the PCRs
		for (int pcr : pcrSelection) {
			String _pcr = tpmEngine.getPcrValue(pcr);
			LOG.info("PCR {} is: {}", pcr, _pcr);
			a.assertNotEquals("0000000000000000000000000000000000000000000000000000000000000000", _pcr);
		}
	}

	public void testPcrReset() throws TpmEngineException {
		// Put something into PCR 16
		tpmEngine.extendPcr(16, Helpers.RandomBytes(16));

		// Read the PCR
		String pcr = tpmEngine.getPcrValue(16);
		LOG.info("PCR 16 is: {}", pcr);
		a.assertNotEquals("0000000000000000000000000000000000000000000000000000000000000000", pcr);

		// Reset and read the PCR again
		LOG.info("Reset PCR 16...");
		tpmEngine.resetPcr(16);
		pcr = tpmEngine.getPcrValue(16);
		LOG.info("PCR 16 is: {}", pcr);
		a.assertEquals("0000000000000000000000000000000000000000000000000000000000000000", pcr);
	}

	public void testQuote() throws TpmEngineException, TpmValidationException {
		// Put something into the PCRs
		List<Integer> pcrSelection = Arrays.asList(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
		extendPcrsWithRandomData(pcrSelection);

		// Load quoting key
		TpmLoadedKey qk = tpmEngine.loadQk();
		LOG.info("Loaded a quoting key of size {} bytes", qk.outPublic.length);

		byte[] qualifyingData = Helpers.RandomBytes(17);
		byte[] quote = null;
		Map<Integer, String> pcrs = null;
		try {
			// Read PCRs to quote
			pcrs = tpmEngine.getPcrValues(pcrSelection);
			LOG.info("The current PCR values are: {}", pcrs);

			// Generate quote for the selected PCRs
			quote = tpmEngine.quote(qk.handle, qualifyingData, pcrSelection);
			LOG.info("Generated a quote of size {} bytes", quote.length);
		} finally {
			// Flush the quoting key
			tpmEngine.flushKey(qk.handle);
		}

		// Verify the quote
		TpmValidator validator = new TpmValidator();
		boolean b = validator.validateQuote(quote, qualifyingData, qk.outPublic, pcrs);
		LOG.info("Verifying quote with correct PCRs. Result: {}", b ? "VALID" : "INVALID");
		a.assertTrue(b);

		// Change value of one expected PCR and verify the quote again
		pcrs.put(2, "D59AF3AE0DB1648B95B854C3E248D751B8453A6DA86DED2A44C033D08B5B658B");
		b = validator.validateQuote(quote, qualifyingData, qk.outPublic, pcrs);
		LOG.info("Verifying quote with wrong PCRs. Result: {}", b ? "VALID!" : "INVALID!");
		a.assertFalse(b);
	}

	public void testEphemeralDhKeysAreNotStatic() throws TpmEngineException {
		// Load storage root key
		TpmLoadedKey srk = tpmEngine.loadSrk();

		TpmKey dkKey1 = null;
		TpmKey dkKey2 = null;
		try {
			// Create an ephemeral DH key pair
			dkKey1 = tpmEngine.createEphemeralDhKey(srk.handle);
			dkKey2 = tpmEngine.createEphemeralDhKey(srk.handle);
		} finally {
			// Flush storage root key
			tpmEngine.flushKey(srk.handle);
		}

		a.assertFalse(Arrays.equals(dkKey1.outPublic, dkKey2.outPublic));
	}

	public void testKeyExchange() throws TpmEngineException, TpmValidationException {
		// Load the quoting key and storage root key used for both Alice and Bob
		TpmLoadedKey qk = tpmEngine.loadQk();
		TpmLoadedKey srk = tpmEngine.loadSrk();

		try {
			// Alice: Draws random nonce and transmits it to Bob
			byte[] nonceA = Helpers.RandomBytes(4);

			// Bob: Draws random nonce and transmits it to Alice
			byte[] nonceB = Helpers.RandomBytes(4);

			// Alice: Creates DH key pair
			TpmKey dhKeyA = tpmEngine.createEphemeralDhKey(srk.handle);
			byte[] dhKeyPubA = dhKeyA.outPublic;
			LOG.info("Created Diffie-Hellman key of size {} bytes for Alice", dhKeyPubA.length);

			// Alice: Load and certify own DH public key with QK
			int dhKeyHandleA = tpmEngine.loadKey(srk.handle, dhKeyA);
			byte[] certA = null;
			try {
				certA = tpmEngine.certifyKey(dhKeyHandleA, qk.handle, nonceB);
				LOG.info("Created Diffie-Hellman certificate of size {} bytes for Alice", certA.length);
			} finally {
				tpmEngine.flushKey(dhKeyHandleA);
			}

			// Alice: Retrieves public part of the quoting key
			byte[] qkPubA = qk.outPublic;

			// Alice: Transmits dhKeyPubA, certA and qkPubA to Bob

			// Bob: Creates DH key pair
			TpmKey dhKeyB = tpmEngine.createEphemeralDhKey(srk.handle);
			byte[] dhKeyPubB = dhKeyB.outPublic;
			LOG.info("Created Diffie-Hellman key of size {} bytes for Bob", dhKeyPubB.length);

			// Bob: Load and certify own DH public key with QK (we use the same QK here for
			// simplicity)
			int dhKeyHandleB = tpmEngine.loadKey(srk.handle, dhKeyB);
			byte[] certB = null;
			try {
				certB = tpmEngine.certifyKey(dhKeyHandleB, qk.handle, nonceA);
				LOG.info("Created Diffie-Hellman certificate of size {} bytes for Bob", certB.length);
			} finally {
				tpmEngine.flushKey(dhKeyHandleB);
			}

			// Bob: Retrieves public part of the quoting key (we use the same QK here for
			// simplicity)
			byte[] qkPubB = qk.outPublic;

			// Bob: Transmits dhKeyPubB, certB and qkPubB to Bob

			// Alice: Verifies Bob's certificate and calculates shared secret using the TPM
			a.assertTrue(new TpmValidator().validateKeyCertification(dhKeyPubB, certB, nonceA, qkPubB));
			dhKeyHandleA = tpmEngine.loadKey(srk.handle, dhKeyA);
			byte[] secretA = null;
			try {
				secretA = tpmEngine.generateSharedSecret(dhKeyHandleA, dhKeyPubB);
			} finally {
				tpmEngine.flushKey(dhKeyHandleA);
			}
			a.assertNotNull(secretA);
			LOG.info("Alice successfully verified Bob's certificate. Her generated secret is: {}",
					SecurityHelper.bytesToHex(secretA));

			// Bob: Verifies Alice's certificate and calculates shared secret using the TPM
			a.assertTrue(new TpmValidator().validateKeyCertification(dhKeyPubA, certA, nonceB, qkPubA));
			dhKeyHandleB = tpmEngine.loadKey(srk.handle, dhKeyB);
			byte[] secretB = null;
			try {
				secretB = tpmEngine.generateSharedSecret(dhKeyHandleB, dhKeyPubA);
			} finally {
				tpmEngine.flushKey(dhKeyHandleB);
			}
			a.assertNotNull(secretB);
			LOG.info("Bob successfully verified Alice's certificate. His generated secret is: {}",
					SecurityHelper.bytesToHex(secretB));

			LOG.info("Shared secrets {}", (Arrays.equals(secretA, secretB) ? "MATCH!" : "DON'T match!"));
			a.assertTrue(Arrays.equals(secretA, secretB));
		} finally {
			// Flush storage root key and quoting key
			tpmEngine.flushKey(srk.handle);
			tpmEngine.flushKey(qk.handle);
		}
	}

	public void testCreationCertification() throws TpmEngineException, TpmValidationException {
		// Load the quoting key and storage root key
		TpmLoadedKey qk = tpmEngine.loadQk();
		TpmLoadedKey srk = tpmEngine.loadSrk();

		// Put something into the PCRs
		List<Integer> pcrNumbers = Arrays.asList(0, 1, 2, 3, 4);
		extendPcrsWithRandomData(pcrNumbers);
		Map<Integer, String> expectedPCRs = tpmEngine.getPcrValues(pcrNumbers);

		try {
			// Create a new DH key pair
			TpmKey dhKey = tpmEngine.createEphemeralDhKey(srk.handle, pcrNumbers);
			byte[] dhKeyPub = dhKey.outPublic;
			LOG.info("Created Diffie-Hellman key of size {} bytes", dhKeyPub.length);

			// Load and certify creation of DH public key with QK
			int dhKeyHandle = tpmEngine.loadKey(srk.handle, dhKey);
			byte[] cert = null;
			byte[] nonce = Helpers.RandomBytes(4);
			try {
				cert = tpmEngine.certifyCreation(dhKeyHandle, qk.handle, nonce, dhKey.creationInfo);
				LOG.info("Created creation certificate of size {} bytes", cert.length);
			} finally {
				tpmEngine.flushKey(dhKeyHandle);
			}

			// Validate certification
			a.assertTrue(new TpmValidator().validateCreationCertification(dhKeyPub, cert, nonce, qk.outPublic,
					dhKey.creationInfo.creationData, expectedPCRs));
			LOG.info("Certificate successfully validated!");
		} finally {
			// Flush storage root key and quoting key
			tpmEngine.flushKey(srk.handle);
			tpmEngine.flushKey(qk.handle);
		}
	}

	public void testImplicitAttestation() throws TpmEngineException {
		// Put something into the PCRs
		List<Integer> pcrNumbers = Arrays.asList(0, 1, 2, 3, 4);
		extendPcrsWithRandomData(pcrNumbers);

		// Calculate the policy digest using the current PCR values
		Map<Integer, String> pcrValues = tpmEngine.getPcrValues(pcrNumbers);
		byte[] policyDigest = tpmEngine.calculatePcrPolicyDigest(pcrValues);

		// Create a policy-authorized signing key bound to the created PCR policy.
		// Note that TPMA_OBJECT.userWithAuth must not be set in this key to enforce
		// user-level authorization with policy only!
		synchronized (tpmEngine) {
			Tpm tpm = tpmEngine.getTpmInterface();
			TPMT_PUBLIC keyTemplate = new TPMT_PUBLIC(TPM_ALG_ID.SHA256,
					new TPMA_OBJECT(TPMA_OBJECT.sign, TPMA_OBJECT.sensitiveDataOrigin), policyDigest,
					new TPMS_RSA_PARMS(new TPMT_SYM_DEF_OBJECT(), new TPMS_SIG_SCHEME_RSASSA(TPM_ALG_ID.SHA256), 2048,
							65537),
					new TPM2B_PUBLIC_KEY_RSA());
			CreatePrimaryResponse keyResponse = tpm.CreatePrimary(TPM_HANDLE.from(TPM_RH.ENDORSEMENT),
					new TPMS_SENSITIVE_CREATE(new byte[0], new byte[0]), keyTemplate, new byte[0],
					new TPMS_PCR_SELECTION[0]);

			// Start an authorization session and use the new signing key in a valid state
			TPM_HANDLE authHandle = null;
			try {
				LOG.info("Loading an implicit attestation key...");
				authHandle = TPM_HANDLE.from(tpmEngine.startPcrPolicyAuthSession(pcrNumbers, Helpers.RandomBytes(16)));
				LOG.info("Expected policy digest is: {}", SecurityHelper.bytesToHex(policyDigest));
				LOG.info("Actual policy digest is:   {}", SecurityHelper.bytesToHex(tpm.PolicyGetDigest(authHandle)));

				// Use the protected signature key in a valid state
				TPMU_SIGNATURE signature = tpm._withSession(authHandle).Sign(keyResponse.handle,
						TPMT_HA.fromHashOf(TPM_ALG_ID.SHA256, "Something to sign").digest, new TPMS_NULL_SIG_SCHEME(),
						new TPMT_TK_HASHCHECK());
				LOG.info("Successfully used the implicit attestation key to create a signature:\n{}",
						signature.toString());
			} catch (TpmException e) {
				LOG.error("Failed to use implicit attestation key in a valid state!", e);
				tpm.FlushContext(keyResponse.handle);
				throw e;
			} finally {
				if (authHandle != null)
					tpm.FlushContext(authHandle);
				authHandle = null;
			}

			// Change one of the PCRs and try to use the key again
			extendPcrsWithRandomData(Arrays.asList(2));
			boolean success = false;
			try {
				LOG.info("Loading the implicit attestation key again after changing the state...");
				authHandle = TPM_HANDLE.from(tpmEngine.startPcrPolicyAuthSession(pcrNumbers, Helpers.RandomBytes(16)));
				LOG.info("Expected policy digest is: {}", SecurityHelper.bytesToHex(policyDigest));
				LOG.info("Actual policy digest is:   {}", SecurityHelper.bytesToHex(tpm.PolicyGetDigest(authHandle)));

				// Use the protected signature key in an invalid state. This should fail with
				// code POLICY_FAIL.
				tpm._withSession(authHandle).Sign(keyResponse.handle,
						TPMT_HA.fromHashOf(TPM_ALG_ID.SHA256, "Something to sign").digest, new TPMS_NULL_SIG_SCHEME(),
						new TPMT_TK_HASHCHECK());
				LOG.error("FAILURE! Created signature despite invalid state!");
			} catch (TpmException e) {
				LOG.info("Successfully failed to load the policy because the PCR values are wrong ;)");
				success = true;
			} finally {
				tpm.FlushContext(keyResponse.handle);
				if (authHandle != null)
					tpm.FlushContext(authHandle);
			}

			a.assertTrue(success);
		}
	}

	private void printResults(String command, LinkedList<Duration> durations) {
		// Calculate results
		double meanMicros = 0;
		for (Duration d : durations)
			meanMicros += (double) d.toNanos() / 1000.0d;
		meanMicros = meanMicros / durations.size();

		double sddMicros = 0;
		for (Duration d : durations)
			sddMicros += (((double) d.toNanos() / 1000.0d) - meanMicros)
					* (((double) d.toNanos() / 1000.0d) - meanMicros);
		double varMicros = sddMicros / (durations.size() - 1);

		LOG.info("##### RESULTS ################################");
		LOG.info("Command: {}", command);
		LOG.info("n      = {}", durations.size());
		LOG.info("min    = {}ms", Collections.min(durations).toMillis());
		LOG.info("max    = {}ms", Collections.max(durations).toMillis());
		LOG.info("mean   = {}ms", meanMicros / 1000.0);
		LOG.info("sigma  = {}us", Math.sqrt(varMicros));
		LOG.info("##############################################");
	}

	public void testTpmSpeed(int n) throws TpmEngineException, TpmValidationException {
		Timer timer = new Timer();
		List<Integer> pcrSelection = Arrays.asList(0, 1, 2, 3, 4, 5, 6, 7);

		// Load quoting key
		LOG.info("Loading quoting key...");
		timer.tick();
		TpmLoadedKey qk = tpmEngine.loadQk();
		LOG.info("Loaded a quoting key of size {} bytes in {}s", qk.outPublic.length, timer.tock().toSeconds());

		// Load root key
		LOG.info("Loading storage root key...");
		timer.tick();
		TpmLoadedKey srk = tpmEngine.loadSrk();
		LOG.info("Loaded a storage root key of size {} bytes in {}s", srk.outPublic.length, timer.tock().toSeconds());

		LinkedList<Duration> durations = new LinkedList<>();
		try {
			// Test PCR read speed
			LOG.info("##### START ###################################");
			LOG.info("Testing performance of command TPM2_PCR_Read...");
			for (int i = 0; i < n + 1; i++) {
				timer.tick();
				Map<Integer, String> pcrs = tpmEngine.getPcrValues(pcrSelection);

				if (i > 0) { // Remove first run as outlier
					Duration d = timer.tock();
					durations.add(d);
					LOG.info("Read {} PCRs ({}/{}) in {}ms", pcrs.size(), i, n, d.toMillis());
				}
			}
			printResults("TPM2_PCR_Read", durations);

			// Test PCR reset speed
			durations.clear();
			LOG.info("##### START ###################################");
			LOG.info("Testing performance of command TPM2_PCR_Reset(16)...");
			for (int i = 0; i < n + 1; i++) {
				timer.tick();
				tpmEngine.resetPcr(16);

				if (i > 0) { // Remove first run as outlier
					Duration d = timer.tock();
					durations.add(d);
					LOG.info("Reset PCR 16 ({}/{}) in {}ms", i, n, d.toMillis());
				}
			}
			printResults("TPM2_PCR_Reset(16)", durations);

			// Test PCR extend speed
			durations.clear();
			LOG.info("##### START ###################################");
			LOG.info("Testing performance of command TPM2_PCR_Extend(16)...");
			for (int i = 0; i < n + 1; i++) {
				byte[] qualifyingData = Helpers.RandomBytes(96);
				timer.tick();
				tpmEngine.extendPcr(16, qualifyingData);

				if (i > 0) { // Remove first run as outlier
					Duration d = timer.tock();
					durations.add(d);
					LOG.info("Extend PCR 16 ({}/{}) in {}ms", i, n, d.toMillis());
				}
			}
			printResults("TPM2_PCR_Extend(16)", durations);

			// Test quoting speed
			durations.clear();
			LOG.info("##### START ###################################");
			LOG.info("Testing performance of command TPM2_Quote...");
			for (int i = 0; i < n + 1; i++) {
				byte[] qualifyingData = Helpers.RandomBytes(32);
				timer.tick();
				byte[] quote = tpmEngine.quote(qk.handle, qualifyingData, pcrSelection);

				if (i > 0) { // Remove first run as outlier
					Duration d = timer.tock();
					durations.add(d);
					LOG.info("Generated quote {}/{} of size {} in {}ms", i, n, quote.length, d.toMillis());
				}
			}
			printResults("TPM2_Quote", durations);

			// Test DH key creation
			durations.clear();
			LinkedList<Duration> durations_create = new LinkedList<>();
			LinkedList<Duration> durations_load = new LinkedList<>();
			LinkedList<Duration> durations_certkey = new LinkedList<>();
			LinkedList<Duration> durations_certcreation = new LinkedList<>();
			LinkedList<Duration> durations_zgen = new LinkedList<>();
			LOG.info("##### START ###################################");
			LOG.info("Testing performance of ECDH key exchange...");
			for (int i = 0; i < n + 1; i++) {
				timer.tick();
				TpmKey dh = tpmEngine.createEphemeralDhKey(srk.handle, pcrSelection);
				if (i > 0) { // Remove first run as outlier
					Duration d = timer.tock();
					durations_create.add(d);
					LOG.info("Generated ECDH key {}/{} in {}ms", i, n, d.toMillis());
				}

				timer.tick();
				int dhh = tpmEngine.loadKey(srk.handle, dh);
				if (i > 0) { // Remove first run as outlier
					Duration d = timer.tock();
					durations_load.add(d);
					LOG.info("Loaded ECDH key {}/{} in {}ms", i, n, d.toMillis());
				}

				try {
					byte[] qualifyingData = Helpers.RandomBytes(32);
					timer.tick();
					tpmEngine.certifyKey(dhh, qk.handle, qualifyingData);
					if (i > 0) { // Remove first run as outlier
						Duration d = timer.tock();
						durations_certkey.add(d);
						LOG.info("Certified ECDH key {}/{} in {}ms", i, n, d.toMillis());
					}

					qualifyingData = Helpers.RandomBytes(32);
					timer.tick();
					tpmEngine.certifyCreation(dhh, qk.handle, qualifyingData, dh.creationInfo);
					if (i > 0) { // Remove first run as outlier
						Duration d = timer.tock();
						durations_certcreation.add(d);
						LOG.info("Certified ECDH key creation {}/{} in {}ms", i, n, d.toMillis());
					}

					timer.tick();
					tpmEngine.generateSharedSecret(dhh, dh.outPublic);
					if (i > 0) { // Remove first run as outlier
						Duration d = timer.tock();
						durations_zgen.add(d);
						LOG.info("Generated shared secret {}/{} in {}ms", i, n, d.toMillis());
					}
				} finally {
					tpmEngine.flushKey(dhh);
				}
			}
			printResults("TPM2_Create(ECDH)", durations_create);
			printResults("TPM2_Load(ECDH)", durations_load);
			printResults("TPM2_Certify(ECDH)", durations_certkey);
			printResults("TPM2_CertifyCreation(ECDH)", durations_certcreation);
			printResults("TPM2_ECDH_ZGen()", durations_zgen);
		} finally {
			// Flush the keys
			tpmEngine.flushKey(srk.handle);
			tpmEngine.flushKey(qk.handle);
		}

		a.assertTrue(true);
	}

}
