package de.fhg.iosb.iad.tpm.test;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.fhg.iosb.iad.tpm.SecurityHelper;
import de.fhg.iosb.iad.tpm.TpmEngine.TpmEngineException;
import de.fhg.iosb.iad.tpm.TpmEngineImpl;
import de.fhg.iosb.iad.tpm.TpmQuoteVerifier;
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

		// Read the PCRs again
		for (int pcr : pcrSelection)
			LOG.info("PCR {} is: {}", pcr, tpmEngine.getPcrValue(pcr));
	}

	public void testQuote() throws TpmEngineException {
		// Put something into the PCRs
		List<Integer> pcrSelection = Arrays.asList(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
		extendPcrsWithRandomData(pcrSelection);

		// Get public part of quoting key
		byte[] qkPub = tpmEngine.getQkPub();
		LOG.info("Generated a quoting key of size {} bytes", qkPub.length);
		// Get some random qualifying data
		byte[] qualifyingData = Helpers.RandomBytes(17);
		// Read PCRs to quote
		Map<Integer, String> pcrs = tpmEngine.getPcrValues(pcrSelection);
		LOG.info("The current PCR values are: {}", pcrs);
		// Quote PCRs
		byte[] quote = tpmEngine.quote(qualifyingData, pcrSelection);
		LOG.info("Generated a quote of size {} bytes", quote.length);
		// Verify quote
		TpmQuoteVerifier verifier = new TpmQuoteVerifier();
		boolean b = verifier.verifyQuote(quote, qualifyingData, qkPub, pcrs);
		LOG.info("Verifying quote with correct PCRs. Result: {}", b ? "VALID" : "INVALID");
		a.assertTrue(b);
		// Change value of one expected PCR and verify again
		pcrs.put(2, "D59AF3AE0DB1648B95B854C3E248D751B8453A6DA86DED2A44C033D08B5B658B");
		b = verifier.verifyQuote(quote, qualifyingData, qkPub, pcrs);
		LOG.info("Verifying quote with wrong PCRs. Result: {}", b ? "VALID!" : "INVALID!");
		a.assertFalse(b);
	}

	public void testEphemeralDhKeysAreNotStatic() throws TpmEngineException {
		// Create an ephemeral DH key pair
		byte[] dkKey1 = tpmEngine.createEphemeralDhKey();
		a.assertNotNull(dkKey1);
		byte[] dkKey2 = tpmEngine.createEphemeralDhKey();
		a.assertNotNull(dkKey2);
		a.assertFalse(Arrays.equals(dkKey1, dkKey2));
	}

	public void testKeyExchange() throws TpmEngineException {
		// Alice: Draws random nonce and transmits it to Bob
		byte[] nonceA = Helpers.RandomBytes(4);

		// Bob: Draws random nonce and transmits it to Alice
		byte[] nonceB = Helpers.RandomBytes(4);

		// Alice: Creates DH key pair
		byte[] dhKeyA = tpmEngine.createEphemeralDhKey();
		byte[] dhPubKeyA = tpmEngine.getDhKeyPub(dhKeyA);
		LOG.info("Created Diffie-Hellman key of size {} bytes for Alice", dhPubKeyA.length);

		// Alice: Certifies own DH public key with QK
		byte[] certA = tpmEngine.certifyEphemeralDhKey(dhKeyA, nonceB);
		LOG.info("Created Diffie-Hellman certificate of size {} bytes for Alice", certA.length);

		// Alice: Retrieves public part of the quoting key
		byte[] qkPubA = tpmEngine.getQkPub();

		// Alice: Transmits dhPubKeyA, certA and qkPubA to Bob

		// Bob: Creates DH key pair
		byte[] dhKeyB = tpmEngine.createEphemeralDhKey();
		byte[] dhPubKeyB = tpmEngine.getDhKeyPub(dhKeyB);
		LOG.info("Created Diffie-Hellman key of size {} bytes for Bob", dhPubKeyB.length);

		// Bob: Certifies own DH public key with QK (we use the same QK here for
		// simplicity)
		byte[] certB = tpmEngine.certifyEphemeralDhKey(dhKeyB, nonceA);
		LOG.info("Created Diffie-Hellman certificate of size {} bytes for Bob", certB.length);

		// Bob: Retrieves public part of the quoting key (we use the same QK here for
		// simplicity)
		byte[] qkPubB = qkPubA;

		// Bob: Transmits dhPubKeyB, certB and qkPubB to Bob

		// Alice: Verifies Bob's certificate and calculates shared secret using the TPM
		byte[] secretA = tpmEngine.calculateSharedDhSecret(dhKeyA, dhPubKeyB, certB, nonceA, qkPubB);
		a.assertNotNull(secretA);
		LOG.info("Alice successfully verified Bob's certificate. Her generated secret is: {}",
				SecurityHelper.bytesToHex(secretA));

		// Bob: Verifies Alice's certificate and calculates shared secret using the TPM
		byte[] secretB = tpmEngine.calculateSharedDhSecret(dhKeyB, dhPubKeyA, certA, nonceB, qkPubA);
		a.assertNotNull(secretB);
		LOG.info("Bob successfully verified Alice's certificate. His generated secret is: {}",
				SecurityHelper.bytesToHex(secretB));

		LOG.info("Shared secrets {}", (Arrays.equals(secretA, secretB) ? "MATCH!" : "DON'T match!"));
		a.assertTrue(Arrays.equals(secretA, secretB));
	}

	public void testImplicitAttestation() throws TpmEngineException {
		// Put something into the PCRs
		List<Integer> pcrNumbers = Arrays.asList(0, 1, 2, 3, 4);
		extendPcrsWithRandomData(pcrNumbers);

		// Calculate the policy digest using the current PCR values
		Map<Integer, String> pcrValues = tpmEngine.getPcrValues(pcrNumbers);
		byte[] policyDigest = tpmEngine.calculatePcrPolicyDigest(pcrValues, TPM_ALG_ID.SHA256);

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
				authHandle = tpmEngine.startPcrPolicyAuthSession(pcrNumbers, Helpers.RandomBytes(16));
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
				authHandle = tpmEngine.startPcrPolicyAuthSession(pcrNumbers, Helpers.RandomBytes(16));
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

}
