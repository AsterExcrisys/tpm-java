package de.fhg.iosb.iad.tpm;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import tss.Crypto;
import tss.Helpers;
import tss.Tpm;
import tss.TpmBuffer;
import tss.TpmDeviceTcp;
import tss.tpm.CertifyResponse;
import tss.tpm.CreatePrimaryResponse;
import tss.tpm.CreateResponse;
import tss.tpm.GetCapabilityResponse;
import tss.tpm.PCR_ReadResponse;
import tss.tpm.StartAuthSessionResponse;
import tss.tpm.TPM2B_DIGEST;
import tss.tpm.TPM2B_PUBLIC_KEY_RSA;
import tss.tpm.TPMA_OBJECT;
import tss.tpm.TPML_HANDLE;
import tss.tpm.TPMS_CERTIFY_INFO;
import tss.tpm.TPMS_ECC_PARMS;
import tss.tpm.TPMS_ECC_POINT;
import tss.tpm.TPMS_KEY_SCHEME_ECDH;
import tss.tpm.TPMS_NULL_ASYM_SCHEME;
import tss.tpm.TPMS_NULL_KDF_SCHEME;
import tss.tpm.TPMS_PCR_SELECTION;
import tss.tpm.TPMS_RSA_PARMS;
import tss.tpm.TPMS_SENSITIVE_CREATE;
import tss.tpm.TPMS_SIG_SCHEME_RSASSA;
import tss.tpm.TPMT_PUBLIC;
import tss.tpm.TPMT_SYM_DEF;
import tss.tpm.TPMT_SYM_DEF_OBJECT;
import tss.tpm.TPM_ALG_ID;
import tss.tpm.TPM_CAP;
import tss.tpm.TPM_ECC_CURVE;
import tss.tpm.TPM_HANDLE;
import tss.tpm.TPM_HT;
import tss.tpm.TPM_RH;
import tss.tpm.TPM_SE;
import tss.tpm.TPM_SU;

public class TpmEngineImpl implements TpmEngine {

	private static final Logger LOG = LoggerFactory.getLogger(TpmEngineImpl.class);

	private static final TPM_ALG_ID pcrHashAlg = TPM_ALG_ID.SHA256;

	private final Tpm tpm;
	private final TPMT_PUBLIC qkTemplate;
	private final TPMT_PUBLIC srkTemplate;
	private final TPMT_PUBLIC dhTemplate;

	protected TpmEngineImpl(Tpm tpm) {
		assert (tpm != null);
		this.tpm = tpm;

		this.qkTemplate = new TPMT_PUBLIC(TPM_ALG_ID.SHA256,
				new TPMA_OBJECT(TPMA_OBJECT.sign, TPMA_OBJECT.sensitiveDataOrigin, TPMA_OBJECT.userWithAuth,
						TPMA_OBJECT.restricted),
				new byte[0], new TPMS_RSA_PARMS(new TPMT_SYM_DEF_OBJECT(),
						new TPMS_SIG_SCHEME_RSASSA(TPM_ALG_ID.SHA256), 2048, 65537),
				new TPM2B_PUBLIC_KEY_RSA());

		this.srkTemplate = new TPMT_PUBLIC(TPM_ALG_ID.SHA256,
				new TPMA_OBJECT(TPMA_OBJECT.fixedTPM, TPMA_OBJECT.fixedParent, TPMA_OBJECT.sensitiveDataOrigin,
						TPMA_OBJECT.userWithAuth, TPMA_OBJECT.noDA, TPMA_OBJECT.restricted, TPMA_OBJECT.decrypt),
				new byte[0], new TPMS_RSA_PARMS(new TPMT_SYM_DEF_OBJECT(TPM_ALG_ID.AES, 128, TPM_ALG_ID.CFB),
						new TPMS_NULL_ASYM_SCHEME(), 2048, 0),
				new TPM2B_PUBLIC_KEY_RSA());

		this.dhTemplate = new TPMT_PUBLIC(TPM_ALG_ID.SHA256,
				new TPMA_OBJECT(TPMA_OBJECT.decrypt, TPMA_OBJECT.sensitiveDataOrigin, TPMA_OBJECT.userWithAuth),
				new byte[0], new TPMS_ECC_PARMS(new TPMT_SYM_DEF_OBJECT(), new TPMS_KEY_SCHEME_ECDH(TPM_ALG_ID.SHA256),
						TPM_ECC_CURVE.NIST_P256, new TPMS_NULL_KDF_SCHEME()),
				new TPMS_ECC_POINT());

		cleanSlots(TPM_HT.TRANSIENT);
		cleanSlots(TPM_HT.LOADED_SESSION);
	}

	private synchronized void cleanSlots(TPM_HT slotType) {
		GetCapabilityResponse caps = tpm.GetCapability(TPM_CAP.HANDLES, slotType.toInt() << 24, 8);
		TPML_HANDLE handles = (TPML_HANDLE) caps.capabilityData;

		if (handles.handle.length == 0)
			LOG.debug("No dangling {} handles", slotType.name());
		else
			for (TPM_HANDLE h : handles.handle) {
				LOG.debug("Dangling {} handle: {}", slotType.name(), h.handle);
				tpm.FlushContext(h);
			}
	}

	@Override
	public synchronized Tpm getTpmInterface() {
		return tpm;
	}

	@Override
	public synchronized byte[] getRandomBytes(int number) throws TpmEngineException {
		byte[] random = null;
		try {
			tpm.StirRandom(Helpers.RandomBytes(number));
			random = tpm.GetRandom(number);
		} catch (Exception e) {
			throw new TpmEngineException("Error in TPM2_GetRandom()", e);
		}
		return random;
	}

	@Override
	public synchronized String getPcrValue(int number) throws TpmEngineException {
		PCR_ReadResponse pcrAtStart = null;
		try {
			pcrAtStart = tpm.PCR_Read(TPMS_PCR_SELECTION.CreateSelectionArray(pcrHashAlg, number));
		} catch (Exception e) {
			throw new TpmEngineException("Error in TPM2_PCR_Read()", e);
		}
		return SecurityHelper.bytesToHex(pcrAtStart.pcrValues[0].buffer);
	}

	@Override
	public Map<Integer, String> getPcrValues(Collection<Integer> numbers) throws TpmEngineException {
		Map<Integer, String> result = new HashMap<Integer, String>();
		for (int n : numbers) {
			result.put(n, getPcrValue(n));
		}
		return result;
	}

	@Override
	public synchronized void extendPcr(int number, byte[] data) throws TpmEngineException {
		try {
			tpm.PCR_Event(TPM_HANDLE.pcr(number), data);
		} catch (Exception e) {
			throw new TpmEngineException("Error in TPM2_PCR_Event()", e);
		}
	}

	@Override
	public void extendPcrs(Map<Integer, byte[]> data) throws TpmEngineException {
		for (Entry<Integer, byte[]> e : data.entrySet()) {
			extendPcr(e.getKey(), e.getValue());
		}
	}

	@Override
	public byte[] calculatePcrDigest(Map<Integer, String> pcrValues) {
		TpmBuffer pcrDigests = new TpmBuffer();
		for (TPM2B_DIGEST d : TpmHelper.createPcrDigests(pcrValues))
			pcrDigests.writeByteBuf(d.buffer);
		return Crypto.hash(pcrHashAlg, pcrDigests.trim());
	}

	@Override
	public synchronized byte[] calculatePcrPolicyDigest(Map<Integer, String> pcrValues, TPM_ALG_ID authHashAlg)
			throws TpmEngineException {
		TPMS_PCR_SELECTION[] pcrSelection = new TPMS_PCR_SELECTION[] {
				TpmHelper.createPcrSelection(pcrValues.keySet(), pcrHashAlg) };
		StartAuthSessionResponse sessionResponse = null;
		byte[] policyDigest = null;
		try {
			sessionResponse = tpm.StartAuthSession(TPM_HANDLE.NULL, TPM_HANDLE.NULL, Helpers.RandomBytes(16),
					new byte[0], TPM_SE.TRIAL, new TPMT_SYM_DEF(), TPM_ALG_ID.SHA256);
			tpm.PolicyPCR(sessionResponse.handle, calculatePcrDigest(pcrValues), pcrSelection);
			policyDigest = tpm.PolicyGetDigest(sessionResponse.handle);
		} catch (Exception e) {
			throw new TpmEngineException("Error in PolicyPCR()", e);
		} finally {
			if (sessionResponse != null)
				tpm.FlushContext(sessionResponse.handle);
		}
		return policyDigest;
	}

	public synchronized TPM_HANDLE startPcrPolicyAuthSession(Collection<Integer> pcrNumbers, byte[] nonceCaller)
			throws TpmEngineException {
		StartAuthSessionResponse sessionResponse = null;
		try {
			sessionResponse = tpm.StartAuthSession(TPM_HANDLE.NULL, TPM_HANDLE.NULL, nonceCaller, new byte[0],
					TPM_SE.POLICY, new TPMT_SYM_DEF(), TPM_ALG_ID.SHA256);
			tpm.PolicyPCR(sessionResponse.handle, calculatePcrDigest(getPcrValues(pcrNumbers)),
					new TPMS_PCR_SELECTION[] { TpmHelper.createPcrSelection(pcrNumbers, pcrHashAlg) });
			return sessionResponse.handle;
		} catch (Exception e) {
			throw new TpmEngineException("Error in PolicyPCR()", e);
		}
	}

	private synchronized CreatePrimaryResponse loadQk() throws TpmEngineException {
		CreatePrimaryResponse response = null;
		try {
			response = tpm.CreatePrimary(TPM_HANDLE.from(TPM_RH.ENDORSEMENT),
					new TPMS_SENSITIVE_CREATE(new byte[0], new byte[0]), qkTemplate, new byte[0],
					new TPMS_PCR_SELECTION[0]);
		} catch (Exception e) {
			throw new TpmEngineException("Error in TPM2_CreatePrimary()", e);
		}
		return response;
	}

	private synchronized CreatePrimaryResponse loadSrk() throws TpmEngineException {
		CreatePrimaryResponse response = null;
		try {
			response = tpm.CreatePrimary(TPM_HANDLE.from(TPM_RH.OWNER),
					new TPMS_SENSITIVE_CREATE(new byte[0], new byte[0]), srkTemplate, new byte[0],
					new TPMS_PCR_SELECTION[0]);
		} catch (Exception e) {
			throw new TpmEngineException("Error in TPM2_CreatePrimary()", e);
		}
		return response;
	}

	@Override
	public synchronized byte[] getQkPub() throws TpmEngineException {
		CreatePrimaryResponse qk = loadQk();
		tpm.FlushContext(qk.handle);
		return qk.outPublic.toBytes();
	}

	@Override
	public synchronized byte[] quote(byte[] qualifyingData, Collection<Integer> pcrNumbers) throws TpmEngineException {
		CreatePrimaryResponse qk = loadQk();
		TPMS_PCR_SELECTION[] pcrSelection = new TPMS_PCR_SELECTION[] {
				TpmHelper.createPcrSelection(pcrNumbers, pcrHashAlg) };

		byte[] quote = null;
		try {
			quote = tpm.Quote(qk.handle, qualifyingData, new TPMS_SIG_SCHEME_RSASSA(TPM_ALG_ID.SHA256), pcrSelection)
					.toBytes();
		} catch (Exception e) {
			throw new TpmEngineException("Error in TPM2_Quote()", e);
		} finally {
			tpm.FlushContext(qk.handle);
		}
		return quote;
	}

	@Override
	public synchronized byte[] createEphemeralDhKey() throws TpmEngineException {
		// Create new ECDH key pair with SRK as parent
		CreatePrimaryResponse srk = loadSrk();
		CreateResponse dhKey = null;
		try {
			dhKey = tpm.Create(srk.handle, new TPMS_SENSITIVE_CREATE(new byte[0], new byte[0]), dhTemplate, new byte[0],
					new TPMS_PCR_SELECTION[0]);
		} catch (Exception e) {
			throw new TpmEngineException("Error in TPM2_Create()", e);
		} finally {
			tpm.FlushContext(srk.handle);
		}

		// Return public part of DH key
		return dhKey.toBytes();
	}

	@Override
	public byte[] getDhKeyPub(byte[] dhKey) throws TpmEngineException {
		CreateResponse dhKeyResponse = null;
		try {
			dhKeyResponse = CreateResponse.fromBytes(dhKey);
		} catch (Exception e) {
			throw new TpmEngineException("Error while parsing TPM data structures", e);
		}
		return dhKeyResponse.outPublic.toBytes();
	}

	@Override
	public synchronized byte[] certifyEphemeralDhKey(byte[] dhKey, byte[] qualifyingData) throws TpmEngineException {
		CreateResponse dhKeyResponse = null;
		try {
			dhKeyResponse = CreateResponse.fromBytes(dhKey);
		} catch (Exception e) {
			throw new TpmEngineException("Error while parsing TPM data structures", e);
		}

		// First, load the created DH key
		CreatePrimaryResponse srk = loadSrk();
		TPM_HANDLE dhKeyH = null;
		try {
			dhKeyH = tpm.Load(srk.handle, dhKeyResponse.outPrivate, dhKeyResponse.outPublic);
		} catch (Exception e) {
			throw new TpmEngineException("Error in TPM2_Load", e);
		}

		// Then sign the DH key and nonce with the QK
		CreatePrimaryResponse qk = loadQk();
		CertifyResponse cert = null;
		try {
			cert = tpm.Certify(dhKeyH, qk.handle, qualifyingData, new TPMS_SIG_SCHEME_RSASSA(TPM_ALG_ID.SHA256));
		} catch (Exception e) {
			throw new TpmEngineException("Error in TPM2_Certify", e);
		} finally {
			tpm.FlushContext(dhKeyH);
			tpm.FlushContext(qk.handle);
			tpm.FlushContext(srk.handle);
		}

		// Return the certificate info and signature
		return cert.toBytes();
	}

	@Override
	public synchronized byte[] calculateSharedDhSecret(byte[] dhKey, byte[] peerKeyPub, byte[] peerCertifyInfo,
			byte[] qualifyingData, byte[] quotingKeyPub) throws TpmEngineException {

		CreateResponse dhKeyResponse = null;
		TPMT_PUBLIC remoteDhPub = null;
		CertifyResponse remoteDhCert = null;
		TPMT_PUBLIC remoteQk = null;
		try {
			dhKeyResponse = CreateResponse.fromBytes(dhKey);
			remoteDhPub = TPMT_PUBLIC.fromBytes(peerKeyPub);
			remoteDhCert = CertifyResponse.fromBytes(peerCertifyInfo);
			remoteQk = TPMT_PUBLIC.fromBytes(quotingKeyPub);
		} catch (Exception e) {
			throw new TpmEngineException("Error while parsing TPM data structures", e);
		}

		// Verify that certifyInfo contains the expected nonce
		if (!Arrays.equals(remoteDhCert.certifyInfo.extraData, qualifyingData)) {
			LOG.warn("Failed to verify signature of the remote DH public key! Cannot calculate shared secret.");
			LOG.warn("Reason: The provided DH public key certificate does not contain the expected nonce.");
			return null;
		}
		// Verify that certifyInfo contains the claimed public key
		if (!Arrays.equals(((TPMS_CERTIFY_INFO) remoteDhCert.certifyInfo.attested).name, remoteDhPub.getName())) {
			LOG.warn("Failed to verify signature of the remote DH public key! Cannot calculate shared secret.");
			LOG.warn("Reason: The provided DH public key certificate does not match the presented public key.");
			return null;
		}
		// Verify signature of dhPubKeyA
		if (!remoteQk.validateSignature(remoteDhCert.certifyInfo.toBytes(), remoteDhCert.signature)) {
			LOG.warn("Failed to verify signature of the remote DH public key! Cannot calculate shared secret.");
			LOG.warn("Reason: The certificate signature does not validate under the remote quoting key.");
			return null;
		}

		// After verification, load my DH key and generate shared secret
		CreatePrimaryResponse srk = loadSrk();
		TPM_HANDLE dhKeyH = null;
		try {
			dhKeyH = tpm.Load(srk.handle, dhKeyResponse.outPrivate, dhKeyResponse.outPublic);
		} catch (Exception e) {
			throw new TpmEngineException("Error in TPM2_Load", e);
		}
		TPMS_ECC_POINT zPoint = null;
		try {
			zPoint = tpm.ECDH_ZGen(dhKeyH, (TPMS_ECC_POINT) remoteDhPub.unique);
		} catch (Exception e) {
			throw new TpmEngineException("Error in TPM2_ECDH_ZGen", e);
		} finally {
			tpm.FlushContext(dhKeyH);
			tpm.FlushContext(srk.handle);
			dhKey = null;
		}

		return zPoint.toBytes();
	}

	@Override
	public synchronized void shutdownTpm() throws TpmEngineException {
		try {
			if (tpm._getDevice() instanceof TpmDeviceTcp)
				tpm.Shutdown(TPM_SU.CLEAR);
		} catch (Exception e) {
			throw new TpmEngineException("Error in TPM2_Shutdown", e);
		}
		close();
	}

	@Override
	public synchronized void close() {
		try {
			tpm.close();
		} catch (IOException e) {
			LOG.error("Error while closing TPM connection", e);
		}
	}

}
