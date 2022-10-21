package de.fhg.iosb.iad.tpm;

import java.io.IOException;
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
import tss.tpm.QuoteResponse;
import tss.tpm.StartAuthSessionResponse;
import tss.tpm.TPM2B_DIGEST;
import tss.tpm.TPM2B_PRIVATE;
import tss.tpm.TPM2B_PUBLIC_KEY_RSA;
import tss.tpm.TPMA_OBJECT;
import tss.tpm.TPML_HANDLE;
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

	@Override
	public synchronized int startPcrPolicyAuthSession(Collection<Integer> pcrNumbers, byte[] nonceCaller)
			throws TpmEngineException {
		StartAuthSessionResponse sessionResponse = null;
		try {
			sessionResponse = tpm.StartAuthSession(TPM_HANDLE.NULL, TPM_HANDLE.NULL, nonceCaller, new byte[0],
					TPM_SE.POLICY, new TPMT_SYM_DEF(), TPM_ALG_ID.SHA256);
			tpm.PolicyPCR(sessionResponse.handle, calculatePcrDigest(getPcrValues(pcrNumbers)),
					new TPMS_PCR_SELECTION[] { TpmHelper.createPcrSelection(pcrNumbers, pcrHashAlg) });
			return sessionResponse.handle.handle;
		} catch (Exception e) {
			throw new TpmEngineException("Error in PolicyPCR()", e);
		}
	}

	@Override
	public synchronized TpmLoadedKey loadQk() throws TpmEngineException {
		CreatePrimaryResponse response = null;
		try {
			response = tpm.CreatePrimary(TPM_HANDLE.from(TPM_RH.ENDORSEMENT),
					new TPMS_SENSITIVE_CREATE(new byte[0], new byte[0]), qkTemplate, new byte[0],
					new TPMS_PCR_SELECTION[0]);
		} catch (Exception e) {
			throw new TpmEngineException("Error in TPM2_CreatePrimary()", e);
		}
		return new TpmLoadedKey(response.handle.handle, response.outPublic.toBytes());
	}

	@Override
	public synchronized TpmLoadedKey loadSrk() throws TpmEngineException {
		CreatePrimaryResponse response = null;
		try {
			response = tpm.CreatePrimary(TPM_HANDLE.from(TPM_RH.OWNER),
					new TPMS_SENSITIVE_CREATE(new byte[0], new byte[0]), srkTemplate, new byte[0],
					new TPMS_PCR_SELECTION[0]);
		} catch (Exception e) {
			throw new TpmEngineException("Error in TPM2_CreatePrimary()", e);
		}
		return new TpmLoadedKey(response.handle.handle, response.outPublic.toBytes());
	}

	@Override
	public synchronized TpmKey createEphemeralDhKey(int rootKeyHandle) throws TpmEngineException {
		CreateResponse response = null;
		try {
			response = tpm.Create(TPM_HANDLE.from(rootKeyHandle), new TPMS_SENSITIVE_CREATE(new byte[0], new byte[0]),
					dhTemplate, new byte[0], new TPMS_PCR_SELECTION[0]);
		} catch (Exception e) {
			throw new TpmEngineException("Error in TPM2_Create()", e);
		}
		return new TpmKey(response.outPrivate.toBytes(), response.outPublic.toBytes());
	}

	@Override
	public synchronized int loadKey(int rootKeyHandle, TpmKey key) throws TpmEngineException {
		TPMT_PUBLIC outPublic = null;
		TPM2B_PRIVATE outPrivate = null;
		try {
			outPublic = TPMT_PUBLIC.fromBytes(key.outPublic);
			outPrivate = TPM2B_PRIVATE.fromBytes(key.outPrivate);
		} catch (Exception e) {
			throw new TpmEngineException("Error while parsing TPM data structures", e);
		}

		TPM_HANDLE handle = null;
		try {
			handle = tpm.Load(TPM_HANDLE.from(rootKeyHandle), outPrivate, outPublic);
		} catch (Exception e) {
			throw new TpmEngineException("Error in TPM2_Create()", e);
		}
		return handle.handle;
	}

	@Override
	public synchronized void flushKey(int handle) throws TpmEngineException {
		tpm.FlushContext(TPM_HANDLE.from(handle));
	}

	@Override
	public synchronized byte[] certifyKey(int keyHandle, int signerHandle, byte[] qualifyingData)
			throws TpmEngineException {
		CertifyResponse cert = null;
		try {
			cert = tpm.Certify(TPM_HANDLE.from(keyHandle), TPM_HANDLE.from(signerHandle), qualifyingData,
					new TPMS_SIG_SCHEME_RSASSA(TPM_ALG_ID.SHA256));
		} catch (Exception e) {
			throw new TpmEngineException("Error in TPM2_Certify", e);
		}
		return cert.toBytes();
	}

	@Override
	public synchronized byte[] quote(int quotingKeyHandle, byte[] qualifyingData, Collection<Integer> pcrNumbers)
			throws TpmEngineException {
		TPMS_PCR_SELECTION[] pcrSelection = new TPMS_PCR_SELECTION[] {
				TpmHelper.createPcrSelection(pcrNumbers, pcrHashAlg) };

		QuoteResponse quote = null;
		try {
			quote = tpm.Quote(TPM_HANDLE.from(quotingKeyHandle), qualifyingData,
					new TPMS_SIG_SCHEME_RSASSA(TPM_ALG_ID.SHA256), pcrSelection);
		} catch (Exception e) {
			throw new TpmEngineException("Error in TPM2_Quote()", e);
		}
		return quote.toBytes();
	}

	@Override
	public synchronized byte[] generateSharedSecret(int privateKeyHandle, byte[] publicKey) throws TpmEngineException {
		TPMT_PUBLIC _publicKey = null;
		try {
			_publicKey = TPMT_PUBLIC.fromBytes(publicKey);
		} catch (Exception e) {
			throw new TpmEngineException("Error while parsing TPM data structures", e);
		}

		TPMS_ECC_POINT zPoint = null;
		try {
			zPoint = tpm.ECDH_ZGen(TPM_HANDLE.from(privateKeyHandle), (TPMS_ECC_POINT) _publicKey.unique);
		} catch (Exception e) {
			throw new TpmEngineException("Error in TPM2_ECDH_ZGen", e);
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
