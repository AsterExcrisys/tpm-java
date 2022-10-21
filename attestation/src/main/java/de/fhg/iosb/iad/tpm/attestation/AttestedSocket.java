package de.fhg.iosb.iad.tpm.attestation;

import java.util.Map;

public interface AttestedSocket {

	/**
	 * Retrieve the peer's attested PCR values.
	 * 
	 * @return Attested PCR values
	 */
	Map<Integer, String> getPeerPcrValues();
}
