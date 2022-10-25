package de.fhg.iosb.iad.tpm.attestation.tapssl;

import java.security.cert.Certificate;
import java.util.Collection;

import de.fhg.iosb.iad.tpm.TpmEngine;
import de.fhg.iosb.iad.tpm.TpmEngine.TpmLoadedKey;
import de.fhg.iosb.iad.tpm.attestation.tap.TapConfiguration;

public class TapSslConfiguration extends TapConfiguration {

	private Certificate[] peerCertificates = new Certificate[0];
	private Certificate[] localCertificates = new Certificate[0];

	public TapSslConfiguration(TpmEngine tpmEngine, TpmLoadedKey quotingKey, Collection<Integer> pcrSelection) {
		super(tpmEngine, quotingKey, pcrSelection);
	}

	protected void setCertificates(Certificate[] peerCertificates, Certificate[] localCertficiates) {
		this.peerCertificates = peerCertificates;
		this.localCertificates = localCertficiates;
	}

	public Certificate[] getPeerCertificates() {
		return peerCertificates;
	}

	public Certificate[] getLocalCertificates() {
		return localCertificates;
	}

}
