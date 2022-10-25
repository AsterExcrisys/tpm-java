package de.fhg.iosb.iad.tpm;

import java.time.Duration;
import java.time.Instant;

public class Timer {

	private Instant tickTime = Instant.now();

	public void tick() {
		tickTime = Instant.now();
	}

	public Duration tock() {
		return Duration.between(tickTime, Instant.now());
	}
}
