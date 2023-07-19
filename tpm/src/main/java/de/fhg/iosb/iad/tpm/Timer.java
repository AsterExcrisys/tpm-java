package de.fhg.iosb.iad.tpm;

import java.time.Duration;
import java.time.Instant;

public class Timer {

	private Instant tickTime = Instant.now();
	private Duration lastTock = Duration.ZERO;

	public void tick() {
		tickTime = Instant.now();
	}

	public Duration tock() {
		lastTock = Duration.between(tickTime, Instant.now());
		return lastTock;
	}

	public Duration lastTock() {
		return lastTock;
	}
}
