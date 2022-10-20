package de.fhg.iosb.iad.tpm.ttp;

import java.sql.SQLException;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.fhg.iosb.iad.tpm.ttp.database.Database;
import io.grpc.stub.StreamObserver;

public class TTPService extends TTPServiceGrpc.TTPServiceImplBase {

	private static final Logger LOG = LoggerFactory.getLogger(TTPService.class);

	private Database database;

	public TTPService(String dbFile) {
		try {
			this.database = new Database(dbFile);
		} catch (SQLException e) {
			LOG.error("Failed to load database {}", dbFile, e);
			this.database = null;
		}
	}

	@Override
	public void getValidPCRValues(TTPRequest request, StreamObserver<TTPResponse> responseObserver) {
		if (database == null) {
			LOG.warn("Database is not loaded! Responding with empty message.");
			responseObserver.onNext(TTPResponse.newBuilder().build());
			responseObserver.onCompleted();
			return;
		}

		String systemFingerprint = request.getQuotingKeyFingerprint();
		LOG.info("Received request for system {}", systemFingerprint);

		try {
			Set<Integer> trustedStates = database.getTrustedStatesForSystem(systemFingerprint);
			LOG.info("System has {} trusted states.", trustedStates.size());

			TTPResponse.Builder response = TTPResponse.newBuilder();
			for (int state : trustedStates) {
				Map<Integer, String> pcrValues = database.getPCRValuesForTrustedState(state);
				response.addTrustedStates(SystemState.newBuilder().putAllPcrValues(pcrValues).build());
			}

			responseObserver.onNext(response.build());
			responseObserver.onCompleted();
		} catch (SQLException e) {
			LOG.error("Error while accessing database!", e);
			responseObserver.onNext(TTPResponse.newBuilder().build());
			responseObserver.onCompleted();
		}
	}

}