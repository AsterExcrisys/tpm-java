package de.fhg.iosb.iad.ttp.database;

import java.io.File;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Database {

	private static final Logger LOG = LoggerFactory.getLogger(Database.class);

	private Connection connection = null;

	public Database(String dbFileName) throws SQLException {
		makeJDBCConnection(dbFileName);
		createTables();
	}

	private void makeJDBCConnection(String dbFileName) {
		if (!new File(dbFileName).isFile())
			LOG.warn("File {} does not exist! Creating an empty database...", dbFileName);
		try {
			Class.forName("org.sqlite.JDBC");
		} catch (ClassNotFoundException e) {
			LOG.error("Couldn't find org.sqlite.JDBC driver!", e);
			return;
		}
		try {
			connection = DriverManager.getConnection("jdbc:sqlite:" + dbFileName);
			LOG.debug("Connection to database {} successful!", dbFileName);
		} catch (SQLException e) {
			LOG.error("Failed to make connection to database {}!", dbFileName, e);
		}
	}

	public void createTables() throws SQLException {
		try (Statement statement = connection.createStatement()) {
			String sql = "CREATE TABLE IF NOT EXISTS PCRValues ('id' INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, 'trustedState' INTEGER NOT NULL, 'PCRRegister' INTEGER NOT NULL, 'PCRValue' TEXT NOT NULL);";
			statement.executeUpdate(sql);
		}
		try (Statement statement = connection.createStatement()) {
			String sql = "CREATE TABLE IF NOT EXISTS TrustedStates ('id' INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, 'systemFingerprint' TEXT NOT NULL, 'trustedState' INTEGER NOT NULL, 'remarks' TEXT);";
			statement.executeUpdate(sql);
		}
	}

	public Set<Integer> getTrustedStatesForSystem(String systemFingerprint) throws SQLException {
		Set<Integer> result = new HashSet<Integer>();
		String sql = "SELECT * FROM TrustedStates WHERE systemFingerprint = ?";
		try (PreparedStatement pStatement = connection.prepareStatement(sql)) {
			pStatement.setString(1, systemFingerprint);
			try (ResultSet rs = pStatement.executeQuery()) {
				while (rs.next()) {
					result.add(rs.getInt("trustedState"));
				}
			}
		}
		return result;
	}

	public Map<Integer, String> getPCRValuesForTrustedState(int trustedState) throws SQLException {
		Map<Integer, String> result = new HashMap<Integer, String>();
		String sql = "SELECT * FROM PCRValues WHERE trustedState = ?";
		try (PreparedStatement pStatement = connection.prepareStatement(sql)) {
			pStatement.setInt(1, trustedState);
			try (ResultSet rs = pStatement.executeQuery()) {
				while (rs.next()) {
					result.put(rs.getInt("PCRRegister"), rs.getString("PCRValue"));
				}
			}
		}
		return result;
	}

}
