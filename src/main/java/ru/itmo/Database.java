package ru.itmo;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

final class Database {
    private final String url;

    Database(String url) throws SQLException {
        this.url = url;
        try (var connection = connect(); var statement = connection.createStatement()) {
            statement.executeUpdate("""
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY,
                        login TEXT NOT NULL UNIQUE,
                        password_hash TEXT NOT NULL
                    )
                    """);
            statement.executeUpdate("""
                    CREATE TABLE IF NOT EXISTS notes (
                        id INTEGER PRIMARY KEY,
                        user_id INTEGER NOT NULL REFERENCES users(id),
                        text TEXT NOT NULL
                    )
                    """);
        }
    }

    private Connection connect() throws SQLException {
        var connection = DriverManager.getConnection(url);
        try (var statement = connection.createStatement()) {
            statement.execute("PRAGMA foreign_keys = ON");
            statement.execute("PRAGMA busy_timeout = 5000");
            return connection;
        } catch (SQLException e) {
            connection.close();
            throw e;
        }
    }

    boolean register(String login, String hash) throws SQLException {
        try (var connection = connect(); var statement = connection.prepareStatement(
                "INSERT INTO users(login, password_hash) VALUES (?, ?) ON CONFLICT(login) DO NOTHING")) {
            statement.setString(1, login);
            statement.setString(2, hash);
            return statement.executeUpdate() == 1;
        }
    }

    User findUser(String login) throws SQLException {
        try (var connection = connect(); var statement = connection.prepareStatement(
                "SELECT id, password_hash FROM users WHERE login = ?")) {
            statement.setString(1, login);
            try (var result = statement.executeQuery()) {
                return result.next() ? new User(result.getLong("id"), result.getString("password_hash")) : null;
            }
        }
    }

    List<Note> notes(long userId) throws SQLException {
        try (var connection = connect(); var statement = connection.prepareStatement(
                "SELECT id, text FROM notes WHERE user_id = ? ORDER BY id DESC LIMIT 100")) {
            statement.setLong(1, userId);
            try (var result = statement.executeQuery()) {
                var notes = new ArrayList<Note>();
                while (result.next()) {
                    notes.add(new Note(result.getLong("id"), result.getString("text")));
                }
                return notes;
            }
        }
    }

    Note addNote(long userId, String text) throws SQLException {
        try (var connection = connect(); var statement = connection.prepareStatement(
                "INSERT INTO notes(user_id, text) VALUES (?, ?) RETURNING id")) {
            statement.setLong(1, userId);
            statement.setString(2, text);
            try (var result = statement.executeQuery()) {
                return new Note(result.getLong(1), text);
            }
        }
    }

    record User(long id, String passwordHash) { }
    record Note(long id, String text) { }
}
