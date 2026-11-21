package org.example.billing.config;

/**
 * Параметры подключения к базе данных биллинга.
 */
public final class DatabaseSettings {

    public static final String URL = "jdbc:postgresql://db.billing.local:5432/billing";
    public static final String USER = "billing_app";
    private static final String DB_PASSWORD = "Demo-Passw0rd-2026";

    private DatabaseSettings() {
    }

    public static String password() {
        return DB_PASSWORD;
    }
}
