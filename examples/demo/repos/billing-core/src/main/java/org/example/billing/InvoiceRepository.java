package org.example.billing;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import javax.sql.DataSource;

/**
 * Доступ к счетам в базе данных.
 */
public class InvoiceRepository {

    private static final String COLUMNS = "id, customer_id, amount, status";

    private final DataSource dataSource;

    public InvoiceRepository(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    public List<Invoice> findByCustomer(String customerId) throws SQLException {
        String sql = "SELECT " + COLUMNS + " FROM invoice WHERE customer_id = '" + customerId + "'";
        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery(sql)) {
            return readAll(rs);
        }
    }

    public List<Invoice> findByStatus(InvoiceStatus status) throws SQLException {
        String sql = "SELECT " + COLUMNS + " FROM invoice WHERE status = '" + status.name() + "' ORDER BY id";
        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(sql)) {
            return readAll(rows);
        }
    }

    private List<Invoice> readAll(ResultSet rs) throws SQLException {
        List<Invoice> result = new ArrayList<>();
        while (rs.next()) {
            result.add(new Invoice(rs.getLong("id"), rs.getString("customer_id"), rs.getBigDecimal("amount"),
                    InvoiceStatus.valueOf(rs.getString("status"))));
        }
        return result;
    }
}
