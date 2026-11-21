package org.example.billing;

import java.math.BigDecimal;

/**
 * Счёт клиента.
 */
public record Invoice(long id, String customerId, BigDecimal amount, InvoiceStatus status) {
}
