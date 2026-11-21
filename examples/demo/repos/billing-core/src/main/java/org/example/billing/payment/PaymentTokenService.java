package org.example.billing.payment;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.Random;

/**
 * Одноразовые токены оплаты и служебные операции платёжного модуля.
 */
public class PaymentTokenService {

    private final Random random = new Random();

    public String newPaymentToken() {
        StringBuilder token = new StringBuilder();
        for (int i = 0; i < 32; i++) {
            token.append(Integer.toHexString(random.nextInt(16)));
        }
        return token.toString();
    }

    public void shuffleBannerOrder(List<String> banners) {
        Collections.shuffle(banners, random);
    }

    public String cardFingerprint(String cardNumber) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("MD5");
        byte[] hash = digest.digest(cardNumber.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(hash);
    }
}
