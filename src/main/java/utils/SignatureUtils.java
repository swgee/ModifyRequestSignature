package utils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class SignatureUtils {

    public static ArrayList calculateNewSignature(ArrayList<String> algorithm, String hashField, String secret, String newRequestBody, String oldSignature) throws Exception {
        // Initialize newHash, set it equal to newRequestBody
        ArrayList output = new ArrayList();
        byte[] newHashBytes = newRequestBody.getBytes(StandardCharsets.UTF_8);

        // Process each algorithm step
        if (!algorithm.isEmpty()) {
            for (String algo : algorithm) {
                try {
                    if (algo.equalsIgnoreCase("Base64")) {
                        // Set newHash equal to Base64 value of itself
                        newHashBytes = Base64.getEncoder().encodeToString(newHashBytes).getBytes();
                    } else if (algo.equalsIgnoreCase("Base64URL")) {
                        // Set newHash equal to Base64 URL value of itself
                        newHashBytes = Base64.getUrlEncoder().encodeToString(newHashBytes).getBytes();
                    } else if (algo.equalsIgnoreCase("SHA256")) {
                        // Set newHash equal to SHA-256 hash of itself
                        MessageDigest digest = MessageDigest.getInstance("SHA-256");
                        newHashBytes = digest.digest(newHashBytes);
                    }
                } catch (Exception e) {
                    throw new Exception("Failed to process algorithm: " + algo, e);
                }
            }
        }

        String newHash = new String(newHashBytes);

        // Validate the oldSignature as a JWT
        if (!oldSignature.contains(".")) {
            throw new IllegalArgumentException(oldSignature + " is not a valid JWT");
        }

        // Split the JWT into parts (header, payload, signature)
        String[] jwtParts = oldSignature.split("\\.");
        if (jwtParts.length != 3) {
            throw new IllegalArgumentException(oldSignature + " is not a valid JWT");
        }

        // Decode the payload (claims) and find the hashField
        String payloadJson = new String(Base64.getDecoder().decode(jwtParts[1]), StandardCharsets.UTF_8);

        if (!payloadJson.contains("\"" + hashField + "\"")) {
            throw new IllegalArgumentException("Specified hash field not found in oldSignature claims");
        }

        // Replace the value of the hashField with the newHash in the payload
        payloadJson = payloadJson.replaceAll("\"" + hashField + "\":\"[^\"]+\"", "\"" + hashField + "\":\"" + newHash + "\"");

        // Re-encode the modified payload as base64 URL
        String newPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));

        // Reconstruct the new JWT without the signature
        String newJwtWithoutSignature = jwtParts[0] + "." + newPayload;

        // Recalculate HS256 signature of newJwtWithoutSignature using secret
        try {
            Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            sha256_HMAC.init(secretKey);
            byte[] signatureBytes = sha256_HMAC.doFinal(newJwtWithoutSignature.getBytes(StandardCharsets.UTF_8));
            String newSignature = Base64.getUrlEncoder().withoutPadding().encodeToString(signatureBytes);

            // Return the new complete JWT
            output.add(newJwtWithoutSignature + "." + newSignature);
            output.add(newHash);
            return output;

        } catch (Exception e) {
            throw new Exception("Failed to calculate new signature", e);
        }
    }
}
