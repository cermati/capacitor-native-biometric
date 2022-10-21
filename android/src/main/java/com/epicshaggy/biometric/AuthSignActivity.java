package com.epicshaggy.biometric;

import static androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG;
import static androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL;

import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.UserNotAuthenticatedException;
import android.util.Base64;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.biometric.BiometricPrompt;

import com.epicshaggy.biometric.capacitornativebiometric.R;

import java.io.IOException;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.util.concurrent.Executor;

public class AuthSignActivity extends AppCompatActivity {

    private Executor executor;
    private int counter = 0;

    private KeyStore keyStore;
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String DEFAULT_KEY = "DefaultKey";
    private static final int MAX_ATTEMPTS = 5;


    private KeyStore getKeyStore() throws
            KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        if (keyStore == null) {
            keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);
        }
        return keyStore;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_sign_auth_activity);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            executor = this.getMainExecutor();
        } else {
            executor = new Executor() {
                @Override
                public void execute(Runnable command) {
                    new Handler().post(command);
                }
            };
        }

        //Get the Keystore instance
        KeyStore keyStore = null;

        try {
            keyStore = getKeyStore();
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }

        try {
            //Retrieves the private key from the keystore
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(DEFAULT_KEY, null);

            //Sign the data with the private key using RSA algorithm along SHA-256 digest algorithm
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            BiometricPrompt.CryptoObject cryptoObject = new BiometricPrompt.CryptoObject(signature);


            BiometricPrompt.PromptInfo.Builder builder = new BiometricPrompt.PromptInfo.Builder()
                    .setTitle(getIntent().hasExtra("title") ? getIntent().getStringExtra("title") : "Authenticate")
                    .setSubtitle(getIntent().hasExtra("subtitle") ? getIntent().getStringExtra("subtitle") : null)
                    .setDescription(getIntent().hasExtra("description") ? getIntent().getStringExtra("description") : null);

            boolean useFallback = getIntent().getBooleanExtra("useFallback", false);

            if (useFallback) {
                builder.setAllowedAuthenticators(BIOMETRIC_STRONG | DEVICE_CREDENTIAL);
            } else {
                builder.setNegativeButtonText(getIntent().hasExtra("negativeButtonText") ? getIntent().getStringExtra("negativeButtonText") : "Cancel");
            }

            BiometricPrompt.PromptInfo promptInfo = builder.build();

            BiometricPrompt biometricPrompt = new BiometricPrompt(this, executor, new BiometricPrompt.AuthenticationCallback() {
                @Override
                public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
                    super.onAuthenticationError(errorCode, errString);
                    finishActivity("authenticationError", "", errorCode);
                }

                @Override
                public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
                    super.onAuthenticationSucceeded(result);
                    String signedString = null;

                    try {
                        BiometricPrompt.CryptoObject cryptoObject = result.getCryptoObject();
                        Signature cryptoSignature = cryptoObject.getSignature();
                        Charset charset = StandardCharsets.UTF_8;
                        byte[] challengeData = getIntent().getStringExtra("challengeString").getBytes(charset);
                        cryptoSignature.update(challengeData);
                        byte[] signed = cryptoSignature.sign();
                        signedString = Base64.encodeToString(signed, Base64.DEFAULT);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }

                    finishActivity("success", signedString, 0);
                }

                @Override
                public void onAuthenticationFailed() {
                    super.onAuthenticationFailed();
                    counter++;
                    if (counter == MAX_ATTEMPTS)
                        finishActivity("failed", "", 0);
                }
            });

            biometricPrompt.authenticate(promptInfo, cryptoObject);

        } catch (UserNotAuthenticatedException e) {
            e.printStackTrace();
        } catch (KeyPermanentlyInvalidatedException e) {
            e.printStackTrace();
            finishActivity("biometryChanged", "", 666);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    void finishActivity(String result, String payload, int errorCode) {
        Intent intent = new Intent();
        if (errorCode != 0) {
            intent.putExtra("result", result);
            intent.putExtra("errorDetails", result);
            intent.putExtra("errorCode", String.valueOf(errorCode));
        } else {
            intent.putExtra("result", result);
            intent.putExtra("signedData", payload);
        }

        setResult(RESULT_OK, intent);
        finish();
    }

}
