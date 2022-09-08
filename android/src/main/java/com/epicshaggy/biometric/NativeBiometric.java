package com.epicshaggy.biometric;

import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.security.keystore.UserNotAuthenticatedException;
import android.util.Base64;

import androidx.activity.result.ActivityResult;
import androidx.biometric.BiometricManager;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.ActivityCallback;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.GregorianCalendar;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;


@CapacitorPlugin(name = "NativeBiometric")
public class NativeBiometric extends Plugin {

    private BiometricManager biometricManager;
    //protected final static int AUTH_CODE = 0102;

    private static final int NONE = 0;
    private static final int FINGERPRINT = 3;
    private static final int FACE_AUTHENTICATION = 4;
    private static final int IRIS_AUTHENTICATION = 5;
    private static final int MULTIPLE = 6;


    private KeyStore keyStore;
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String DEFAULT_KEY = "DefaultKey";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String RSA_MODE = "RSA/ECB/PKCS1Padding";
    private static final String AES_MODE = "AES/ECB/PKCS7Padding";
    private static final byte[] FIXED_IV = new byte[12];
    private static final String ENCRYPTED_KEY = "NativeBiometricKey";
    private static final String NATIVE_BIOMETRIC_SHARED_PREFERENCES = "NativeBiometricSharedPreferences";

    private SharedPreferences encryptedSharedPreferences;

    private int getAvailableFeature() {
        // default to none
        int type = NONE;

        // if has fingerprint
        if (getContext().getPackageManager().hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)) {
            type = FINGERPRINT;
        }

        // if has face auth
        if (getContext().getPackageManager().hasSystemFeature(PackageManager.FEATURE_FACE)
        ) {
            // if also has fingerprint
            if (type != NONE)
                return MULTIPLE;

            type = FACE_AUTHENTICATION;
        }

        // if has iris auth
        if (getContext().getPackageManager().hasSystemFeature(PackageManager.FEATURE_IRIS)) {
            // if also has fingerprint or face auth
            if (type != NONE)
                return MULTIPLE;

            type = IRIS_AUTHENTICATION;
        }

        return type;
    }

    @PluginMethod()
    public void isAvailable(PluginCall call) {
        JSObject ret = new JSObject();

        biometricManager = BiometricManager.from(getContext());
        int canAuthenticateResult = biometricManager.canAuthenticate();

        switch (canAuthenticateResult) {
            case BiometricManager.BIOMETRIC_SUCCESS:
                ret.put("isAvailable", true);
                break;
            default:
                ret.put("isAvailable", false);
                ret.put("errorCode", canAuthenticateResult);
                break;
        }

        ret.put("biometryType", getAvailableFeature());
        call.resolve(ret);
    }

    @PluginMethod()
    public void verifyIdentity(final PluginCall call) {
        Intent intent = new Intent(getContext(), AuthActivity.class);

        intent.putExtra("title", call.getString("title", "Authenticate"));

        if (call.hasOption("subtitle"))
            intent.putExtra("subtitle", call.getString("subtitle"));

        if (call.hasOption("description"))
            intent.putExtra("description", call.getString("description"));

        if (call.hasOption("negativeButtonText"))
            intent.putExtra("negativeButtonText", call.getString("negativeButtonText"));

        if (call.hasOption("maxAttempts"))
            intent.putExtra("maxAttempts", call.getInt("maxAttempts"));

        boolean useFallback = call.getBoolean("useFallback", false);

        if (useFallback && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            KeyguardManager keyguardManager = (KeyguardManager) getActivity().getSystemService(Context.KEYGUARD_SERVICE);
            useFallback = keyguardManager.isDeviceSecure();
        }

        intent.putExtra("useFallback", useFallback);

        bridge.saveCall(call);
        startActivityForResult(call, intent, "verifyResult");
    }

    @PluginMethod()
    public void setCredentials(final PluginCall call) {
        String username = call.getString("username", null);
        String password = call.getString("password", null);
        String KEY_ALIAS = call.getString("server", null);

        if (username != null && password != null && KEY_ALIAS != null) {
            try {
                SharedPreferences.Editor editor = getContext().getSharedPreferences(NATIVE_BIOMETRIC_SHARED_PREFERENCES, Context.MODE_PRIVATE).edit();
                editor.putString("username", encryptString(username, KEY_ALIAS));
                editor.putString("password", encryptString(password, KEY_ALIAS));
                editor.apply();
                call.resolve();
            } catch (GeneralSecurityException e) {
                call.reject("Failed to save credentials", e);
                e.printStackTrace();
            } catch (IOException e) {
                call.reject("Failed to save credentials", e);
                e.printStackTrace();
            }
        } else {
            call.reject("Missing properties");
        }
    }

    @PluginMethod()
    public void getCredentials(final PluginCall call) {
        String KEY_ALIAS = call.getString("server", null);

        SharedPreferences sharedPreferences = getContext().getSharedPreferences(NATIVE_BIOMETRIC_SHARED_PREFERENCES, Context.MODE_PRIVATE);
        String username = sharedPreferences.getString("username", null);
        String password = sharedPreferences.getString("password", null);
        if (KEY_ALIAS != null) {
            if (username != null && password != null) {
                try {
                    JSObject jsObject = new JSObject();
                    jsObject.put("username", decryptString(username, KEY_ALIAS));
                    jsObject.put("password", decryptString(password, KEY_ALIAS));
                    call.resolve(jsObject);
                } catch (GeneralSecurityException e) {
                    call.reject("Failed to get credentials", e);
                } catch (IOException e) {
                    call.reject("Failed to get credentials", e);
                }
            } else {
                call.reject("No credentials found");
            }
        } else {
            call.reject("No server name was provided");
        }
    }

    @ActivityCallback
    private void verifyResult(PluginCall call, ActivityResult result) {
        if (result.getResultCode() == Activity.RESULT_OK) {
            Intent data = result.getData();
            if (data.hasExtra("result")) {
                switch (data.getStringExtra("result")) {
                    case "success":
                        call.resolve();
                        break;
                    case "failed":
                        call.reject(data.getStringExtra("errorDetails"), data.getStringExtra("errorCode"));
                        break;
                    default:
                        call.reject("Verification error: " + data.getStringExtra("result"));
                        break;
                }
            }
        } else {
            call.reject("Something went wrong.");
        }
    }

    @PluginMethod
    private void signData(PluginCall call) throws CertificateException, KeyStoreException, NoSuchAlgorithmException, IOException {
        String signatureResult = null;
        JSObject ret = new JSObject();

        //Get the Keystore instance
        KeyStore keyStore = getKeyStore();

        try {
            //Retrieves the private key from the keystore
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(DEFAULT_KEY, null);
            Charset charset = Charset.forName("UTF-8");
            byte[] challangeData = call.getString("challengeString").getBytes(charset);

            //Sign the data with the private key using RSA algorithm along SHA-256 digest algorithm
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(challangeData);
            byte[] signatureBytes = signature.sign();

            signatureResult = new String(signatureBytes);
            ret.put("signedData", signatureResult);
            call.resolve(ret);
        } catch (UserNotAuthenticatedException e) {
            //Exception thrown when the user has not been authenticated
            call.reject("User has not been authenticated");
        } catch (KeyPermanentlyInvalidatedException e) {
            //Exception thrown when the key has been invalidated for example when lock screen has been disabled.
            call.reject("Process interrupted");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @PluginMethod()
    public void deleteCredentials(final PluginCall call) {
        String KEY_ALIAS = call.getString("server", DEFAULT_KEY);

        if (KEY_ALIAS != null) {
            try {
                getKeyStore().deleteEntry(KEY_ALIAS);
                SharedPreferences.Editor editor = getContext().getSharedPreferences(NATIVE_BIOMETRIC_SHARED_PREFERENCES, Context.MODE_PRIVATE).edit();
                editor.clear();
                editor.apply();
                call.resolve();
            } catch (KeyStoreException e) {
                call.reject("Failed to delete", e);
            } catch (CertificateException e) {
                call.reject("Failed to delete", e);
            } catch (NoSuchAlgorithmException e) {
                call.reject("Failed to delete", e);
            } catch (IOException e) {
                call.reject("Failed to delete", e);
            }
        } else {
            call.reject("No server name was provided");
        }
    }

    @PluginMethod()
    public void getPublicKey(final PluginCall call) throws GeneralSecurityException, IOException {
        JSObject ret = new JSObject();
        KeyPair keyPair = getKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        ret.put("publicKey", new String(Base64.encode(publicKey.getEncoded(), Base64.DEFAULT)));
        call.resolve(ret);
    }

    private String encryptString(String stringToEncrypt, String KEY_ALIAS) throws GeneralSecurityException, IOException {
        Cipher cipher;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, getKey(KEY_ALIAS), new GCMParameterSpec(128, FIXED_IV));
        } else {
            cipher = Cipher.getInstance(AES_MODE, "BC");
            cipher.init(Cipher.ENCRYPT_MODE, getKey(KEY_ALIAS));
        }
        byte[] encodedBytes = cipher.doFinal(stringToEncrypt.getBytes("UTF-8"));
        return Base64.encodeToString(encodedBytes, Base64.DEFAULT);
    }

    private String decryptString(String stringToDecrypt, String KEY_ALIAS) throws GeneralSecurityException, IOException {
        byte[] encryptedData = Base64.decode(stringToDecrypt, Base64.DEFAULT);

        Cipher cipher;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, getKey(KEY_ALIAS), new GCMParameterSpec(128, FIXED_IV));
        } else {
            cipher = Cipher.getInstance(AES_MODE, "BC");
            cipher.init(Cipher.DECRYPT_MODE, getKey(KEY_ALIAS));
        }
        byte[] decryptedData = cipher.doFinal(encryptedData);
        return new String(decryptedData, "UTF-8");
    }


    private KeyPair generateKeyPair() throws GeneralSecurityException {
        //Create the start date for this key to be eligible
        GregorianCalendar startDate = new GregorianCalendar();

        //Create RSA key pair and store it in Android Keystore
        KeyPairGenerator generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEY_STORE);

        //Creating the key pair with sign and verify purposes
        generator.initialize(new KeyGenParameterSpec.Builder(DEFAULT_KEY,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY).
                setCertificateSerialNumber(BigInteger.valueOf(777)).                        //Serial number used for the self-signed certificate of the generated key pair, default is 1
                        setCertificateSubject(new X500Principal("CN=DefaultKey")).    //Subject used for the self-signed certificate of the generated key pair, default is CN=fake
                        setDigests(KeyProperties.DIGEST_SHA256).                            //Set of digests algorithms with which the key can be used
                        setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1).    //Set of padding schemes with which the key can be used when signing/verifying
                        setCertificateNotBefore(startDate.getTime()).                       //Start of the validity period for the self-signed certificate of the generated, default Jan 1 1970
                        setUserAuthenticationRequired(true).                                //Sets whether this key is authorized to be used only if the user has been authenticated, default false
                        setUserAuthenticationValidityDurationSeconds(30).                   //Duration(seconds) for which this key is authorized to be used after the user is successfully authenticated
                        build());

        return generator.genKeyPair();
    }

    private KeyPair getKeyPair() throws GeneralSecurityException, IOException {
        KeyPair keyPair = null;
        KeyStore keystore = getKeyStore();

        Key key = keystore.getKey(DEFAULT_KEY, null);

        if (key != null && key instanceof PrivateKey) {
            // Get certificate of public key
            Certificate cert = keystore.getCertificate(DEFAULT_KEY);

            // Get public key
            PublicKey publicKey = cert.getPublicKey();

            // Return a key pair
            keyPair = new KeyPair(publicKey, (PrivateKey) key);
        } else if (key == null) {
            keyPair = generateKeyPair();
        }

        return keyPair;
    }

    private Key generateKey(String KEY_ALIAS) throws GeneralSecurityException, IOException {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);
            generator.init(new KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setRandomizedEncryptionRequired(false)
                    .build()
            );
            return generator.generateKey();
        } else {
            return getAESKey(KEY_ALIAS);
        }
    }

    private Key getKey(String KEY_ALIAS) throws GeneralSecurityException, IOException {
        KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) getKeyStore().getEntry(KEY_ALIAS, null);
        if (secretKeyEntry != null) {
            return secretKeyEntry.getSecretKey();
        }
        return generateKey(KEY_ALIAS);
    }

    private KeyStore getKeyStore() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        if (keyStore != null) {
            return keyStore;
        } else {
            keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);
            return keyStore;
        }
    }

    private Key getAESKey(String KEY_ALIAS) throws CertificateException, NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, UnrecoverableEntryException, IOException, InvalidAlgorithmParameterException {
        SharedPreferences sharedPreferences = getContext().getSharedPreferences("", Context.MODE_PRIVATE);
        String encryptedKeyB64 = sharedPreferences.getString(ENCRYPTED_KEY, null);
        if (encryptedKeyB64 == null) {
            byte[] key = new byte[16];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(key);
            byte[] encryptedKey = rsaEncrypt(key, KEY_ALIAS);
            encryptedKeyB64 = Base64.encodeToString(encryptedKey, Base64.DEFAULT);
            SharedPreferences.Editor edit = sharedPreferences.edit();
            edit.putString(ENCRYPTED_KEY, encryptedKeyB64);
            edit.apply();
            return new SecretKeySpec(key, "AES");
        } else {
            byte[] encryptedKey = Base64.decode(encryptedKeyB64, Base64.DEFAULT);
            byte[] key = rsaDecrypt(encryptedKey, KEY_ALIAS);
            return new SecretKeySpec(key, "AES");
        }
    }

    private KeyStore.PrivateKeyEntry getPrivateKeyEntry(String KEY_ALIAS) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, CertificateException, KeyStoreException, IOException, UnrecoverableEntryException {
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) getKeyStore().getEntry(KEY_ALIAS, null);

        if (privateKeyEntry == null) {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEY_STORE);
            keyPairGenerator.initialize(new KeyPairGeneratorSpec.Builder(getContext())
                    .setAlias(KEY_ALIAS)
                    .build());
            keyPairGenerator.generateKeyPair();
        }

        return privateKeyEntry;
    }

    private byte[] rsaEncrypt(byte[] secret, String KEY_ALIAS) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, UnrecoverableEntryException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        KeyStore.PrivateKeyEntry privateKeyEntry = getPrivateKeyEntry(KEY_ALIAS);
        // Encrypt the text
        Cipher inputCipher = Cipher.getInstance(RSA_MODE, "AndroidOpenSSL");
        inputCipher.init(Cipher.ENCRYPT_MODE, privateKeyEntry.getCertificate().getPublicKey());

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, inputCipher);
        cipherOutputStream.write(secret);
        cipherOutputStream.close();

        byte[] vals = outputStream.toByteArray();
        return vals;
    }

    private byte[] rsaDecrypt(byte[] encrypted, String KEY_ALIAS) throws UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IOException, CertificateException, InvalidAlgorithmParameterException {
        KeyStore.PrivateKeyEntry privateKeyEntry = getPrivateKeyEntry(KEY_ALIAS);
        Cipher output = Cipher.getInstance(RSA_MODE, "AndroidOpenSSL");
        output.init(Cipher.DECRYPT_MODE, privateKeyEntry.getPrivateKey());
        CipherInputStream cipherInputStream = new CipherInputStream(
                new ByteArrayInputStream(encrypted), output);
        ArrayList<Byte> values = new ArrayList<>();
        int nextByte;
        while ((nextByte = cipherInputStream.read()) != -1) {
            values.add((byte) nextByte);
        }

        byte[] bytes = new byte[values.size()];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = values.get(i).byteValue();
        }
        return bytes;
    }
}
