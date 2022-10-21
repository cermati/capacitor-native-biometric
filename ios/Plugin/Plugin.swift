import Foundation
import Capacitor
import LocalAuthentication

/**
 * Please read the Capacitor iOS Plugin Development Guide
 * here: https://capacitor.ionicframework.com/docs/plugins/ios
 */

@objc(NativeBiometric)
public class NativeBiometric: CAPPlugin {
    
    struct Credentials {
        var username: String
        var password: String
    }
    
    enum KeychainError: Error{
        case noPassword
        case unexpectedPasswordData
        case duplicateItem
        case unhandledError(status: OSStatus)
    }
    
    let BIOMETRIC_KEY = "CermatiBiometricKey"
    
    typealias JSObject = [String:Any]
    
    @objc func isAvailable(_ call: CAPPluginCall) {
        let context = LAContext()
        var error: NSError?
        var obj = JSObject()
        
        obj["isAvailable"] = false
        obj["biometryType"] = 0
        
        if LAContext.biometricsChanged() {
            obj["isBiometryChanged"] = true
            
            // Reset LAContext.savedBiometricsPolicyState to nil after doing so
            LAContext.savedBiometricsPolicyState = nil
        }else {
            // Handle biometrics changed
            obj["isBiometryChanged"] = false
        }
        
        let useFallback = call.getBool("useFallback", false)
        let policy = useFallback ? LAPolicy.deviceOwnerAuthentication : LAPolicy.deviceOwnerAuthenticationWithBiometrics
        
        if context.canEvaluatePolicy(policy, error: &error){
            switch context.biometryType {
            case .touchID:
                obj["biometryType"] = 1
            case .faceID:
                obj["biometryType"] = 2
            default:
                obj["biomertryType"] = 0
            }
            
            obj["isAvailable"] = true
            call.resolve(obj)
        } else {
            guard let authError = error else {
                obj["errorCode"] = 0
                call.resolve(obj)
                return
            }
            var errorCode = 0
            switch authError.code {
            case LAError.biometryNotAvailable.rawValue:
                errorCode = 1
                
            case LAError.biometryLockout.rawValue:
                errorCode = 2 //"Authentication could not continue because the user has been locked out of biometric authentication, due to failing authentication too many times."
                
            case LAError.biometryNotEnrolled.rawValue:
                errorCode = 3//message = "Authentication could not start because the user has not enrolled in biometric authentication."
                
            default:
                errorCode = 0 //"Did not find error code on LAError object"
            }
            obj["errorCode"] = errorCode
            call.resolve(obj)
        }
    }
    
    @objc func verifyIdentity(_ call: CAPPluginCall){
        let context = LAContext()
        var canEvaluateError: NSError?
        var obj = JSObject()
        
        let useFallback = call.getBool("useFallback", false)
        
        context.localizedFallbackTitle = ""
        context.localizedCancelTitle = call.getString("negativeButtonText") ?? "Gunakan Pin"
        
        let policy = useFallback ? LAPolicy.deviceOwnerAuthentication : LAPolicy.deviceOwnerAuthenticationWithBiometrics
        
        if context.canEvaluatePolicy(policy, error: &canEvaluateError){
            
            let reason = call.getString("reason") ?? "For biometric authentication"
            
            context.evaluatePolicy(policy, localizedReason: reason) { [self] (success, evaluateError) in
                
                if success {
                    obj["isVerified"] = true
                    call.resolve(obj)
                }else{
                    guard let error = evaluateError
                    else {
                        call.reject("Biometrics Error", "0")
                        return
                    }
                    
                    let errorCode = self.errorBiometricVerificationMapper(error._code)
                
                    call.reject(error.localizedDescription, errorCode, error )
                }
                
            }
            
        }else{
            call.reject("Authentication not available")
        }
    }
    
    func errorBiometricVerificationMapper(_ error: Int) -> String {
        var errorCode = "0"
        
        switch error {
            
        case LAError.authenticationFailed.rawValue:
            errorCode = "10"
            
        case LAError.appCancel.rawValue:
            errorCode = "11"
            
        case LAError.invalidContext.rawValue:
            errorCode = "12"
            
        case LAError.notInteractive.rawValue:
            errorCode = "13"
            
        case LAError.passcodeNotSet.rawValue:
            errorCode = "14"
            
        case LAError.systemCancel.rawValue:
            errorCode = "15"
            
        case LAError.userCancel.rawValue:
            errorCode = "16"
            
        case LAError.userFallback.rawValue:
            errorCode = "17"
            
        case LAError.biometryNotAvailable.rawValue:
            errorCode = "1"
            
        case LAError.biometryLockout.rawValue:
            errorCode = "2" //"Authentication could not continue because the user has been locked out of biometric authentication, due to failing authentication too many times."
            
        case LAError.biometryNotEnrolled.rawValue:
            errorCode = "3" //message = "Authentication could not start because the user has not enrolled in biometric authentication."
            
        default:
            errorCode = "0" // Biometrics unavailable
        }
        
        return errorCode
    }
    
    @objc func getCredentials(_ call: CAPPluginCall){
        guard let server = call.getString("server") else{
            call.reject("No server name was provided")
            return
        }
        do{
            let credentials = try getCredentialsFromKeychain(server)
            var obj = JSObject()
            obj["username"] = credentials.username
            obj["password"] = credentials.password
            call.resolve(obj)
        } catch {
            call.reject(error.localizedDescription)
        }
    }
    
    @objc func setCredentials(_ call: CAPPluginCall){
        
        guard let server = call.getString("server"), let username = call.getString("username"), let password = call.getString("password") else {
            call.reject("Missing properties")
            return;
        }
        
        let credentials = Credentials(username: username, password: password)
        
        do{
            try storeCredentialsInKeychain(credentials, server)
            call.resolve()
        } catch KeychainError.duplicateItem {
            do {
                try updateCredentialsInKeychain(credentials, server)
                call.resolve()
            }catch{
                call.reject(error.localizedDescription)
            }
        } catch {
            call.reject(error.localizedDescription)
        }
    }
    
    @objc func deleteCredentials(_ call: CAPPluginCall){
        guard let server = call.getString("server") else {
            call.reject("No server name was provided")
            return
        }
        
        do {
            try deleteCredentialsFromKeychain(server)
            call.resolve()
        }catch {
            call.reject(error.localizedDescription)
        }
    }
    
    @objc func getPublicKey(_ call: CAPPluginCall){
        var obj = JSObject()
        
        let isBiometricKeyExist = doesBiometricKeyExist()
        if(isBiometricKeyExist){
            do{
                try deleteBiometricKey()
                
                obj["keysDeleted"] = true;
            }catch{
                call.reject("Error deleting biometric key from keystore");
            }
        }
        
        do{
            let generatedPublicKey = try generatePublicKey()
            
            var error:Unmanaged<CFError>?
            if let cfdata = SecKeyCopyExternalRepresentation(generatedPublicKey, &error) {
                let data:Data = cfdata as Data
                let b64Key = data.base64EncodedString(options: .lineLength64Characters)
                
                obj["publicKey"] = convertToPemPublicKey(b64Key)
                call.resolve(obj)
            }
        }catch{
            call.reject("Cannot generate public key")
        }
    }
    
    func convertToPemPublicKey(_ b64Key: String) -> String {
        let head = "-----BEGIN RSA PUBLIC KEY-----";
        let body = b64Key
        let tail = "-----END RSA PUBLIC KEY-----";
        
        let pemPublicKey = """
            \(head)
            \(body)
            \(tail)
            """;
        
        return pemPublicKey.toBase64();
    }
    
    @objc func signData(_ call: CAPPluginCall){
        let context = LAContext()
        var canEvaluateError: NSError?
        var obj = JSObject()
        
        let useFallback = call.getBool("useFallback", false)
        
        context.localizedFallbackTitle = ""
        context.localizedCancelTitle = "Gunakan Pin"
        
        let policy = useFallback ? LAPolicy.deviceOwnerAuthentication : LAPolicy.deviceOwnerAuthenticationWithBiometrics
        
        if context.canEvaluatePolicy(policy, error: &canEvaluateError){
            
            let reason = call.getString("reason") ?? "For biometric authentication"
            
            context.evaluatePolicy(policy, localizedReason: reason) { [self] (success, evaluateError) in
                
                if success {
                    let query: [String: Any] = [
                        kSecClass as String: kSecClassKey,
                        kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                        kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                        kSecAttrKeySizeInBits as String: 2048,
                        kSecAttrApplicationTag as String: BIOMETRIC_KEY,
                        kSecReturnRef as String: true
                    ]
                    
                    var item: CFTypeRef?
                    let status = SecItemCopyMatching(query as CFDictionary, &item)
                    guard status == errSecSuccess else { return }
                    let privateKey = item as! SecKey
                    
                    guard let challengeString = call.getString("challengeString") else {
                        call.reject("No challenge string was provided")
                        return
                    }
                    
                    guard let messageData = challengeString.data(using: String.Encoding.utf8) else {
                        call.reject("Invalid message to sign")
                        return
                    }
                    
                    do{
                        guard let signData = SecKeyCreateSignature(
                            privateKey,
                            SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA256,
                            messageData as CFData, nil) else {
                            call.reject("Cannot sign data")
                            return
                        }
                        
                        let signedData = signData as Data
                        let signedString = signedData.base64EncodedString(options: [])
                        obj["signedData"] = signedString
                        call.resolve(obj)
                    }
                }else{
                    guard let error = evaluateError
                    else {
                        call.reject("Biometrics Error", "0")
                        return
                    }
                    
                    let errorCode = self.errorBiometricVerificationMapper(error._code)
                
                    call.reject(error.localizedDescription, errorCode, error )
                }
                
            }
        }else{
            call.reject("Authentication not available")
        }
    }
    
    @objc func biometricKeysExist(_ call: CAPPluginCall){
        var obj = JSObject()
        let isBiometricKeyExist = doesBiometricKeyExist()
        
        obj["keyExist"] = isBiometricKeyExist
        
        call.resolve(obj)
    }
    
    @objc func deleteKeyPair(_ call: CAPPluginCall) {
        var obj = JSObject()
        let isBiometricKeyExist = doesBiometricKeyExist()
        
        if(isBiometricKeyExist){
            do{
                try deleteBiometricKey()
                
                obj["keysDeleted"] = true;
            }catch{
                call.reject("Error deleting biometric key from keystore");
            }
        }else{
            obj["keysDeleted"] = false;
        }
        
        call.resolve()
    }
    
    func generatePublicKey() throws -> SecKey {
        let attributes: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked,
                kSecAttrApplicationTag as String: BIOMETRIC_KEY,
            ]
        ]
        
        var error: Unmanaged<CFError>?
        guard let privateKey =
                SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            // throw error
            throw error!.takeRetainedValue() as Error
        }
        
        let publicKey = SecKeyCopyPublicKey(privateKey)!
        
        return publicKey
    }
    
    func deleteBiometricKey() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String : BIOMETRIC_KEY,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw KeychainError.unhandledError(status: status) }
    }
    
    func doesBiometricKeyExist() -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: BIOMETRIC_KEY,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }
    
    
    // Store user Credentials in Keychain
    func storeCredentialsInKeychain(_ credentials: Credentials, _ server: String) throws {
        let query: [String: Any] = [kSecClass as String: kSecClassInternetPassword,
                                    kSecAttrAccount as String: credentials.username,
                                    kSecAttrServer as String: server,
                                    kSecValueData as String: credentials.password.data(using: .utf8)!]
        
        let status = SecItemAdd(query as CFDictionary, nil)
        
        guard status != errSecDuplicateItem else { throw KeychainError.duplicateItem }
        guard status == errSecSuccess else { throw KeychainError.unhandledError(status: status) }
    }
    
    // Update user Credentials in Keychain
    func updateCredentialsInKeychain(_ credentials: Credentials, _ server: String) throws{
        let query: [String: Any] = [kSecClass as String: kSecClassInternetPassword,
                                    kSecAttrServer as String: server]
        
        let account = credentials.username
        let password = credentials.password.data(using: String.Encoding.utf8)!
        let attributes: [String: Any] = [kSecAttrAccount as String: account,
                                         kSecValueData as String: password]
        
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        guard status != errSecItemNotFound else { throw KeychainError.noPassword }
        guard status == errSecSuccess else { throw KeychainError.unhandledError(status: status) }
    }
    
    // Get user Credentials from Keychain
    func getCredentialsFromKeychain(_ server: String) throws -> Credentials {
        let query: [String: Any] = [kSecClass as String: kSecClassInternetPassword,
                                    kSecAttrServer as String: server,
                                    kSecMatchLimit as String: kSecMatchLimitOne,
                                    kSecReturnAttributes as String: true,
                                    kSecReturnData as String: true]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status != errSecItemNotFound else { throw KeychainError.noPassword }
        guard status == errSecSuccess else { throw KeychainError.unhandledError(status: status) }
        
        
        
        guard let existingItem = item as? [String: Any],
              let passwordData = existingItem[kSecValueData as String] as? Data,
              let password = String(data: passwordData, encoding: .utf8),
              let username = existingItem[kSecAttrAccount as String] as? String
        else {
            throw KeychainError.unexpectedPasswordData
        }
        
        let credentials = Credentials(username: username, password: password)
        return credentials
    }
    
    // Delete user Credentials from Keychain
    func deleteCredentialsFromKeychain(_ server: String)throws{
        let query: [String: Any] = [kSecClass as String: kSecClassInternetPassword,
                                    kSecAttrServer as String: server]
        
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw KeychainError.unhandledError(status: status) }
    }
}

extension LAContext {
    static var savedBiometricsPolicyState: Data? {
        get {
            UserDefaults.standard.data(forKey: "BiometricsPolicyState")
        }
        set {
            UserDefaults.standard.set(newValue, forKey: "BiometricsPolicyState")
        }
    }
    
    static func biometricsChanged() -> Bool {
        let context = LAContext()
        var error: NSError?
        context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        
        // If there is no saved policy state yet, save it
        if error == nil && LAContext.savedBiometricsPolicyState == nil {
            LAContext.savedBiometricsPolicyState = context.evaluatedPolicyDomainState
            return false
        }
        
        if let domainState = context.evaluatedPolicyDomainState, domainState != LAContext.savedBiometricsPolicyState {
            return true
        }
        
        return false
    }
}

extension String {
    
    func fromBase64() -> String? {
        guard let data = Data(base64Encoded: self) else {
            return nil
        }
        
        return String(data: data, encoding: .utf8)
    }
    
    func toBase64() -> String {
        return Data(self.utf8).base64EncodedString()
    }
    
}
