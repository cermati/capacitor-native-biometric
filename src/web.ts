import { WebPlugin } from "@capacitor/core";
import {
  NativeBiometricPlugin,
  AvailableResult,
  BiometricOptions,
  GetCredentialOptions,
  SetCredentialOptions,
  DeleteCredentialOptions,
  Credentials,
  SignDataOptions,
  PublicKey,
  SignedData
} from "./definitions";

export class NativeBiometricWeb
  extends WebPlugin
  implements NativeBiometricPlugin
{
  constructor() {
    super();
  }
  isAvailable(): Promise<AvailableResult> {
    throw new Error("Method not implemented.");
  }

  verifyIdentity(_options?: BiometricOptions): Promise<any> {
    throw new Error("Method not implemented.");
  }
  getCredentials(_options: GetCredentialOptions): Promise<Credentials> {
    throw new Error("Method not implemented.");
  }
  setCredentials(_options: SetCredentialOptions): Promise<any> {
    throw new Error("Method not implemented.");
  }
  deleteCredentials(_options: DeleteCredentialOptions): Promise<any> {
    throw new Error("Method not implemented.");
  }
  getPublicKey(): Promise<PublicKey> {
    throw new Error("Method not implemented.");
  }
  signData(_options: SignDataOptions): Promise<SignedData> {
    throw new Error("Method not implemented.");
  }
}
