import { bcrypt, bcryptVerify } from "hash-wasm";
import { type IDataType } from "hash-wasm/dist/lib/util";
import * as crypto from "node:crypto";
// Hash/Verify/

export interface IPasswordHandler {
  hasher: IHasher;

  /**
   * @todo make a type for all the supported algorithms.
   */
  hash: (password: string) => Promise<string>;

  /**
   * verifies if the password matches a given hash
   * @param password - the password to verify
   * @param hashedPassword - the hashed password
   *
   * @returns boolean if the password is correct
   */
  verify: (password: string, hashedPassword: string) => Promise<boolean>;
}

export interface IHasher {
  /**
   * @param hashes str
   */
  hash: (str: IDataType) => Promise<string>;

  /**
   * verifies if the password matches a given hash
   * @param string - the password to verify
   * @param hashedString - the hashed password
   *
   * @returns boolean if the password is correct
   */
  verify: (password: IDataType, hashedPassword: string) => Promise<boolean>;
}

export class BcryptHasher implements IHasher {
  private readonly costFactor: number = 10;

  async hash(str: IDataType): Promise<string> {
    return await bcrypt({
      password: str,
      salt: crypto.randomBytes(16),
      costFactor: this.costFactor,
    });
  }

  async verify(password: IDataType, hashedPassword: string): Promise<boolean> {
    return await bcryptVerify({ password, hash: hashedPassword });
  }

  /**
   * @default costFactor default is 10
   */
  constructor(costFactor?: number) {
    this.costFactor = costFactor ?? this.costFactor;
  }
}

export class PasswordHandler implements IPasswordHandler {
  readonly hasher: IHasher;

  constructor(hashingAlgorithm: IHasher) {
    this.hasher = hashingAlgorithm;
  }

  async hash(password: string): Promise<string> {
    return await this.hasher.hash(password);
  }

  async verify(password: string, hashedPassword: string): Promise<boolean> {
    return await this.hasher.verify(password, hashedPassword);
  }
}
