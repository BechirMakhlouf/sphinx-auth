import { type IHasher } from "./crypto";

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
