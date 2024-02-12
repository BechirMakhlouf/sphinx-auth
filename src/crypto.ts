// import { scrypt } from "hash-wasm";

import { bcrypt, bcryptVerify } from "hash-wasm";
import { type IDataType } from "hash-wasm/dist/lib/util";
import * as crypto from "node:crypto";

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
  readonly DEFAULT_COST_FACTOR = 10
  private readonly costFactor: number = this.DEFAULT_COST_FACTOR;

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

