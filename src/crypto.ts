// import { scrypt } from "hash-wasm";

import {
  type Argon2VerifyOptions,
  argon2Verify,
  argon2d,
  argon2i,
  argon2id,
  bcrypt,
  bcryptVerify,
} from "hash-wasm";
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
  readonly DEFAULT_COST_FACTOR = 10;
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

export interface Argon2Options {
  /**
   * Salt (usually containing random bytes)
   */
  salt: IDataType;
  /**
   * Number of iterations to perform
   */
  iterations: number;
  /**
   * Degree of parallelism
   */
  parallelism: number;
  /**
   * Amount of memory to be used in kibibytes (1024 bytes)
   */
  memorySize: number;
  /**
   * Output size in bytes
   */
  hashLength: number;
  /**
   * Desired output type. Defaults to 'hex'
   */
  outputType?: "hex" | "binary" | "encoded";
}

export class Argon2Hasher implements IHasher {
  public hashingConfiguration: Argon2Options = {
    salt: crypto.randomBytes(32), // A random salt as a string or buffer
    iterations: 3, // Number of iterations
    parallelism: 2, // Degree of parallelism
    memorySize: 4096, // Memory usage in kibibytes (4MB)
    hashLength: 32, // Output size in bytes (256 bits)
    outputType: "encoded", // Desired output type
  };

  private readonly hasher: typeof argon2id;
  private readonly argon2 = {
    argon2d,
    argon2i,
    argon2id,
  };

  async hash(
    str: IDataType,
    secret?: IDataType,
    customConfig?: Argon2Options,
  ): Promise<string> {
    return await this.hasher({
      ...(customConfig ?? this.hashingConfiguration),
      password: str,
      secret,
    });
  }

  async verify(
    password: IDataType,
    hashedPassword: string,
    secret?: IDataType,
  ): Promise<boolean> {
    return await argon2Verify({ password, secret, hash: hashedPassword });
  }

  constructor(
    argonType: "argon2i" | "argon2d" | "argon2id",
    options?: Argon2Options,
  ) {
    if (options !== undefined) {
      this.hashingConfiguration = options;
    }

    this.hasher = this.argon2[argonType];
  }
}
