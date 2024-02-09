export interface PasswordInterface {
  /**
   * @todo make a type for all the supported algorithms.
   */
  hash: (password: string, algorithm: any) => Promise<string>;

  /**
   * verifies if the password matches a given hash
   *
   * @param password - the password to verify
   * @param hashedPassword - the hashed password
   *
   * @returns boolean if the password is correct
   */
  verify: (hashedPassword: string, password: string) => Promise<boolean>;
}

// export const Password: PasswordInterface = {
//   hash: async (password: string) => {
//     return password;
//   },
//
//   verify: async (hashedPassword: string) => {
//     return Boolean(hashedPassword);
//   },
// };
