import { PasswordHandler } from "../src/password";
import { Argon2Hasher, BcryptHasher } from "../src/crypto";

test("bcrypt hashing", async () => {
  const passwordHandler = new PasswordHandler(new BcryptHasher());

  const password: string = "testing password";
  const passwordHash: string = await passwordHandler.hash(password);

  expect(await passwordHandler.verify(password, passwordHash)).toBe(true);
});

test("argon2 hashing", async () => {
  const passwordHandler = new PasswordHandler(new Argon2Hasher("argon2id"));
  const password: string = "testing password";
  const passwordHash: string = await passwordHandler.hash(password);
  expect(await passwordHandler.verify(password, passwordHash)).toBe(true);
});
