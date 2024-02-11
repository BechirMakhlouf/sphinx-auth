import { PasswordHandler, BcryptHasher } from "../src/password";

test("password hashing", async () => {
  const passwordHandler = new PasswordHandler(new BcryptHasher());

  const password: string = "testing password";
  const passwordHash: string = await passwordHandler.hash(password);

  expect(await passwordHandler.verify(password, passwordHash)).toBe(true);
});
