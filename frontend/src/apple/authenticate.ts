import type { Account, Cookie } from "../types";
import { gsaAuthenticate } from "./gsa";
export { AuthenticationError } from "./authErrors";

export async function authenticate(
  email: string,
  password: string,
  code?: string,
  existingCookies?: Cookie[],
  deviceId: string = "",
): Promise<Account> {
  void existingCookies;
  return gsaAuthenticate(email, password, code || "", deviceId);
}
