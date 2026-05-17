import type { Account } from "../types";
import { countryToStoreId, generateDeviceId } from "./config";
import {
  aes256CbcDecryptPkcs7,
  base64Encode,
  bytesToHex,
  concatBytes,
  hmacSha256,
  pbkdf2Sha256,
  sha256,
  utf8,
} from "./crypto";
import { AuthenticationError } from "./authErrors";
import { buildPlist, parsePlist } from "./plist";
import { computePublicEphemeral, processSrpReply } from "./srp";
import { authHeaders } from "../api/client";

const gsaEndpoint = "https://gsa.apple.com/grandslam/GsService2";
const validateEndpoint = "https://gsa.apple.com/grandslam/GsService2/validate";
const trustedDeviceEndpoint =
  "https://gsa.apple.com/auth/verify/trusteddevice";
const authEndpoint = "https://gsa.apple.com/auth";
const verifyPhoneEndpoint = "https://gsa.apple.com/auth/verify/phone/";
const verifyPhoneSecurityCodeEndpoint =
  "https://gsa.apple.com/auth/verify/phone/securitycode";
const gsaUserAgent = "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0";

interface GsaSpd {
  dsid: string;
  idmsToken: string;
  firstName: string;
  lastName: string;
  passwordToken?: string;
  storeFront?: string;
}

interface LoginSession {
  spd: GsaSpd;
  state:
    | "loggedIn"
    | "needsTrustedDevice2FA"
    | "needsSMS2FA"
    | `needsExtra:${string}`;
}

let cachedAnisette: { headers: Record<string, string>; generatedAt: number } | null =
  null;

export async function gsaAuthenticate(
  email: string,
  password: string,
  code: string,
  deviceId: string,
): Promise<Account> {
  let session = await loginEmailPassword(email, password);
  if (session.state === "needsTrustedDevice2FA") {
    if (!code) {
      await send2FAToTrustedDevices(session).catch(() => {});
      throw new AuthenticationError(
        "Authentication requires verification code.",
        { codeRequired: true, kind: "two_factor_required" },
      );
    }
    await verifyTrustedDevice2FA(code, session);
    session = await loginEmailPassword(email, password);
  } else if (session.state === "needsSMS2FA") {
    if (!code) {
      await sendSMS2FAToTrustedPhone(session);
      throw new AuthenticationError(
        "Authentication requires SMS verification code.",
        { codeRequired: true, kind: "two_factor_required" },
      );
    }
    const verifyBody = await trustedPhoneVerifyBody(session);
    await verifySMS2FA(code, verifyBody, session);
    session = await loginEmailPassword(email, password);
  } else if (session.state.startsWith("needsExtra:")) {
    throw new AuthenticationError(
      `additional authentication step required: ${session.state.slice("needsExtra:".length)}`,
      { kind: "gsa_malformed" },
    );
  }

  if (session.state !== "loggedIn") {
    throw new AuthenticationError("unexpected login state", {
      kind: "gsa_malformed",
    });
  }

  const store =
    session.spd.storeFront ??
    countryToStoreId(
      Intl.DateTimeFormat().resolvedOptions().locale.split("-").pop() || "US",
    ) ??
    "143441";

  return {
    email,
    password,
    appleId: email,
    store,
    firstName: session.spd.firstName,
    lastName: session.spd.lastName,
    passwordToken: session.spd.passwordToken ?? "",
    directoryServicesIdentifier: session.spd.dsid,
    cookies: [],
    deviceIdentifier: deviceId || generateDeviceId(),
  };
}

async function loginEmailPassword(
  email: string,
  password: string,
): Promise<LoginSession> {
  const a = crypto.getRandomValues(new Uint8Array(32));
  const aPub = computePublicEphemeral(a);
  const anisette = await fetchAnisetteHeaders();

  const headers: Record<string, string> = {
    "Content-Type": "text/x-xml-plist",
    Accept: "*/*",
    "User-Agent": gsaUserAgent,
  };
  const clientInfo = getHeader(anisette, "X-Mme-Client-Info");
  if (clientInfo) headers["X-MMe-Client-Info"] = clientInfo;

  const cpd = buildCpd(anisette);
  const initResponse = await sendPlistRequest(gsaEndpoint, "POST", headers, {
    Header: { Version: "1.0.1" },
    Request: {
      A2k: aPub,
      cpd,
      o: "init",
      ps: ["s2k", "s2k_fo"],
      u: email,
    },
  });
  checkGsaError(initResponse);

  const salt = getUint8Array(initResponse.s, "missing init salt");
  const bPub = getUint8Array(initResponse.B, "missing server public ephemeral");
  const iterations = Number(initResponse.i || 0);
  const challenge = String(initResponse.c || "");
  const protocolName = String(initResponse.sp || "s2k");

  if (!iterations || !challenge) {
    throw new AuthenticationError("missing init parameters", {
      kind: "gsa_malformed",
    });
  }

  const passwordKey = await derivePasswordKey(
    password,
    salt,
    iterations,
    protocolName,
  );
  const verifier = await processSrpReply(
    a,
    utf8(email),
    passwordKey,
    salt,
    bPub,
  );

  const completeResponse = await sendPlistRequest(gsaEndpoint, "POST", headers, {
    Header: { Version: "1.0.1" },
    Request: {
      M1: verifier.m1,
      cpd,
      c: challenge,
      o: "complete",
      u: email,
    },
  });
  checkGsaError(completeResponse);

  const m2 = getUint8Array(completeResponse.M2, "missing server proof");
  if (!bytesEqual(m2, verifier.expectedM2)) {
    throw new AuthenticationError("server proof mismatch", {
      kind: "gsa_malformed",
    });
  }

  const spdEncrypted = getUint8Array(completeResponse.spd, "missing spd");
  const spd = await decodeSpd(spdEncrypted, verifier.key);

  let state: LoginSession["state"] = "loggedIn";
  const status = isRecord(completeResponse.Status)
    ? completeResponse.Status
    : undefined;
  const authStep = status?.au;
  if (authStep === "trustedDeviceSecondaryAuth") {
    state = "needsTrustedDevice2FA";
  } else if (authStep === "secondaryAuth") {
    state = "needsSMS2FA";
  } else if (typeof authStep === "string" && authStep) {
    state = `needsExtra:${authStep}`;
  }

  return { spd, state };
}

async function derivePasswordKey(
  password: string,
  salt: Uint8Array,
  iterations: number,
  protocolName: string,
): Promise<Uint8Array> {
  const hashed = await sha256(utf8(password));
  const pbkdfPassword =
    protocolName === "s2k_fo" ? utf8(bytesToHex(hashed)) : hashed;
  return pbkdf2Sha256(pbkdfPassword, salt, iterations, 32);
}

async function decodeSpd(
  ciphertext: Uint8Array,
  sessionKey: Uint8Array,
): Promise<GsaSpd> {
  const extraDataKey = await hmacSha256(sessionKey, utf8("extra data key:"));
  const extraDataIv = await hmacSha256(sessionKey, utf8("extra data iv:"));
  const plaintext = await aes256CbcDecryptPkcs7(
    ciphertext,
    extraDataKey,
    extraDataIv.slice(0, 16),
  );
  const spdText = new TextDecoder().decode(plaintext);
  let spdParsed: unknown;
  try {
    spdParsed = parsePlist(spdText);
  } catch (error) {
    const message = error instanceof Error ? error.message : "unknown error";
    throw new AuthenticationError(`Invalid decrypted SPD payload: ${message}`, {
      kind: "gsa_malformed",
    });
  }
  const spd = getRecord(spdParsed, "invalid spd");

  const dsid = String(spd.adsid || "");
  const idmsToken = String(spd.GsIdmsToken || "");
  if (!dsid || !idmsToken) {
    throw new AuthenticationError("missing adsid or GsIdmsToken", {
      kind: "gsa_malformed",
    });
  }

  return {
    dsid,
    idmsToken,
    firstName: typeof spd.fn === "string" ? spd.fn : "",
    lastName: typeof spd.ln === "string" ? spd.ln : "",
    passwordToken: extractPasswordToken(spd),
    storeFront:
      typeof spd.sf === "string"
        ? spd.sf
        : typeof spd.storeFront === "string"
          ? spd.storeFront
          : undefined,
  };
}

function extractPasswordToken(spd: Record<string, unknown>): string | undefined {
  const tokenTree = isRecord(spd.t) ? spd.t : undefined;
  const pet =
    tokenTree && isRecord(tokenTree["com.apple.gs.idms.pet"])
      ? tokenTree["com.apple.gs.idms.pet"]
      : undefined;
  if (pet && typeof pet.token === "string") return pet.token;
  if (typeof spd.token === "string") return spd.token;
  if (typeof spd.passwordToken === "string") return spd.passwordToken;
  return undefined;
}

async function send2FAToTrustedDevices(session: LoginSession): Promise<void> {
  const headers = await build2FAHeaders(session, false);
  await sendRawRequest(trustedDeviceEndpoint, "GET", headers);
}

async function verifyTrustedDevice2FA(
  code: string,
  session: LoginSession,
): Promise<void> {
  const headers = await build2FAHeaders(session, false);
  headers["security-code"] = code;
  const response = await sendRawRequest(validateEndpoint, "GET", headers);
  checkGsaError(parsePlist(response.bodyText) as Record<string, any>);
}

async function sendSMS2FAToTrustedPhone(session: LoginSession): Promise<void> {
  const body = await trustedPhoneVerifyBody(session);
  const headers = await build2FAHeaders(session, true);
  headers.Accept = "application/json";
  await sendRawRequest(
    verifyPhoneEndpoint,
    "POST",
    headers,
    utf8(JSON.stringify(body)),
  );
}

async function trustedPhoneVerifyBody(
  session: LoginSession,
): Promise<Record<string, unknown>> {
  const extras = await getAuthExtras(session);
  const phone = extras.trustedPhoneNumbers?.[0];
  if (!phone || typeof phone.id !== "number") {
    throw new AuthenticationError("no trusted phone numbers", {
      kind: "gsa_malformed",
    });
  }
  return { phoneNumber: { id: phone.id }, mode: "sms" };
}

async function verifySMS2FA(
  code: string,
  verifyBody: Record<string, unknown>,
  session: LoginSession,
): Promise<void> {
  const headers = await build2FAHeaders(session, true);
  headers.Accept = "application/json";
  try {
    await sendRawRequest(
      verifyPhoneSecurityCodeEndpoint,
      "POST",
      headers,
      utf8(JSON.stringify({ ...verifyBody, securityCode: { code } })),
    );
  } catch {
    throw new AuthenticationError("Invalid verification code.", {
      kind: "invalid_two_factor",
    });
  }
}

async function getAuthExtras(
  session: LoginSession,
): Promise<{ trustedPhoneNumbers?: Array<{ id: number }> }> {
  const headers = await build2FAHeaders(session, true);
  headers.Accept = "application/json";
  const response = await sendRawRequest(authEndpoint, "GET", headers, undefined, [
    201,
    423,
  ]);
  return JSON.parse(response.bodyText);
}

async function build2FAHeaders(
  session: LoginSession,
  sms: boolean,
): Promise<Record<string, string>> {
  const anisette = await fetchAnisetteHeaders();
  const headers: Record<string, string> = { ...anisette };
  if (!sms) {
    headers["Content-Type"] = "text/x-xml-plist";
    headers.Accept = "text/x-xml-plist";
  } else {
    headers["Content-Type"] = "application/json";
  }
  headers["User-Agent"] = "Xcode";
  headers["Accept-Language"] = "en-us";
  headers["X-Apple-Identity-Token"] = base64Encode(
    `${session.spd.dsid}:${session.spd.idmsToken}`,
  );
  const locale = getHeader(anisette, "X-Apple-Locale");
  if (locale) headers.Loc = locale;
  headers["X-Apple-App-Info"] = "com.apple.gs.xcode.auth";
  headers["X-Xcode-Version"] = "11.2 (11B41)";
  return headers;
}

function buildCpd(headers: Record<string, string>): Record<string, string> {
  return {
    ...headers,
    bootstrap: "true",
    icscrec: "true",
    loc: "en_GB",
    pbe: "false",
    prkgen: "true",
    svct: "iCloud",
  };
}

async function fetchAnisetteHeaders(): Promise<Record<string, string>> {
  const now = Date.now();
  if (cachedAnisette && now - cachedAnisette.generatedAt < 60_000) {
    return cachedAnisette.headers;
  }

  const response = await fetch("/api/anisette", {
    headers: authHeaders(),
  });
  if (!response.ok) {
    throw new AuthenticationError(`anisette proxy failed with HTTP ${response.status}`, {
      kind: "anisette_unavailable",
    });
  }
  const parsed = (await response.json()) as Record<string, unknown>;
  const headers: Record<string, string> = {};
  for (const [key, value] of Object.entries(parsed)) {
    if (typeof value === "string") headers[key] = value;
  }
  if (Object.keys(headers).length === 0) {
    throw new AuthenticationError("empty anisette response", {
      kind: "anisette_unavailable",
    });
  }
  cachedAnisette = { headers, generatedAt: now };
  return headers;
}

async function sendPlistRequest(
  url: string,
  method: string,
  headers: Record<string, string>,
  body: Record<string, unknown>,
): Promise<Record<string, any>> {
  const response = await sendRawRequest(
    url,
    method,
    headers,
    utf8(buildPlist(body)),
  );
  let parsed: Record<string, any>;
  try {
    parsed = parsePlist(response.bodyText) as Record<string, any>;
  } catch (error) {
    const message = error instanceof Error ? error.message : "unknown error";
    throw new AuthenticationError(
      `Invalid plist response for ${method} ${url}: ${message}`,
      { kind: "gsa_malformed" },
    );
  }
  return getRecord(parsed.Response, "missing Response");
}

async function sendRawRequest(
  url: string,
  method: string,
  headers: Record<string, string>,
  body?: Uint8Array,
  acceptableStatusCodes: number[] = [],
  redirectCount = 0,
  slashRetry = false,
): Promise<{
  status: number;
  statusText: string;
  headers: Record<string, string>;
  bodyText: string;
}> {
  const response = await sendAppleProxyRequest(url, method, headers, body);

  if (response.status >= 300 && response.status < 400) {
    if (redirectCount >= 3) {
      throw new AuthenticationError(`too many redirects for ${method} ${url}`, {
        kind: "gsa_malformed",
      });
    }
    const location = response.headers.location;
    if (!location) {
      throw new AuthenticationError(
        `redirect without Location for ${method} ${url}`,
        { kind: "gsa_malformed" },
      );
    }
    const nextUrl = new URL(location, url).toString();
    return sendRawRequest(
      nextUrl,
      response.status === 303 ? "GET" : method,
      headers,
      response.status === 303 ? undefined : body,
      acceptableStatusCodes,
      redirectCount + 1,
      slashRetry,
    );
  }

  if (
    response.status === 405 &&
    !slashRetry &&
    !new URL(url).pathname.endsWith("/")
  ) {
    const retryUrl = new URL(url);
    retryUrl.pathname += "/";
    return sendRawRequest(
      retryUrl.toString(),
      method,
      headers,
      body,
      acceptableStatusCodes,
      redirectCount,
      true,
    );
  }

  if (
    (response.status < 200 || response.status >= 300) &&
    !acceptableStatusCodes.includes(response.status)
  ) {
    const parts = [`HTTP ${response.status} for ${method} ${url}`];
    if (response.headers.allow) parts.push(`Allow: ${response.headers.allow}`);
    if (response.headers.location)
      parts.push(`Location: ${response.headers.location}`);
    if (response.headers["x-apple-jingle-correlation-key"]) {
      parts.push(
        `correlation: ${response.headers["x-apple-jingle-correlation-key"]}`,
      );
    }
    const snippet = response.bodyText.trim();
    if (snippet) parts.push(`body: ${snippet.slice(0, 200)}`);
    throw new AuthenticationError(parts.join(" | "), {
      kind: "gsa_malformed",
    });
  }

  return response;
}

async function sendAppleProxyRequest(
  url: string,
  method: string,
  headers: Record<string, string>,
  body?: Uint8Array,
): Promise<{
  status: number;
  statusText: string;
  headers: Record<string, string>;
  bodyText: string;
}> {
  const response = await fetch("/api/apple-proxy", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...authHeaders(),
    },
    body: JSON.stringify({
      url,
      method,
      headers,
      bodyBase64: body ? base64Encode(body) : "",
    }),
  });

  if (!response.ok) {
    throw new AuthenticationError(
      `apple proxy failed with HTTP ${response.status}`,
      { kind: "gsa_malformed" },
    );
  }

  return (await response.json()) as {
    status: number;
    statusText: string;
    headers: Record<string, string>;
    bodyText: string;
  };
}

function checkGsaError(response: Record<string, any>): void {
  const status = isRecord(response.Status) ? response.Status : response;
  const ec = Number(status.ec || 0);
  if (ec !== 0) {
    throw new AuthenticationError(
      `GSA authentication failed (ec=${ec}): ${String(status.em || "unknown error")}`,
      { kind: "gsa_error" },
    );
  }
}

function getHeader(
  headers: Record<string, string>,
  name: string,
): string | undefined {
  const lower = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === lower) return value;
  }
  return undefined;
}

function getUint8Array(value: unknown, message: string): Uint8Array {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  throw new AuthenticationError(message, { kind: "gsa_malformed" });
}

function getRecord(value: unknown, message: string): Record<string, any> {
  if (isRecord(value)) return value;
  throw new AuthenticationError(message, { kind: "gsa_malformed" });
}

function isRecord(value: unknown): value is Record<string, any> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  for (let i = 0; i < left.length; i++) {
    if (left[i] !== right[i]) return false;
  }
  return true;
}
