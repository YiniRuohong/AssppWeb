import {
  bigIntToBytes,
  bytesToBigInt,
  concatBytes,
  modPow,
  sha256,
} from "./crypto";
import { AuthenticationError } from "./authErrors";

const RFC5054_2048_N_BASE64 =
  "rGvbQTJKmpvxZt5eE4lYL69ytmUZh+4H/DGSlD21YFCjcynLtKCZ7YGT4HV3Z6E91SMSq0sDMQ3Nf0ip2gT9UOgIOWntt2ewz2CVF5oWOrNmGgX71fqq6CkYqZYvC5O4Vfl5k+yXXuqoDXQK2/T/dHNZ0EHVwz6nHSgeRGsUdzvKl7Q6I/uAFna9IHpDbGSB8dK5B4cXRhpbnTLmiPh3SFRFI7UksNV9Xqd6J3XS7PoDLPvb9S+zeGFgJ5AE5Xrmr4dOcwPOUymczAQce8MI2CpWmPOo0MOCca41+Onb+7aUtcgD2J965DXeI21SX1R1m2XjcvzWjvIPpxEfnkr/cw==";

const srpN = bytesToBigInt(
  Uint8Array.from(atob(RFC5054_2048_N_BASE64), (c) => c.charCodeAt(0)),
);
const srpG = 2n;

export interface SrpClientVerifier {
  m1: Uint8Array;
  expectedM2: Uint8Array;
  key: Uint8Array;
}

export function computePublicEphemeral(a: Uint8Array): Uint8Array {
  return bigIntToBytes(modPow(srpG, bytesToBigInt(a), srpN));
}

export async function processSrpReply(
  a: Uint8Array,
  username: Uint8Array,
  password: Uint8Array,
  salt: Uint8Array,
  bPub: Uint8Array,
): Promise<SrpClientVerifier> {
  const aInt = bytesToBigInt(a);
  const aPubBytes = bigIntToBytes(modPow(srpG, aInt, srpN));
  const bPubInt = bytesToBigInt(bPub);

  if (bPubInt % srpN === 0n) {
    throw new AuthenticationError("illegal server ephemeral", {
      kind: "gsa_malformed",
    });
  }

  const bPubBytes = bigIntToBytes(bPubInt);
  const u = bytesToBigInt(await sha256(concatBytes(aPubBytes, bPubBytes)));
  const k = await computeK();
  const identityHash = await sha256(concatBytes(new Uint8Array([58]), password));
  const x = bytesToBigInt(await sha256(concatBytes(salt, identityHash)));
  const gx = modPow(srpG, x, srpN);
  const kgx = (k * gx) % srpN;
  const base = ((srpN + bPubInt - kgx) % srpN + srpN) % srpN;
  const exp = u * x + aInt;
  const sInt = modPow(base, exp, srpN);
  const key = await sha256(bigIntToBytes(sInt));
  const m1 = await computeM1(aPubBytes, bPubBytes, key, username, salt);
  const expectedM2 = await sha256(concatBytes(aPubBytes, m1, key));

  return { m1, expectedM2, key };
}

async function computeK(): Promise<bigint> {
  const nBytes = bigIntToBytes(srpN);
  const gBytes = bigIntToBytes(srpG);
  const paddedG = concatBytes(
    new Uint8Array(Math.max(0, nBytes.length - gBytes.length)),
    gBytes,
  );
  return bytesToBigInt(await sha256(concatBytes(nBytes, paddedG)));
}

async function computeM1(
  aPub: Uint8Array,
  bPub: Uint8Array,
  key: Uint8Array,
  username: Uint8Array,
  salt: Uint8Array,
): Promise<Uint8Array> {
  const nBytes = bigIntToBytes(srpN);
  const gBytes = bigIntToBytes(srpG);
  const paddedG = concatBytes(
    new Uint8Array(Math.max(0, nBytes.length - gBytes.length)),
    gBytes,
  );
  const gHash = await sha256(paddedG);
  const nHash = await sha256(nBytes);
  const xored = new Uint8Array(gHash.length);
  for (let i = 0; i < gHash.length; i++) {
    xored[i] = gHash[i] ^ nHash[i];
  }
  const userHash = await sha256(username);
  return sha256(concatBytes(xored, userHash, salt, aPub, bPub, key));
}
