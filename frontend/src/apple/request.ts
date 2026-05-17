import { libcurl, initLibcurl } from "./libcurl-init";
import { buildCookieHeader } from "./cookies";
import { userAgent } from "./config";
import type { Cookie } from "../types";

export interface CurlRequestOptions {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: string | Uint8Array | ArrayBuffer;
  userAgent?: string;
}

export interface AppleRequestOptions {
  host: string;
  path: string;
  method: string;
  headers?: Record<string, string>;
  body?: string;
  cookies?: Cookie[];
}

export interface AppleResponse {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  rawHeaders: [string, string][];
  body: string;
  bodyBytes: Uint8Array;
}

export interface CurlResponse {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  rawHeaders: [string, string][];
  bodyText: string;
  bodyBytes: Uint8Array;
}

export async function curlRequest(
  opts: CurlRequestOptions,
): Promise<CurlResponse> {
  await initLibcurl();

  const headers: Record<string, string> = {
    "User-Agent": opts.userAgent || userAgent,
    ...(opts.headers || {}),
  };

  const resp = await libcurl.fetch(opts.url, {
    method: opts.method,
    headers,
    body: opts.body,
    redirect: "manual",
    _libcurl_http_version: 1.1,
  });

  const responseHeaders: Record<string, string> = {};
  for (const [key, value] of resp.raw_headers) {
    responseHeaders[key.toLowerCase()] = value;
  }

  const bodyBuffer = await resp.arrayBuffer();
  const bodyBytes = new Uint8Array(bodyBuffer);
  const bodyText = new TextDecoder().decode(bodyBytes);

  return {
    status: resp.status,
    statusText: resp.statusText,
    headers: responseHeaders,
    rawHeaders: resp.raw_headers,
    bodyText,
    bodyBytes,
  };
}

export async function appleRequest(
  opts: AppleRequestOptions,
): Promise<AppleResponse> {
  const url = `https://${opts.host}${opts.path}`;
  const headers: Record<string, string> = {
    ...opts.headers,
  };

  if (opts.cookies?.length) {
    const cookieHeader = buildCookieHeader(opts.cookies, url);
    if (cookieHeader) {
      headers["Cookie"] = cookieHeader;
    }
  }

  const resp = await curlRequest({
    method: opts.method,
    url,
    headers,
    body: opts.body,
    userAgent,
  });

  return {
    status: resp.status,
    statusText: resp.statusText,
    headers: resp.headers,
    rawHeaders: resp.rawHeaders,
    body: resp.bodyText,
    bodyBytes: resp.bodyBytes,
  };
}
