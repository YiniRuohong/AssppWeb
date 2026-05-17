import { Router, Request, Response } from "express";
import https from "https";

const router = Router();
const ALLOWED_HOSTS = new Set(["gsa.apple.com"]);
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 20_000;

router.post("/apple-proxy", async (req: Request, res: Response) => {
  const { url, method, headers, bodyBase64 } = req.body ?? {};

  if (typeof url !== "string" || typeof method !== "string") {
    res.status(400).json({ error: "Missing url or method" });
    return;
  }

  let target: URL;
  try {
    target = new URL(url);
  } catch {
    res.status(400).json({ error: "Invalid url" });
    return;
  }

  if (target.protocol !== "https:" || !ALLOWED_HOSTS.has(target.hostname)) {
    res.status(400).json({ error: "Target host is not allowed" });
    return;
  }

  const requestHeaders: Record<string, string> = {};
  if (headers && typeof headers === "object") {
    for (const [key, value] of Object.entries(headers)) {
      if (typeof value === "string") requestHeaders[key] = value;
    }
  }

  const body =
    typeof bodyBase64 === "string" && bodyBase64.length > 0
      ? Buffer.from(bodyBase64, "base64")
      : undefined;

  try {
    const response = await new Promise<{
      status: number;
      statusText: string;
      headers: Record<string, string>;
      bodyBase64: string;
      bodyText: string;
    }>((resolve, reject) => {
      const proxyRequest = https.request(
        target,
        {
          method,
          headers: requestHeaders,
          timeout: REQUEST_TIMEOUT_MS,
        },
        (proxyResponse) => {
          const chunks: Buffer[] = [];
          let totalBytes = 0;

          proxyResponse.on("data", (chunk: Buffer) => {
            totalBytes += chunk.length;
            if (totalBytes > MAX_RESPONSE_BYTES) {
              proxyRequest.destroy();
              reject(new Error("Apple proxy response too large"));
              return;
            }
            chunks.push(chunk);
          });

          proxyResponse.on("end", () => {
            const buffer = Buffer.concat(chunks);
            const responseHeaders: Record<string, string> = {};
            for (const [key, value] of Object.entries(proxyResponse.headers)) {
              if (typeof value === "string") {
                responseHeaders[key.toLowerCase()] = value;
              } else if (Array.isArray(value)) {
                responseHeaders[key.toLowerCase()] = value.join(", ");
              }
            }

            resolve({
              status: proxyResponse.statusCode || 0,
              statusText: proxyResponse.statusMessage || "",
              headers: responseHeaders,
              bodyBase64: buffer.toString("base64"),
              bodyText: buffer.toString("utf8"),
            });
          });

          proxyResponse.on("error", reject);
        },
      );

      proxyRequest.on("error", reject);
      proxyRequest.on("timeout", () => {
        proxyRequest.destroy();
        reject(new Error("Apple proxy request timed out"));
      });

      if (body) proxyRequest.write(body);
      proxyRequest.end();
    });

    res.json(response);
  } catch (err) {
    console.error(
      "Apple proxy error:",
      err instanceof Error ? err.message : err,
    );
    res.status(502).json({ error: "Apple proxy request failed" });
  }
});

export default router;
