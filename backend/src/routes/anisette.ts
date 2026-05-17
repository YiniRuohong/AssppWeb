import { Router, Request, Response } from "express";
import https from "https";
import {
  ANISETTE_MAX_BYTES,
  ANISETTE_TIMEOUT_MS,
  ANISETTE_URL,
} from "../config.js";

const router = Router();
const userAgent = "AssppWeb/1.0";

router.get("/anisette", async (_req: Request, res: Response) => {
  try {
    const body = await new Promise<string>((resolve, reject) => {
      const request = https.get(
        ANISETTE_URL,
        {
          headers: {
            Accept: "application/json",
            "User-Agent": userAgent,
          },
          timeout: ANISETTE_TIMEOUT_MS,
        },
        (resp) => {
          let data = "";
          let totalBytes = 0;

          resp.on("data", (chunk: Buffer) => {
            totalBytes += chunk.length;
            if (totalBytes > ANISETTE_MAX_BYTES) {
              request.destroy();
              reject(new Error("Anisette response too large"));
              return;
            }
            data += chunk;
          });
          resp.on("end", () => {
            if (resp.statusCode && resp.statusCode >= 400) {
              reject(
                new Error(`Anisette upstream returned HTTP ${resp.statusCode}`),
              );
              return;
            }
            resolve(data);
          });
          resp.on("error", reject);
        },
      );
      request.on("error", reject);
      request.on("timeout", () => {
        request.destroy();
        reject(new Error("Anisette request timed out"));
      });
    });

    const parsed = JSON.parse(body) as Record<string, unknown>;
    res.json(parsed);
  } catch (err) {
    console.error(
      `Anisette proxy error (${ANISETTE_URL}):`,
      err instanceof Error ? err.message : err,
    );
    res.status(502).json({ error: "Anisette request failed" });
  }
});

export default router;
