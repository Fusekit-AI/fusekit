import crypto from "node:crypto";

type WebhookRequest = {
  method?: string;
  headers: Record<string, string | string[] | undefined>;
  body?: {
    type?: string;
  };
};

type WebhookResponse = {
  status(code: number): WebhookResponse;
  json(payload: unknown): void;
};

function safeEqual(left: string, right: string) {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

export default function handler(request: WebhookRequest, response: WebhookResponse) {
  if (request.method !== "POST") {
    response.status(405).json({ ok: false });
    return;
  }

  const expectedSignature = process.env.WEBHOOK_SECRET;
  const providedSignature = String(request.headers["x-moonlite-webhook-secret"] || "");

  if (!expectedSignature || !safeEqual(expectedSignature, providedSignature)) {
    response.status(401).json({ ok: false });
    return;
  }

  response.json({
    ok: true,
    event: typeof request.body?.type === "string" ? request.body.type : "unknown",
  });
}
