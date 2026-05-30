import { Resend } from "resend";

const fromEmail = process.env.RESEND_FROM_EMAIL;
const audienceId = process.env.RESEND_AUDIENCE_ID;
const appUrl = process.env.NEXT_PUBLIC_APP_URL;

type FormBody = {
  name?: string;
  email?: string;
};

type RsvpRequest = {
  method?: string;
  body?: FormBody;
};

type RsvpResponse = {
  status(code: number): RsvpResponse;
  json(payload: unknown): void;
  writeHead(code: number, headers: Record<string, string>): void;
  end(): void;
};

export default async function handler(request: RsvpRequest, response: RsvpResponse) {
  if (request.method !== "POST") {
    response.status(405).json({ ok: false });
    return;
  }

  const name = String(request.body?.name || "").trim();
  const email = String(request.body?.email || "").trim().toLowerCase();

  if (!name || !email || !email.includes("@")) {
    response.status(400).json({ ok: false, error: "invalid_rsvp" });
    return;
  }

  const resend = new Resend(process.env.RESEND_API_KEY);

  if (audienceId) {
    await resend.contacts.create({
      audienceId,
      email,
      firstName: name,
      unsubscribed: false,
    });
  }

  if (fromEmail) {
    await resend.emails.send({
      from: fromEmail,
      to: email,
      subject: "You are on the Moonlite RSVP list",
      html: `<p>${name}, you are on the list.</p><p>Details live at ${appUrl || "moonlite.rsvp"}.</p>`,
    });
  }

  response.writeHead(303, { Location: "/thanks" });
  response.end();
}
