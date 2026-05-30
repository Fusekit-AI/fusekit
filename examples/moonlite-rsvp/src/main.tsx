import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

function App() {
  const isThanks = window.location.pathname === "/thanks";

  if (isThanks) {
    return (
      <main className="screen">
        <section className="hero hero-thanks">
          <img
            className="hero-photo"
            alt=""
            src="https://images.unsplash.com/photo-1519671482749-fd09be7ccebf?auto=format&fit=crop&w=1800&q=80"
          />
          <nav className="nav" aria-label="Event">
            <a href="/">Moonlite</a>
            <span>Private rooftop RSVP</span>
          </nav>
          <div className="status">RSVP received</div>
          <h1>You are on the list.</h1>
          <p>
            If this page is live on moonlite.rsvp and the confirmation email
            was sent, your RSVP is confirmed.
          </p>
          <a className="back" href="/">
            Back to invitation
          </a>
        </section>
      </main>
    );
  }

  return (
    <main className="screen">
      <section className="hero">
        <img
          className="hero-photo"
          alt=""
          src="https://images.unsplash.com/photo-1519671482749-fd09be7ccebf?auto=format&fit=crop&w=1800&q=80"
        />
        <nav className="nav" aria-label="Event">
          <a href="/">Moonlite</a>
          <span>Private rooftop RSVP</span>
        </nav>
        <div className="status">Friday, 8 PM · Rooftop RSVP</div>
        <h1>Moonlite RSVP</h1>
        <p>
          An intimate rooftop invitation for friends, music, and late-night
          city lights.
        </p>
        <form className="signup" action="/api/rsvp" method="post">
          <input aria-label="Name" name="name" placeholder="Full name" required />
          <input
            aria-label="Email address"
            name="email"
            placeholder="Email address"
            type="email"
            required
          />
          <button type="submit">RSVP</button>
        </form>
        <div className="event-line" aria-label="Event details">
          <span>Moonlite.RSVP</span>
          <span>8 PM</span>
          <span>Rooftop after dark</span>
        </div>
      </section>
      <section className="proof">
        <article>
          <span>01</span>
          <strong>Custom domain</strong>
          <p>Expected at https://moonlite.rsvp</p>
        </article>
        <article>
          <span>02</span>
          <strong>RSVP email</strong>
          <p>Requires Resend domain verification before guests receive confirmations.</p>
        </article>
        <article>
          <span>03</span>
          <strong>Webhook security</strong>
          <p>Uses a signing secret that must never land in the app repo.</p>
        </article>
      </section>
    </main>
  );
}

createRoot(document.getElementById("root") as HTMLElement).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
