import os
import logging
import stripe
from app import db

log = logging.getLogger(__name__)

# ============================================================================
# WEBHOOK SIGNATURE MODE
#
# Comment OUT the PRODUCTION line and comment IN the LOCAL TESTING line only
# for local development. Never ship with ALLOW_UNSIGNED_WEBHOOKS = True —
# in that mode anyone who can reach /api/stripe-webhook can mark any
# submission as paid without paying.
# ============================================================================
ALLOW_UNSIGNED_WEBHOOKS = False      # PRODUCTION: require Stripe signature
# ALLOW_UNSIGNED_WEBHOOKS = True     # LOCAL TESTING ONLY — comment the line above
# ============================================================================

STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")

EXPECTED_AMOUNT_CENTS = 100       # $1.00
EXPECTED_CURRENCY = "usd"

stripe.api_key = STRIPE_SECRET_KEY


def create_checkout_session(sid, filename, success_url, cancel_url):
    """Create a Stripe Checkout Session for the $1 raw-export purchase."""
    if not stripe.api_key:
        log.error("STRIPE_SECRET_KEY is not set. Cannot create checkout session.")
        return None
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{
                "price_data": {
                    "currency": EXPECTED_CURRENCY,
                    "product_data": {
                        "name": "Extended Observation Data",
                        "description": f"Redacted zip archive for {filename}",
                    },
                    "unit_amount": EXPECTED_AMOUNT_CENTS,
                },
                "quantity": 1,
            }],
            mode="payment",
            client_reference_id=sid,
            metadata={"submission_id": sid},
            success_url=success_url,
            cancel_url=cancel_url,
        )
        return session.url
    except Exception as e:
        log.error(f"Stripe checkout creation failed for {sid}: {e}")
        return None


def _verify_signature(payload, sig_header):
    """Return the parsed event dict, or None if verification fails.

    In production (ALLOW_UNSIGNED_WEBHOOKS = False) this requires
    STRIPE_WEBHOOK_SECRET to be set and the Stripe-Signature header to be
    valid. Anything else returns None and the caller responds 400 (Stripe
    will not retry permanent failures).
    """
    if ALLOW_UNSIGNED_WEBHOOKS:
        log.warning(
            "ALLOW_UNSIGNED_WEBHOOKS=True — accepting unsigned webhook. "
            "This MUST be False in production."
        )
        try:
            import json
            return json.loads(payload)
        except Exception as e:
            log.error(f"Failed to parse unsigned payload: {e}")
            return None

    if not WEBHOOK_SECRET:
        log.error(
            "STRIPE_WEBHOOK_SECRET is not set. Refusing webhook. "
            "Set it in the environment, or flip ALLOW_UNSIGNED_WEBHOOKS=True "
            "for local testing."
        )
        return None

    try:
        return stripe.Webhook.construct_event(payload, sig_header, WEBHOOK_SECRET)
    except ValueError as e:
        log.error(f"Invalid Stripe payload: {e}")
        return None
    except Exception as e:
        # Covers SignatureVerificationError across Stripe SDK versions
        log.error(f"Stripe signature verification failed: {type(e).__name__}: {e}")
        return None


def _validate_paid_session(session):
    """Return (sid, error_reason). sid is None on failure.

    Defense in depth: verify the amount and currency match what we charged,
    and that Stripe reports the payment as paid. Card payments complete with
    payment_status='paid' on checkout.session.completed.
    """
    sid = session.get("client_reference_id")
    if not sid:
        return None, "no client_reference_id"
    amount = session.get("amount_total")
    if amount != EXPECTED_AMOUNT_CENTS:
        return None, f"amount mismatch: got {amount}, expected {EXPECTED_AMOUNT_CENTS}"
    currency = session.get("currency")
    if currency != EXPECTED_CURRENCY:
        return None, f"currency mismatch: got {currency}, expected {EXPECTED_CURRENCY}"
    status = session.get("payment_status")
    if status != "paid":
        return None, f"payment_status={status} (not paid)"
    return sid, None


def verify_paid_session(session_id, expected_sid):
    """Retrieve a checkout session from Stripe and confirm it is paid for
    the expected submission. Used on the ?payment=success redirect so the
    user does not have to wait for the webhook to arrive.

    Returns True if the session is valid and mark_paid succeeded (or was
    already set). Returns False on any mismatch or Stripe error.
    """
    if not stripe.api_key or not session_id or not expected_sid:
        return False
    try:
        session = stripe.checkout.Session.retrieve(session_id)
    except Exception as e:
        log.error(f"Stripe session retrieve failed id={session_id}: {e}")
        return False
    sid, reason = _validate_paid_session(session)
    if sid is None:
        log.warning(f"verify_paid_session rejected id={session_id} reason={reason}")
        return False
    if sid != expected_sid:
        log.warning(
            f"verify_paid_session sid mismatch id={session_id} "
            f"got={sid} expected={expected_sid}"
        )
        return False
    db.mark_paid(sid, session_id)
    return True


def handle_webhook(payload, sig_header):
    """Dispatch a Stripe webhook. Returns True → route responds 200, False → 400."""
    event = _verify_signature(payload, sig_header)
    if event is None:
        return False

    event_type = event.get("type", "")
    session = event.get("data", {}).get("object", {}) or {}

    if event_type == "checkout.session.completed":
        sid, reason = _validate_paid_session(session)
        if sid is None:
            log.warning(f"checkout.session.completed rejected: {reason}")
            return False
        session_id = session.get("id", "")
        log.info(
            f"Payment received sid={sid} session={session_id} "
            f"amount={session.get('amount_total')} {session.get('currency')}"
        )
        ok = db.mark_paid(sid, session_id)
        if not ok:
            log.warning(f"mark_paid no-op sid={sid} (already paid or row gone)")
        return True

    if event_type == "checkout.session.async_payment_succeeded":
        sid, reason = _validate_paid_session(session)
        if sid is None:
            log.warning(f"async_payment_succeeded rejected: {reason}")
            return False
        log.info(f"Async payment confirmed sid={sid} session={session.get('id')}")
        db.mark_paid(sid, session.get("id", ""))
        return True

    if event_type == "checkout.session.async_payment_failed":
        sid = session.get("client_reference_id")
        log.warning(f"Async payment failed sid={sid} session={session.get('id')}")
        return True  # ack, do not retry

    # Any other event type: ack so Stripe stops retrying
    log.info(f"Unhandled Stripe event type: {event_type}")
    return True
