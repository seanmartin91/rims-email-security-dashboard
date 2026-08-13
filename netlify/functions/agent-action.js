// Guarded actions endpoint (PHASE 2 — intentionally disabled for now).
//
// The monitor is read-only today. This stub reserves the shape for approve-then-act
// controls (e.g. block a sender, purge a campaign) without enabling anything yet.
// Turning it on later requires:
//   1. Additional Graph WRITE permissions + admin consent (least-privilege), and/or
//      Exchange Online app-only access for block-list / purge.
//   2. An auth check here (only signed-in RIMs admins may call it).
//   3. A human confirmation step in the UI before any state-changing call.
// Until all three exist, this endpoint refuses every request by design.

exports.handler = async (event) => {
  return {
    statusCode: 403,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
    body: JSON.stringify({
      enabled: false,
      message:
        "Guarded actions are not enabled. This is a read-only monitor. " +
        "Enabling actions requires write permissions, an auth gate, and a UI confirmation step (Phase 2).",
    }),
  };
};
