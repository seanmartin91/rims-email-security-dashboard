// RIMs Transport — AI-Managed Email Security agent (read-only monitor)
// Serverless backend: authenticates to Microsoft Graph with app (client-credentials)
// and returns live security alerts + incidents. Falls back to demo data when the
// tenant credentials are not configured, so the dashboard always renders.
//
// Required Netlify environment variables (Site settings > Environment variables):
//   MS_TENANT_ID       - RIMs' Entra (Azure AD) tenant ID (GUID)
//   MS_CLIENT_ID       - App registration (client) ID
//   MS_CLIENT_SECRET   - App registration client secret  (NEVER commit this)
//
// Required Graph APPLICATION permissions (admin-consented on RIMs' tenant):
//   SecurityAlert.Read.All      (for /security/alerts_v2)
//   SecurityIncident.Read.All   (for /security/incidents)

const TENANT = process.env.MS_TENANT_ID;
const CLIENT = process.env.MS_CLIENT_ID;
const SECRET = process.env.MS_CLIENT_SECRET;

const GRAPH = "https://graph.microsoft.com/v1.0";

// ---- Recommendation engine (rule-based; no LLM, so no per-call cost) ----
// Turns alerts + incidents into prioritised, actionable recommendations.
// An LLM step could later rewrite these into richer narratives — kept optional.
function rank(p) { return { high: 0, medium: 1, low: 2 }[p] ?? 3; }
function buildRecommendations(alerts, incidents) {
  const A = alerts || [], I = incidents || [];
  const blob = A.map((a) => ((a.title || "") + " " + (a.category || "")).toLowerCase()).join(" | ");
  const iblob = I.map((i) => ((i.name || "") + " " + (i.type || "")).toLowerCase()).join(" | ");
  const recs = [];

  if (/(bmo|bank of montreal|rbc|scotiabank|cibc|\btd\b|impersonat|phish)/.test(blob))
    recs.push({ priority: "high", title: "Block the phishing sender domain and warn staff",
      why: "Bank-brand / impersonation phishing detected in recent alerts — the pattern behind the BMO wave.",
      action: "Add the sending domain + link host to the Tenant Allow/Block List, then send the staff heads-up email." });

  if (/(bec|impersonation|ceo|invoice|payment|wire)/.test(iblob))
    recs.push({ priority: "high", title: "Verify the BEC attempt caused no payment change",
      why: "A business-email-compromise / impersonation incident is open.",
      action: "Confirm with Finance that no vendor bank details or payments were changed; keep the sender quarantined." });

  if (/(malware|attachment|virus)/.test(blob))
    recs.push({ priority: "medium", title: "Confirm the malicious attachment was contained",
      why: "A malware / attachment detection fired.",
      action: "Check Safe Attachments quarantined it, then search for other recipients of the same file." });

  if (/(sign-in|impossible travel|identity|token|risky)/.test(blob))
    recs.push({ priority: "medium", title: "Review the flagged sign-in",
      why: "A risky / impossible-travel sign-in was detected.",
      action: "Confirm the account was reset and enforce MFA re-registration if it isn't already." });

  if (/(click|awareness|repeat)/.test(iblob))
    recs.push({ priority: "low", title: "Assign targeted awareness training",
      why: "A user clicked a simulated or real phishing link.",
      action: "Auto-enrol them in a short 'spot the spoof' module and shorten their next simulation interval." });

  recs.push({ priority: "low", title: "Keep Defender P1 impersonation protection tuned",
    why: "On Plan 1, impersonation protection is the main lever against brand look-alikes.",
    action: "Ensure bmo.com + the big Canadian banks are listed as protected domains with action = Quarantine." });

  if (!recs.length)
    recs.push({ priority: "low", title: "No action needed", why: "No active threats beyond baseline.",
      action: "Posture looks healthy — the agent will flag anything new." });

  return recs.sort((a, b) => rank(a.priority) - rank(b.priority)).slice(0, 5);
}

function json(statusCode, obj) {
  return {
    statusCode,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
    body: JSON.stringify(obj),
  };
}

// Demo data (BMO-themed to match the recent incident) shown until live creds are set.
function demoPayload(reason) {
  const incidents = [
    { id: "demo-1", name: "CEO impersonation → Finance", type: "BEC", severity: "high", status: "active", createdDateTime: null },
    { id: "demo-2", name: "Repeat clicker — 1 user", type: "Awareness", severity: "low", status: "active", createdDateTime: null },
  ];
  const alerts = [
    { title: "Phishing campaign impersonating BMO removed after delivery (ZAP)", severity: "high", category: "Phishing", status: "resolved", createdDateTime: null, provider: "Microsoft Defender for Office 365" },
    { title: "Malware attachment detonated by Safe Attachments", severity: "medium", category: "Malware", status: "resolved", createdDateTime: null, provider: "Microsoft Defender for Office 365" },
    { title: "Impossible-travel sign-in blocked", severity: "medium", category: "Identity", status: "resolved", createdDateTime: null, provider: "Microsoft Entra ID" },
  ];
  return {
    live: false,
    demo: true,
    reason: reason || "not_configured",
    generatedAt: new Date().toISOString(),
    openIncidents: incidents.length,
    incidents,
    alerts,
    recommendations: buildRecommendations(alerts, incidents),
  };
}

async function getToken() {
  const body = new URLSearchParams({
    client_id: CLIENT,
    client_secret: SECRET,
    scope: "https://graph.microsoft.com/.default",
    grant_type: "client_credentials",
  });
  const r = await fetch(`https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/token`, {
    method: "POST",
    body,
  });
  if (!r.ok) throw new Error(`token_${r.status}`);
  const j = await r.json();
  return j.access_token;
}

async function graphGet(token, path) {
  const r = await fetch(GRAPH + path, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error(`graph_${r.status}_${path.split("?")[0]}`);
  return r.json();
}

exports.handler = async () => {
  // Not configured yet -> demo mode (dashboard still renders).
  if (!TENANT || !CLIENT || !SECRET) {
    return json(200, demoPayload("not_configured"));
  }

  try {
    const token = await getToken();

    // Alerts (required). alerts_v2 surfaces EOP / Defender for Office 365 detections.
    const alertsResp = await graphGet(
      token,
      "/security/alerts_v2?$top=20&$orderby=createdDateTime%20desc"
    );
    const alerts = (alertsResp.value || []).map((a) => ({
      title: a.title,
      severity: a.severity,
      category: a.category,
      status: a.status,
      createdDateTime: a.createdDateTime,
      provider: a.serviceSource || a.detectionSource || "Microsoft 365",
    }));

    // Incidents (best-effort — some tenants/licences return limited data).
    let incidents = [];
    try {
      const incResp = await graphGet(
        token,
        "/security/incidents?$filter=status%20eq%20'active'&$top=50"
      );
      incidents = (incResp.value || []).map((i) => ({
        id: i.id,
        name: i.displayName,
        type: (i.classification || "Incident"),
        severity: i.severity,
        status: i.status,
        createdDateTime: i.createdDateTime,
      }));
    } catch (e) {
      incidents = [];
    }

    return json(200, {
      live: true,
      demo: false,
      generatedAt: new Date().toISOString(),
      openIncidents: incidents.length,
      incidents,
      alerts,
      recommendations: buildRecommendations(alerts, incidents),
    });
  } catch (e) {
    // Auth/permission/config error -> fall back to demo so the page still works,
    // and report the reason so setup issues are visible in the health check.
    return json(200, demoPayload(String((e && e.message) || e)));
  }
};
