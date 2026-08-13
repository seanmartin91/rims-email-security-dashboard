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

function json(statusCode, obj) {
  return {
    statusCode,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
    body: JSON.stringify(obj),
  };
}

// Demo data (BMO-themed to match the recent incident) shown until live creds are set.
function demoPayload(reason) {
  return {
    live: false,
    demo: true,
    reason: reason || "not_configured",
    generatedAt: new Date().toISOString(),
    openIncidents: 2,
    incidents: [
      { id: "demo-1", name: "CEO impersonation → Finance", type: "BEC", severity: "high", status: "active", createdDateTime: null },
      { id: "demo-2", name: "Repeat clicker — 1 user", type: "Awareness", severity: "low", status: "active", createdDateTime: null },
    ],
    alerts: [
      { title: "Phishing campaign impersonating BMO removed after delivery (ZAP)", severity: "high", category: "Phishing", status: "resolved", createdDateTime: null, provider: "Microsoft Defender for Office 365" },
      { title: "Malware attachment detonated by Safe Attachments", severity: "medium", category: "Malware", status: "resolved", createdDateTime: null, provider: "Microsoft Defender for Office 365" },
      { title: "Impossible-travel sign-in blocked", severity: "medium", category: "Identity", status: "resolved", createdDateTime: null, provider: "Microsoft Entra ID" },
    ],
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
    });
  } catch (e) {
    // Auth/permission/config error -> fall back to demo so the page still works,
    // and report the reason so setup issues are visible in the health check.
    return json(200, demoPayload(String((e && e.message) || e)));
  }
};
