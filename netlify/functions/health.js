// Connection health check for the RIMs security agent.
// Returns ONLY booleans about whether each secret is present — never their values.
// Visit /.netlify/functions/health to confirm the Azure wiring during setup.

exports.handler = async () => {
  const configured =
    !!process.env.MS_TENANT_ID &&
    !!process.env.MS_CLIENT_ID &&
    !!process.env.MS_CLIENT_SECRET;

  let tokenOk = null;
  let detail = configured ? "credentials_present" : "not_configured";

  if (configured) {
    try {
      const body = new URLSearchParams({
        client_id: process.env.MS_CLIENT_ID,
        client_secret: process.env.MS_CLIENT_SECRET,
        scope: "https://graph.microsoft.com/.default",
        grant_type: "client_credentials",
      });
      const r = await fetch(
        `https://login.microsoftonline.com/${process.env.MS_TENANT_ID}/oauth2/v2.0/token`,
        { method: "POST", body }
      );
      tokenOk = r.ok;
      detail = r.ok ? "token_acquired" : `token_error_${r.status}`;
    } catch (e) {
      tokenOk = false;
      detail = String((e && e.message) || e);
    }
  }

  return {
    statusCode: 200,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
    body: JSON.stringify({
      configured,
      tenantIdSet: !!process.env.MS_TENANT_ID,
      clientIdSet: !!process.env.MS_CLIENT_ID,
      clientSecretSet: !!process.env.MS_CLIENT_SECRET,
      tokenAcquired: tokenOk,
      detail,
      checkedAt: new Date().toISOString(),
    }),
  };
};
