// Client-side vulnerabilities — INTENTIONALLY VULNERABLE.
const express = require('express');
const router = express.Router();

// A single page demonstrating client-side flaws for DevTools-based exercises.
// VB-157 reverse tabnabbing, VB-166 postMessage no origin check,
// VB-167 DOM clobbering, VB-169 secrets in localStorage, VB-032 DOM XSS.
router.get('/client', (req, res) => {
  res.type('html').send(`<!DOCTYPE html>
<html><head><title>VulnBank Client-Side Lab</title></head><body>
<h2>Client-Side Attack Lab</h2>

<!-- VB-169: sensitive token stashed in localStorage (readable by any XSS) -->
<script>
  localStorage.setItem('authToken', 'sk_live_vulnbank_USER_TOKEN_abc123');
  localStorage.setItem('pan', '4111111111111111');
</script>
<p>Open DevTools → Application → Local Storage to find secrets (VB-169).</p>

<!-- VB-157: target=_blank without rel=noopener -> reverse tabnabbing -->
<p><a href="https://example.com" target="_blank">Partner site</a>
   (opened tab can rewrite window.opener.location — VB-157)</p>

<!-- VB-032: DOM-based XSS via location.hash sink -->
<div id="out"></div>
<script>
  // Try:  /client#<img src=x onerror=alert(document.domain)>
  document.getElementById('out').innerHTML = 'Section: ' + decodeURIComponent(location.hash.slice(1));
</script>

<!-- VB-166: postMessage handler with no origin check -->
<script>
  window.addEventListener('message', function (e) {
    // No e.origin validation -> any page can drive this handler (VB-166).
    document.getElementById('out').innerHTML += '<br>msg: ' + e.data;
  });
</script>

<!-- VB-167: DOM clobbering — code trusts window.config which can be clobbered by HTML ids -->
<script>
  // If attacker-injected HTML defines <a id="config"><a id="config" name="isAdmin">,
  // window.config.isAdmin becomes truthy.
  if (window.config && window.config.isAdmin) {
    document.body.innerHTML += '<p style="color:red">ADMIN MODE (DOM clobbered)</p>';
  }
</script>
</body></html>`);
});

module.exports = router;
