# The next_steps and checklist outputs: plain text for humans.

locals {
  next_steps = compact([
    local.google && local.google_dkim == null ? "DKIM: in the Google Admin console (Apps > Google Workspace > Gmail > Authenticate email) generate a 2048-bit key, set google_dkim_value to the TXT value shown, and apply again." : "",
    local.google && local.google_dkim != null ? "DKIM: wait for DNS to update (up to 48 hours, usually under one), then click Start authentication in Admin console > Apps > Google Workspace > Gmail > Authenticate email." : "",
    local.m365 && !local.m365_dkim_ready ? "DKIM: copy the Selector1CNAME and Selector2CNAME values from the Defender portal (Email authentication settings > DKIM) or Get-DkimSigningConfig into m365_dkim_selector1_target and m365_dkim_selector2_target, and apply again." : "",
    local.m365 && local.m365_dkim_ready ? "DKIM: once DNS has updated, turn on 'Sign messages for this domain with DKIM signatures' for ${var.domain} in the Defender portal (Email authentication settings > DKIM)." : "",
    local.m365 && var.manage_mx && var.mx_records == null ? "MX: compare the MX value with the one Microsoft 365 admin center > Settings > Domains shows for ${var.domain}. Domains added since July 2026, and any with DNSSEC turned on, use an mx.microsoft host instead: if yours does, set mx_records to it." : "",
    var.verification_txt == null ? "Verification: if your provider asks you to prove you own ${var.domain}, set verification_txt to the code it gives you and apply again." : "",
    var.create_dmarc && length(var.dmarc_rua) == 0 ? "DMARC: set dmarc_rua to an address you read, so you get the daily reports that show whether every sender passes." : "",
    var.create_dmarc && var.dmarc_policy == "none" ? "DMARC: after two to four weeks of clean reports, move dmarc_policy to quarantine (try dmarc_pct = 25 first), then to reject." : "",
    var.mta_sts_policy_id != null ? "MTA-STS: host the policy file at https://mta-sts.${var.domain}/.well-known/mta-sts.txt, or receivers ignore the record." : "",
  ])

  checklist = join("\n", concat(
    ["Email DNS for ${var.domain} (${local.google ? "Google Workspace" : "Microsoft 365"})", "", "Records:"],
    flatten([
      for k in sort(keys(local.records_raw)) : [
        for v in sort(local.records_raw[k].records) : "  [ ] ${k}: ${local.records_raw[k].type} ${local.records_raw[k].name} -> ${v}"
      ]
    ]),
    ["", "Check (DNS can take up to an hour to update):"],
    [for k in sort(keys(local.records_raw)) : "  dig +short ${local.records_raw[k].type} ${local.records_raw[k].name}"],
    length(local.next_steps) == 0 ? [] : concat(["", "Still to do:"], [for s in local.next_steps : "  [ ] ${s}"]),
    ["", "Then send a message to a Gmail address, open it, choose Show original: SPF, DKIM and DMARC should each say PASS."],
  ))
}
