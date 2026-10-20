# terraform test: plans the module against a mocked AWS provider, so it needs no
# AWS account or credentials.

mock_provider "aws" {
  mock_data "aws_route53_zone" {
    defaults = {
      zone_id = "Z0000000000TEST"
    }
  }
}

variables {
  domain         = "example.com"
  email_provider = "google_workspace"
}

run "google_defaults" {
  command = plan

  assert {
    condition     = aws_route53_record.this["MX"].records == toset(["1 smtp.google.com"])
    error_message = "Google Workspace gets the single smtp.google.com MX at priority 1"
  }

  assert {
    condition     = output.spf_record == "v=spf1 include:_spf.google.com ~all"
    error_message = "SPF for Google with a soft fail by default"
  }

  assert {
    condition     = aws_route53_record.this["apex TXT"].records == toset(["v=spf1 include:_spf.google.com ~all"])
    error_message = "the apex TXT holds the SPF record"
  }

  assert {
    condition     = output.dmarc_record == "v=DMARC1; p=none"
    error_message = "DMARC starts at p=none with defaults left out"
  }

  assert {
    condition     = aws_route53_record.this["DMARC"].name == "_dmarc.example.com"
    error_message = "DMARC lives at _dmarc.<domain>"
  }

  assert {
    condition     = !contains(keys(aws_route53_record.this), "DKIM")
    error_message = "no DKIM record until the key is pasted in"
  }

  assert {
    condition     = !contains(keys(aws_route53_record.this), "autodiscover")
    error_message = "autodiscover is Microsoft only"
  }

  assert {
    condition     = alltrue([for r in values(aws_route53_record.this) : r.allow_overwrite == false && r.ttl == 3600 && r.zone_id == "Z0000000000TEST"])
    error_message = "existing records are not overwritten unless asked; default TTL; zone looked up by name"
  }

  assert {
    condition     = length(output.next_steps) > 0 && strcontains(output.next_steps[0], "generate a 2048-bit key")
    error_message = "next steps start with generating the DKIM key"
  }
}

run "google_dkim_split_for_route53" {
  command = plan

  variables {
    google_dkim_value = "v=DKIM1; k=rsa; p=P+zopUCScODCRTiNL4IiRZZINegDW/QEBG8XpbySfbrVPVQ+uGgkZmK/829d1W8i8b2R4LjW8Pa4iOZoW7dqRI+0xFxBEXzNwzFaLEqu4R0db8GSrwYWg5tib3NPhLPu3z+PG9Xhp//OOp3IfIyw7bR4bC7i1ud3ikOYXMKttQX21Mtyska9iTnK4t86YNXSgHmMdURlqFJrzF028JVkBYSy5aAdTRXjB8p8YvUAkrObVhhyBNOU4BIkXzDBYkXRWaPLBH6Md87M+8ArRvYQqOWVpkbLQiVK+KjyRp0ptHYYeqopaMpxuIIQZqTJE05gHhcWzYaJdlNQkO6VGLtTYbJZc048PdoSfVMfeHpo2S/7VcEAe0E93V2v6JodJNzPKThfH2D0"
  }

  assert {
    condition     = aws_route53_record.this["DKIM"].name == "google._domainkey.example.com"
    error_message = "default selector is google"
  }

  assert {
    condition     = length(split("\"\"", one(aws_route53_record.this["DKIM"].records))) == 2
    error_message = "a 410-character key becomes two strings"
  }

  assert {
    condition     = alltrue([for s in split("\"\"", one(aws_route53_record.this["DKIM"].records)) : length(s) <= 255])
    error_message = "no string over 255 characters"
  }

  assert {
    condition     = length(split("\"\"", one(aws_route53_record.this["DKIM"].records))[0]) == 255
    error_message = "the first string is filled to 255"
  }

  assert {
    condition     = replace(one(aws_route53_record.this["DKIM"].records), "\"\"", "") == var.google_dkim_value
    error_message = "joined back together, the strings are the original key"
  }

  assert {
    condition     = strcontains(output.next_steps[0], "Start authentication")
    error_message = "next step is to start DKIM signing in the Admin console"
  }
}

run "google_dkim_pasted_with_quotes" {
  command = plan

  variables {
    google_dkim_selector = "google2026"
    google_dkim_value    = "\"v=DKIM1; k=rsa; p=AAAA\" \"BBBB\"\n"
  }

  assert {
    condition     = aws_route53_record.this["DKIM"].records == toset(["v=DKIM1; k=rsa; p=AAAABBBB"])
    error_message = "quotes, chunk breaks and line breaks are cleaned up"
  }

  assert {
    condition     = aws_route53_record.this["DKIM"].name == "google2026._domainkey.example.com"
    error_message = "custom selector"
  }
}

run "microsoft_365_defaults" {
  command = plan

  variables {
    email_provider = "microsoft_365"
  }

  assert {
    condition     = aws_route53_record.this["MX"].records == toset(["0 example-com.mail.protection.outlook.com"])
    error_message = "Exchange Online MX from the domain with dashes"
  }

  assert {
    condition     = output.spf_record == "v=spf1 include:spf.protection.outlook.com ~all"
    error_message = "SPF for Microsoft 365"
  }

  assert {
    condition     = aws_route53_record.this["autodiscover"].records == toset(["autodiscover.outlook.com"])
    error_message = "autodiscover CNAME for Outlook"
  }

  assert {
    condition     = !contains(keys(aws_route53_record.this), "DKIM selector1")
    error_message = "no DKIM CNAMEs without the tenant's targets"
  }

  assert {
    condition     = anytrue([for s in output.next_steps : strcontains(s, "mx.microsoft")])
    error_message = "remind to check the MX against the admin center"
  }
}

run "microsoft_365_dkim_new_format" {
  command = plan

  variables {
    email_provider      = "microsoft_365"
    m365_initial_domain = "contoso.onmicrosoft.com"
    m365_dkim_partition = "n"
  }

  assert {
    condition     = aws_route53_record.this["DKIM selector1"].records == toset(["selector1-example-com._domainkey.contoso.n-v1.dkim.mail.microsoft"])
    error_message = "selector1 target in the dkim.mail.microsoft format"
  }

  assert {
    condition     = aws_route53_record.this["DKIM selector2"].name == "selector2._domainkey.example.com"
    error_message = "selector2 host"
  }
}

run "microsoft_365_dkim_legacy_format" {
  command = plan

  variables {
    email_provider      = "microsoft_365"
    m365_initial_domain = "contoso"
  }

  assert {
    condition     = aws_route53_record.this["DKIM selector2"].records == toset(["selector2-example-com._domainkey.contoso.onmicrosoft.com"])
    error_message = "older domains point at <prefix>.onmicrosoft.com"
  }
}

run "microsoft_365_explicit_targets_and_mx_override" {
  command = plan

  variables {
    email_provider             = "microsoft_365"
    zone_id                    = "ZEXPLICIT"
    m365_initial_domain        = "ignored"
    m365_dkim_selector1_target = "selector1-example-com._domainkey.contoso.r-v1.dkim.mail.microsoft"
    m365_dkim_selector2_target = "selector2-example-com._domainkey.contoso.r-v1.dkim.mail.microsoft"
    mx_records                 = ["0 example-com.o-v1.mx.microsoft"]
    m365_autodiscover          = false
    verification_txt           = "MS=ms12345678"
  }

  assert {
    condition     = aws_route53_record.this["DKIM selector1"].records == toset(["selector1-example-com._domainkey.contoso.r-v1.dkim.mail.microsoft"])
    error_message = "explicit targets win over the derived ones"
  }

  assert {
    condition     = aws_route53_record.this["MX"].records == toset(["0 example-com.o-v1.mx.microsoft"])
    error_message = "mx_records overrides the default"
  }

  assert {
    condition     = !contains(keys(aws_route53_record.this), "autodiscover")
    error_message = "autodiscover can be turned off"
  }

  assert {
    condition     = aws_route53_record.this["apex TXT"].records == toset(["v=spf1 include:spf.protection.outlook.com ~all", "MS=ms12345678"])
    error_message = "verification code shares the apex TXT with SPF"
  }

  assert {
    condition     = output.zone_id == "ZEXPLICIT" && aws_route53_record.this["MX"].zone_id == "ZEXPLICIT"
    error_message = "zone_id skips the lookup"
  }
}

run "spf_merges_every_sender_into_one_record" {
  command = plan

  variables {
    spf_include_extra = ["amazonses.com", "include:servers.mcsv.net", "_spf.google.com"]
    spf_ip4           = ["203.0.113.10", "198.51.100.0/24"]
    spf_policy        = "-all"
    extra_apex_txt    = ["google-site-verification=abc123", "facebook-domain-verification=xyz"]
  }

  assert {
    condition     = output.spf_record == "v=spf1 ip4:203.0.113.10 ip4:198.51.100.0/24 include:_spf.google.com include:amazonses.com include:servers.mcsv.net -all"
    error_message = "one SPF record: IPs, the provider, extra senders (deduplicated), then the policy"
  }

  assert {
    condition     = output.spf_lookup_count == 3
    error_message = "three includes, three lookups; IPs cost none"
  }

  assert {
    condition     = length([for v in aws_route53_record.this["apex TXT"].records : v if startswith(v, "v=spf1")]) == 1
    error_message = "exactly one SPF value at the apex"
  }

  assert {
    condition     = length(aws_route53_record.this["apex TXT"].records) == 3
    error_message = "existing apex values are kept next to SPF"
  }
}

run "spf_ten_lookups_is_the_limit" {
  command = plan

  variables {
    spf_include_extra = [for i in range(9) : "sender${i}.example.net"]
  }

  assert {
    condition     = output.spf_lookup_count == 10
    error_message = "the provider plus nine senders is exactly ten"
  }
}

run "spf_over_ten_lookups_is_refused" {
  command = plan

  variables {
    spf_include_extra = [for i in range(10) : "sender${i}.example.net"]
  }

  expect_failures = [aws_route53_record.this]
}

run "second_spf_record_is_refused" {
  command = plan

  variables {
    extra_apex_txt = ["v=spf1 include:old.example.net ~all"]
  }

  expect_failures = [var.extra_apex_txt]
}

run "dmarc_enforcing" {
  command = plan

  variables {
    dmarc_policy           = "quarantine"
    dmarc_subdomain_policy = "reject"
    dmarc_rua              = ["dmarc@example.com", "mailto:reports@dmarc.example.net"]
    dmarc_pct              = 25
    dmarc_adkim            = "s"
    dmarc_aspf             = "s"
  }

  assert {
    condition     = output.dmarc_record == "v=DMARC1; p=quarantine; sp=reject; rua=mailto:dmarc@example.com,mailto:reports@dmarc.example.net; pct=25; adkim=s; aspf=s"
    error_message = "DMARC record with every tag"
  }

  assert {
    condition     = !anytrue([for s in output.next_steps : strcontains(s, "dmarc_rua")])
    error_message = "no reminder to add a report address once one is set"
  }
}

run "dmarc_policy_is_validated" {
  command = plan

  variables {
    dmarc_policy = "block"
  }

  expect_failures = [var.dmarc_policy]
}

run "leave_mx_alone" {
  command = plan

  variables {
    manage_mx = false
  }

  assert {
    condition     = !contains(keys(aws_route53_record.this), "MX")
    error_message = "manage_mx = false leaves MX untouched"
  }

  assert {
    condition     = length(output.mx_records) == 0
    error_message = "no MX in the outputs"
  }
}

run "google_legacy_mx" {
  command = plan

  variables {
    google_legacy_mx = true
  }

  assert {
    condition     = length(aws_route53_record.this["MX"].records) == 5 && contains(aws_route53_record.this["MX"].records, "1 aspmx.l.google.com")
    error_message = "the five-record ASPMX set"
  }
}

run "take_over_existing_records" {
  command = plan

  variables {
    replace_existing_records = true
    ttl                      = 300
  }

  assert {
    condition     = alltrue([for r in values(aws_route53_record.this) : r.allow_overwrite && r.ttl == 300])
    error_message = "opt-in overwrite and custom TTL reach every record"
  }
}

run "mta_sts_and_tls_rpt_are_opt_in" {
  command = plan

  variables {
    mta_sts_policy_id = "20261020"
    tls_rpt_rua       = ["tls@example.com"]
  }

  assert {
    condition     = aws_route53_record.this["MTA-STS"].records == toset(["v=STSv1; id=20261020"]) && aws_route53_record.this["MTA-STS"].name == "_mta-sts.example.com"
    error_message = "MTA-STS TXT record"
  }

  assert {
    condition     = aws_route53_record.this["TLS-RPT"].records == toset(["v=TLSRPTv1; rua=mailto:tls@example.com"]) && aws_route53_record.this["TLS-RPT"].name == "_smtp._tls.example.com"
    error_message = "TLS-RPT TXT record"
  }
}

run "dmarc_and_spf_can_be_skipped" {
  command = plan

  variables {
    create_spf   = false
    create_dmarc = false
  }

  assert {
    condition     = !contains(keys(aws_route53_record.this), "apex TXT") && !contains(keys(aws_route53_record.this), "DMARC")
    error_message = "nothing at the apex or _dmarc when both are off"
  }

  assert {
    condition     = output.spf_record == null && output.dmarc_record == null
    error_message = "outputs are null when off"
  }
}

run "provider_is_validated" {
  command = plan

  variables {
    email_provider = "yahoo"
  }

  expect_failures = [var.email_provider]
}

run "m365_dkim_needs_both_selectors" {
  command = plan

  variables {
    email_provider             = "microsoft_365"
    m365_dkim_selector1_target = "selector1-example-com._domainkey.contoso.onmicrosoft.com"
  }

  expect_failures = [aws_route53_record.this]
}

run "checklist_lists_every_record_and_step" {
  command = plan

  variables {
    dmarc_rua = ["dmarc@example.com"]
  }

  assert {
    condition     = startswith(output.checklist, "Email DNS for example.com (Google Workspace)")
    error_message = "checklist names the domain and provider"
  }

  assert {
    condition     = strcontains(output.checklist, "[ ] MX: MX example.com -> 1 smtp.google.com")
    error_message = "checklist has the MX record"
  }

  assert {
    condition     = strcontains(output.checklist, "[ ] DMARC: TXT _dmarc.example.com -> v=DMARC1; p=none; rua=mailto:dmarc@example.com")
    error_message = "checklist has the DMARC record"
  }

  assert {
    condition     = strcontains(output.checklist, "dig +short TXT _dmarc.example.com")
    error_message = "checklist has the dig commands"
  }

  assert {
    condition     = strcontains(output.checklist, "Still to do:") && strcontains(output.checklist, "generate a 2048-bit key")
    error_message = "checklist ends with the steps left"
  }
}
