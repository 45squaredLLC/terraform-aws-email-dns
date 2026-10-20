# The DNS records that keep a business's email out of the spam folder: SPF, DKIM
# and DMARC, plus MX and the provider's own records, for Google Workspace or
# Microsoft 365, in a Route 53 hosted zone.

locals {
  google = var.email_provider == "google_workspace"
  m365   = var.email_provider == "microsoft_365"
  dashed = replace(var.domain, ".", "-")

  zone_id = var.zone_id != null ? var.zone_id : data.aws_route53_zone.this[0].zone_id

  # ------------------------------------------------------------------------- #
  # MX
  # ------------------------------------------------------------------------- #

  google_mx = var.google_legacy_mx ? [
    "1 aspmx.l.google.com",
    "5 alt1.aspmx.l.google.com",
    "5 alt2.aspmx.l.google.com",
    "10 alt3.aspmx.l.google.com",
    "10 alt4.aspmx.l.google.com",
  ] : ["1 smtp.google.com"]

  # The long-standing Exchange Online pattern. Microsoft's admin center shows the
  # exact value for each domain; newer domains get an mx.microsoft host instead,
  # which mx_records accepts.
  m365_mx = ["0 ${local.dashed}.mail.protection.outlook.com"]

  mx = var.mx_records != null ? var.mx_records : (local.google ? local.google_mx : local.m365_mx)

  # ------------------------------------------------------------------------- #
  # SPF: one record, every sender merged into it
  # ------------------------------------------------------------------------- #

  provider_spf_include = local.google ? "_spf.google.com" : "spf.protection.outlook.com"

  spf_includes = distinct(concat(
    [local.provider_spf_include],
    [for d in var.spf_include_extra : trimprefix(lower(d), "include:")],
  ))

  spf_record = join(" ", concat(
    ["v=spf1"],
    [for ip in var.spf_ip4 : "ip4:${ip}"],
    [for ip in var.spf_ip6 : "ip6:${ip}"],
    [for d in local.spf_includes : "include:${d}"],
    [var.spf_policy],
  ))

  # Every include costs at least one DNS lookup; receivers stop at 10 and treat
  # the record as broken. Includes nested inside those domains count too, but
  # can't be known at plan time.
  spf_lookup_count = length(local.spf_includes)

  # ------------------------------------------------------------------------- #
  # DMARC
  # ------------------------------------------------------------------------- #

  dmarc_rua = [for a in var.dmarc_rua : startswith(lower(a), "mailto:") ? a : "mailto:${a}"]

  dmarc_record = join("; ", compact([
    "v=DMARC1",
    "p=${var.dmarc_policy}",
    var.dmarc_subdomain_policy == null ? "" : "sp=${var.dmarc_subdomain_policy}",
    length(local.dmarc_rua) == 0 ? "" : "rua=${join(",", local.dmarc_rua)}",
    var.dmarc_pct == 100 ? "" : "pct=${var.dmarc_pct}",
    var.dmarc_adkim == "r" ? "" : "adkim=${var.dmarc_adkim}",
    var.dmarc_aspf == "r" ? "" : "aspf=${var.dmarc_aspf}",
  ]))

  # ------------------------------------------------------------------------- #
  # DKIM
  # ------------------------------------------------------------------------- #

  # The Admin console value may be pasted with quotes, split into "..." "..."
  # chunks, or wrapped across lines. Reduce it to the one plain string.
  google_dkim = var.google_dkim_value == null ? null : trimspace(replace(replace(replace(var.google_dkim_value, "/\"\\s*\"/", ""), "\"", ""), "/\\s*\\n\\s*/", ""))

  m365_prefix = var.m365_initial_domain == null ? null : split(".", lower(var.m365_initial_domain))[0]

  m365_dkim_parent = local.m365_prefix == null ? null : (
    var.m365_dkim_partition == null
    ? "${local.m365_prefix}.onmicrosoft.com"
    : "${local.m365_prefix}.${var.m365_dkim_partition}-v1.dkim.mail.microsoft"
  )

  m365_dkim_targets = {
    selector1 = coalesce(var.m365_dkim_selector1_target, local.m365_dkim_parent == null ? "-" : "selector1-${local.dashed}._domainkey.${local.m365_dkim_parent}")
    selector2 = coalesce(var.m365_dkim_selector2_target, local.m365_dkim_parent == null ? "-" : "selector2-${local.dashed}._domainkey.${local.m365_dkim_parent}")
  }
  m365_dkim_ready = local.m365 && local.m365_dkim_targets.selector1 != "-" && local.m365_dkim_targets.selector2 != "-"

  # ------------------------------------------------------------------------- #
  # Optional MTA-STS / TLS-RPT
  # ------------------------------------------------------------------------- #

  tls_rpt_rua = [for a in var.tls_rpt_rua : startswith(a, "https://") || startswith(lower(a), "mailto:") ? a : "mailto:${a}"]

  # ------------------------------------------------------------------------- #
  # Every record, keyed by a fixed label so plans stay readable.
  # ------------------------------------------------------------------------- #

  apex_txt = concat(
    var.create_spf ? [local.spf_record] : [],
    var.verification_txt == null ? [] : [var.verification_txt],
    var.extra_apex_txt,
  )

  records_raw = merge(
    var.manage_mx ? {
      "MX" = { name = var.domain, type = "MX", records = local.mx }
    } : {},
    length(local.apex_txt) > 0 ? {
      "apex TXT" = { name = var.domain, type = "TXT", records = local.apex_txt }
    } : {},
    var.create_dmarc ? {
      "DMARC" = { name = "_dmarc.${var.domain}", type = "TXT", records = [local.dmarc_record] }
    } : {},
    local.google && local.google_dkim != null ? {
      "DKIM" = { name = "${var.google_dkim_selector}._domainkey.${var.domain}", type = "TXT", records = [local.google_dkim] }
    } : {},
    local.m365_dkim_ready ? {
      "DKIM selector1" = { name = "selector1._domainkey.${var.domain}", type = "CNAME", records = [local.m365_dkim_targets.selector1] }
      "DKIM selector2" = { name = "selector2._domainkey.${var.domain}", type = "CNAME", records = [local.m365_dkim_targets.selector2] }
    } : {},
    local.m365 && var.m365_autodiscover ? {
      "autodiscover" = { name = "autodiscover.${var.domain}", type = "CNAME", records = ["autodiscover.outlook.com"] }
    } : {},
    var.mta_sts_policy_id == null ? {} : {
      "MTA-STS" = { name = "_mta-sts.${var.domain}", type = "TXT", records = ["v=STSv1; id=${var.mta_sts_policy_id}"] }
    },
    length(local.tls_rpt_rua) == 0 ? {} : {
      "TLS-RPT" = { name = "_smtp._tls.${var.domain}", type = "TXT", records = ["v=TLSRPTv1; rua=${join(",", local.tls_rpt_rua)}"] }
    },
  )

  # A single DNS TXT string holds at most 255 characters. Route 53 takes longer
  # values (a 2048-bit DKIM key) as several strings, written "aaa""bbb" inside
  # one Terraform string. Receivers join them back together.
  records = {
    for k, r in local.records_raw : k => merge(r, {
      records = r.type == "TXT" ? [for v in r.records : join("\"\"", regexall(".{1,255}", v))] : r.records
    })
  }
}

data "aws_route53_zone" "this" {
  count = var.zone_id == null ? 1 : 0

  name         = coalesce(var.zone_name, var.domain)
  private_zone = false
}

resource "aws_route53_record" "this" {
  for_each = local.records

  zone_id         = local.zone_id
  name            = each.value.name
  type            = each.value.type
  ttl             = var.ttl
  records         = each.value.records
  allow_overwrite = var.replace_existing_records

  lifecycle {
    precondition {
      condition     = !var.create_spf || local.spf_lookup_count <= 10
      error_message = "The SPF record has ${local.spf_lookup_count} includes. Receivers allow at most 10 DNS lookups (nested includes count too), and treat a longer record as broken. Drop senders you no longer use, or use their IP ranges in spf_ip4/spf_ip6."
    }

    precondition {
      condition     = var.verification_txt == null || !startswith(lower(trimspace(coalesce(var.verification_txt, "-"))), "v=spf1")
      error_message = "verification_txt is an SPF record. The module writes the SPF record itself; put extra senders in spf_include_extra."
    }

    precondition {
      condition     = (var.m365_dkim_selector1_target == null) == (var.m365_dkim_selector2_target == null)
      error_message = "Set both m365_dkim_selector1_target and m365_dkim_selector2_target, or neither: Microsoft 365 DKIM needs both CNAME records."
    }

    precondition {
      condition     = var.m365_dkim_partition == null || var.m365_initial_domain != null
      error_message = "m365_dkim_partition needs m365_initial_domain (e.g. contoso.onmicrosoft.com) to build the DKIM targets."
    }
  }
}
