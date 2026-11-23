# terraform-aws-email-dns

Keep your business email out of the spam folder. This module writes the DNS records that prove your email really comes from you, for **Google Workspace** or **Microsoft 365**, into your Route 53 hosted zone with one `terraform apply`.

**Live demo:** `email-dns-demo.45squared.com`, set up with this module. Look at its records from any terminal:

```bash
dig +short MX email-dns-demo.45squared.com
dig +short TXT email-dns-demo.45squared.com
dig +short TXT _dmarc.email-dns-demo.45squared.com
dig +short TXT google._domainkey.email-dns-demo.45squared.com
```

## Why email lands in spam

Anyone can put your address in the From line of an email. So Gmail, Outlook and every other mail service check the sender's domain for three DNS records before they trust a message. When those records are missing or wrong, your invoices, quotes and replies to customers go to spam or bounce, and nothing tells you it happened.

- **SPF** lists the servers allowed to send email for your domain.
- **DKIM** adds a signature to every message that proves it came from your domain and wasn't changed on the way.
- **DMARC** tells receivers what to do with mail that fails those checks, and sends you a daily report of who is sending as you.

Since February 2024, Gmail requires everyone sending to personal Gmail accounts to pass SPF or DKIM, and senders of more than 5,000 messages a day to have SPF, DKIM and DMARC ([Google's sender guidelines](https://support.google.com/a/answer/81126)). Outlook.com applies the same three to high-volume senders since May 2025 ([Microsoft's announcement](https://techcommunity.microsoft.com/blog/microsoftdefenderforoffice365blog/strengthening-email-ecosystem-outlook%E2%80%99s-new-requirements-for-high%E2%80%90volume-senders/4399730)). Small senders get filtered on the same signals.

## What it creates

| Record | Google Workspace | Microsoft 365 |
|---|---|---|
| MX (incoming mail) | `1 smtp.google.com` | `0 <domain-with-dashes>.mail.protection.outlook.com`, or your `mx.microsoft` host |
| SPF (apex TXT) | `v=spf1 include:_spf.google.com ~all` | `v=spf1 include:spf.protection.outlook.com ~all` |
| DKIM | TXT at `google._domainkey`, split into 255-character strings for Route 53 | CNAMEs at `selector1._domainkey` and `selector2._domainkey` |
| DMARC | `v=DMARC1; p=none; rua=...` at `_dmarc` | same |
| Verification | your `google-site-verification=` code, in the apex TXT | your `MS=ms...` code, in the apex TXT |
| Autodiscover | | CNAME `autodiscover` to `autodiscover.outlook.com` |
| MTA-STS, TLS-RPT | optional, off by default | optional, off by default |

Guard rails:

- **One SPF record.** Every sender (your mailbox provider, newsletter tool, invoicing app, website form) is merged into a single SPF value. Two SPF records break SPF for everyone, so a second `v=spf1` value is refused.
- **The 10-lookup limit.** Receivers stop after 10 DNS lookups and treat the SPF record as broken. The plan fails when the record has more than 10 includes. Includes nested inside a sender's own record count too and can't be seen at plan time, so check the finished record with a checker (see [Verify](#verify)).
- **Nothing live changes by accident.** If an MX or apex TXT record already exists, the first apply stops with an error instead of taking it over. See [Domains that already have email](#domains-that-already-have-email).
- **Long DKIM keys just work.** Paste the key from the Google Admin console as shown; quotes and line breaks are cleaned up and the value is split the way Route 53 needs.

## Quick start: Google Workspace

You need an AWS account, [Terraform](https://developer.hashicorp.com/terraform/install) 1.5 or newer, the AWS CLI signed in, and your domain's DNS in a Route 53 hosted zone.

```hcl
provider "aws" {
  region = "us-east-1"
}

module "email_dns" {
  source = "github.com/45squaredLLC/terraform-aws-email-dns?ref=v1.0.0"

  domain         = "example.com"
  email_provider = "google_workspace"

  verification_txt  = "google-site-verification=..." # from the Workspace setup, if asked
  google_dkim_value = null                           # step 2 below
  dmarc_rua         = ["dmarc@example.com"]
}

output "next_steps" {
  value = module.email_dns.next_steps
}
```

1. `terraform init && terraform apply`. This creates MX, SPF and DMARC.
2. In the Google Admin console, go to **Apps > Google Workspace > Gmail > Authenticate email**, pick the domain, and click **Generate new record** (2048-bit, prefix `google`). Paste the TXT value into `google_dkim_value` and apply again.
3. Wait for DNS to update (Google says up to 48 hours; usually much less), then click **Start authentication** on the same page.

Google's own steps: [Set up MX records](https://knowledge.workspace.google.com/admin/domains/set-up-mx-records-for-google-workspace), [Set up DKIM](https://knowledge.workspace.google.com/admin/security/set-up-dkim).

## Quick start: Microsoft 365

```hcl
module "email_dns" {
  source = "github.com/45squaredLLC/terraform-aws-email-dns?ref=v1.0.0"

  domain           = "example.com"
  email_provider   = "microsoft_365"
  verification_txt = "MS=ms12345678" # from the domain setup wizard

  # From the Defender portal (Email authentication settings > DKIM) or
  # Get-DkimSigningConfig -Identity example.com | fl Selector1CNAME,Selector2CNAME
  m365_dkim_selector1_target = "selector1-example-com._domainkey.contoso.n-v1.dkim.mail.microsoft"
  m365_dkim_selector2_target = "selector2-example-com._domainkey.contoso.n-v1.dkim.mail.microsoft"

  dmarc_rua = ["dmarc@example.com"]
}
```

Then turn on DKIM signing for the domain in the Defender portal once DNS has updated.

Microsoft's values depend on your tenant and when the domain was added, so **copy them from the admin center rather than guessing**:

- **MX.** The default is the long-standing `<domain-with-dashes>.mail.protection.outlook.com` (`example.com` becomes `example-com`). Since July 2026 Microsoft gives newly added domains an MX host under `mx.microsoft` instead (for example `example-com.o-v1.mx.microsoft`; Message Center MC1048624), and domains with DNSSEC/DANE turned on move to one too. Existing `mail.protection.outlook.com` records keep working. Compare with **Microsoft 365 admin center > Settings > Domains** and set `mx_records = ["0 <host>"]` when it differs. ([External DNS records for Microsoft 365](https://learn.microsoft.com/en-us/microsoft-365/enterprise/external-domain-name-system-records), [DANE and the mx.microsoft change](https://learn.microsoft.com/en-us/exchange/security-and-compliance/how-dane-secures-email))
- **DKIM.** Domains added from May 2025 use `selector1-<domain-with-dashes>._domainkey.<initial-domain-prefix>.<partition>-v1.dkim.mail.microsoft`, where the one-letter partition is assigned by Microsoft. Older domains use `selector1-<domain-with-dashes>._domainkey.<initial-domain-prefix>.onmicrosoft.com`. The two formats can't be mixed. If you know the parts, `m365_initial_domain` (plus `m365_dkim_partition` for the new format) builds both targets for you; explicit targets win. ([DKIM for custom domains in Microsoft 365](https://learn.microsoft.com/en-us/defender-office-365/email-authentication-dkim-configure))

## Other services that send as you

Newsletters, invoicing, booking and CRM tools often send email from your address. Add each one's SPF include (their help pages list it) so their mail passes too:

```hcl
  spf_include_extra = ["amazonses.com", "servers.mcsv.net"] # Amazon SES, Mailchimp
  spf_ip4           = ["203.0.113.10"]                      # an office server or scanner
```

Each include costs at least one of the 10 lookups. IP addresses cost none. Many services also give you their own DKIM records to add; set those up in their dashboard.

## Domains that already have email

Route 53 keeps every TXT value on the bare domain in **one record set**. Taking it over replaces all of it, so:

1. Look at what is there: `dig +short TXT example.com` and `dig +short MX example.com`.
2. Copy any value you want to keep (other site verifications) into `extra_apex_txt`. Fold the old SPF record's includes into `spf_include_extra` / `spf_ip4`; don't copy the SPF record itself.
3. Already happy with your MX records? Set `manage_mx = false` and the module leaves them alone.
4. Apply with `replace_existing_records = true`.

Tip: drop `ttl` to 300 a day before switching mail providers so a mistake can be undone quickly, then raise it again.

## DMARC rollout: none, then quarantine, then reject

Start in watch mode and tighten once the reports show every real sender passes:

1. **`dmarc_policy = "none"`** (the default) with `dmarc_rua` set. Nothing is blocked; you get daily reports. Read them for two to four weeks (a free report service makes the XML readable) and add any sender you forgot.
2. **`dmarc_policy = "quarantine"`, `dmarc_pct = 25`**, then 50, then 100. Failing mail goes to spam.
3. **`dmarc_policy = "reject"`**. Forged mail is bounced. This is what stops someone sending fake invoices in your name.

Then consider `spf_policy = "-all"`. Sending DMARC reports to an address at another domain needs that domain to accept them (an `example.com._report._dmarc` TXT record on its side); report services set that up for you.

## Inputs

| Name | Description | Default |
|---|---|---|
| `domain` | The domain you send email from. | required |
| `email_provider` | `google_workspace` or `microsoft_365`. | required |
| `zone_id` | Route 53 hosted zone ID; skips the lookup. | `null` |
| `zone_name` | Hosted zone to look up when `zone_id` is not set. | `domain` |
| `manage_mx` | Create the MX records. | `true` |
| `mx_records` | Override MX values, as `"priority host"`. | provider default |
| `google_legacy_mx` | Google: the older five-record ASPMX set. | `false` |
| `m365_autodiscover` | Microsoft 365: create the autodiscover CNAME. | `true` |
| `create_spf` | Publish the SPF record. | `true` |
| `spf_include_extra` | Other senders' SPF include domains. | `[]` |
| `spf_ip4` / `spf_ip6` | IP addresses or ranges allowed to send. | `[]` |
| `spf_policy` | `~all` (soft fail) or `-all` (hard fail). | `~all` |
| `verification_txt` | Provider's domain verification code. | `null` |
| `extra_apex_txt` | Other apex TXT values to keep. | `[]` |
| `google_dkim_selector` | Google: DKIM selector. | `google` |
| `google_dkim_value` | Google: DKIM TXT value from the Admin console. | `null` |
| `m365_dkim_selector1_target` / `m365_dkim_selector2_target` | Microsoft 365: DKIM CNAME targets. | `null` |
| `m365_initial_domain` | Microsoft 365: `contoso.onmicrosoft.com`, to build DKIM targets. | `null` |
| `m365_dkim_partition` | Microsoft 365: partition letter for the `dkim.mail.microsoft` format. | `null` |
| `create_dmarc` | Publish the DMARC record. | `true` |
| `dmarc_policy` | `none`, `quarantine` or `reject`. | `none` |
| `dmarc_subdomain_policy` | `sp=` for subdomains. | `null` (same as policy) |
| `dmarc_rua` | Addresses for daily DMARC reports. | `[]` |
| `dmarc_pct` | Percentage the policy applies to. | `100` |
| `dmarc_adkim` / `dmarc_aspf` | Alignment: `r` relaxed or `s` strict. | `r` |
| `mta_sts_policy_id` | Publish `_mta-sts` with this id (host the policy file yourself). | `null` (off) |
| `tls_rpt_rua` | Addresses for SMTP TLS reports. | `[]` (off) |
| `ttl` | TTL for every record, in seconds. | `3600` |
| `replace_existing_records` | Let Terraform take over records that already exist. | `false` |

## Outputs

| Name | Description |
|---|---|
| `records` | Every record created: name, type, values |
| `spf_record` | The SPF value |
| `spf_lookup_count` | Top-level SPF lookups (nested includes not counted) |
| `dmarc_record` | The DMARC value |
| `mx_records` | MX values |
| `zone_id` | The hosted zone used |
| `next_steps` | What is left to do by hand (turn on DKIM, check MX, tighten DMARC) |
| `checklist` | Plain-text checklist: every record, the `dig` commands to check them, and the steps left. Print it with `terraform output -raw checklist` |

## Verify

After the apply (and a few minutes for DNS):

```bash
dig +short MX example.com
dig +short TXT example.com                     # one v=spf1 value
dig +short TXT _dmarc.example.com
dig +short TXT google._domainkey.example.com   # Google
dig +short CNAME selector1._domainkey.example.com   # Microsoft 365
```

Then send a message to a Gmail address, open it, and choose **Show original**: SPF, DKIM and DMARC should each say `PASS`. Free checkers such as [Google Admin Toolbox Check MX](https://toolbox.googleapps.com/apps/checkmx/), [MXToolbox](https://mxtoolbox.com/SuperTool.aspx) and [learndmarc.com](https://www.learndmarc.com/) show the same, including the SPF lookup count with nested includes.

## MTA-STS (optional)

MTA-STS tells other mail servers to only deliver to you over an encrypted connection. It needs two parts: the `_mta-sts` TXT record (set `mta_sts_policy_id`) and a policy file served over HTTPS at `https://mta-sts.<domain>/.well-known/mta-sts.txt`. This module creates only the record. The file can be hosted with our [static-site module](https://github.com/45squaredLLC/terraform-aws-static-site). Start the policy in `mode: testing` and set `tls_rpt_rua` to get reports.

## Tests

```bash
terraform init -backend=false
terraform test    # plans every scenario against a mocked AWS provider
```

## Don't want to run it yourself?

[45Squared](https://45squared.com/?utm_source=github&utm_medium=readme&utm_campaign=terraform-aws-email-dns) builds, hosts and looks after websites and the email setup behind them for small businesses. If your quotes and invoices are landing in spam and you'd rather someone just fixed it, [we'll set this up for you](https://45squared.com/contact/?utm_source=github&utm_medium=readme&utm_campaign=terraform-aws-email-dns).

## License

MIT
