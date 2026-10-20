variable "domain" {
  description = "The domain you send email from, e.g. example.com. A subdomain such as mail.example.com works too (set zone_name)."
  type        = string

  validation {
    condition     = can(regex("^([a-z0-9]([a-z0-9-]*[a-z0-9])?\\.)+[a-z]{2,63}$", var.domain))
    error_message = "domain must be a lowercase domain name without a trailing dot, e.g. example.com."
  }
}

variable "email_provider" {
  description = "Who hosts your mailboxes: \"google_workspace\" or \"microsoft_365\" (Microsoft 365 / Exchange Online)."
  type        = string

  validation {
    condition     = contains(["google_workspace", "microsoft_365"], var.email_provider)
    error_message = "email_provider must be \"google_workspace\" or \"microsoft_365\"."
  }
}

variable "zone_id" {
  description = "Route 53 hosted zone ID to put the records in. Leave null to look the zone up by zone_name."
  type        = string
  default     = null
}

variable "zone_name" {
  description = "Route 53 hosted zone to look up when zone_id is not set. Defaults to the domain itself; set it when domain is a subdomain (domain = mail.example.com, zone_name = example.com)."
  type        = string
  default     = null
}

# --------------------------------------------------------------------------- #
# MX: where incoming mail goes
# --------------------------------------------------------------------------- #

variable "manage_mx" {
  description = "Create the MX records. Set false to leave MX records that already exist alone (they are managed somewhere else, or mail is already flowing and you only want SPF, DKIM and DMARC)."
  type        = bool
  default     = true
}

variable "mx_records" {
  description = "Override the MX values, as \"priority host\" strings, e.g. [\"0 example-com.o-v1.mx.microsoft\"]. Leave null for the provider default. Newer Microsoft 365 domains (and any with DNSSEC turned on) use an mx.microsoft host: copy the value your admin center shows."
  type        = list(string)
  default     = null

  validation {
    condition     = var.mx_records == null ? true : alltrue([for r in var.mx_records : can(regex("^[0-9]{1,5} [A-Za-z0-9.-]+$", r))])
    error_message = "Each mx_records entry must be \"priority host\", e.g. \"1 smtp.google.com\"."
  }
}

variable "google_legacy_mx" {
  description = "Google only: publish the older five-record ASPMX set instead of the single smtp.google.com record. Both work; only use this to match a setup that already exists."
  type        = bool
  default     = false
}

variable "m365_autodiscover" {
  description = "Microsoft 365 only: create the autodiscover CNAME so Outlook finds the mailbox settings on its own."
  type        = bool
  default     = true
}

# --------------------------------------------------------------------------- #
# Apex TXT: SPF and verification codes (one record set holds them all)
# --------------------------------------------------------------------------- #

variable "create_spf" {
  description = "Publish an SPF record listing who may send email for the domain."
  type        = bool
  default     = true
}

variable "spf_include_extra" {
  description = "Other services that send email as your domain (newsletters, invoicing, your website's form), as SPF include domains, e.g. [\"amazonses.com\", \"servers.mcsv.net\"]. They are merged into the single SPF record."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for d in var.spf_include_extra : can(regex("^(include:)?[A-Za-z0-9_.-]+\\.[A-Za-z]{2,63}$", d))])
    error_message = "spf_include_extra entries must be domain names such as amazonses.com (an include: prefix is allowed)."
  }
}

variable "spf_ip4" {
  description = "IPv4 addresses or ranges allowed to send for the domain (an office mail server, a printer that emails scans). These cost no DNS lookups."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for ip in var.spf_ip4 : can(cidrhost(strcontains(ip, "/") ? ip : "${ip}/32", 0))])
    error_message = "spf_ip4 entries must be IPv4 addresses or CIDR ranges."
  }
}

variable "spf_ip6" {
  description = "IPv6 addresses or ranges allowed to send for the domain."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for ip in var.spf_ip6 : can(cidrhost(strcontains(ip, "/") ? ip : "${ip}/128", 0))])
    error_message = "spf_ip6 entries must be IPv6 addresses or CIDR ranges."
  }
}

variable "spf_policy" {
  description = "What receivers should do with mail from a server not on the list: \"~all\" (soft fail, the safe start) or \"-all\" (hard fail, once you are sure every sender is listed)."
  type        = string
  default     = "~all"

  validation {
    condition     = contains(["~all", "-all"], var.spf_policy)
    error_message = "spf_policy must be \"~all\" or \"-all\"."
  }
}

variable "verification_txt" {
  description = "Domain verification code from your provider's setup wizard, e.g. \"google-site-verification=...\" or \"MS=ms12345678\". Added to the apex TXT record next to SPF."
  type        = string
  default     = null
}

variable "extra_apex_txt" {
  description = "Other TXT values that already live on the domain itself (other site verifications, for example). Route 53 keeps every apex TXT value in one record set, so anything not listed here is removed when replace_existing_records is true."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for v in var.extra_apex_txt : !startswith(lower(trimspace(v)), "v=spf1")])
    error_message = "Don't put an SPF record in extra_apex_txt: a domain may only have one. Add its includes to spf_include_extra, spf_ip4 or spf_ip6 instead."
  }
}

# --------------------------------------------------------------------------- #
# DKIM: the signature that proves a message wasn't forged or altered
# --------------------------------------------------------------------------- #

variable "google_dkim_selector" {
  description = "Google only: the DKIM selector (the \"prefix\" in the Admin console). Google's default is \"google\"."
  type        = string
  default     = "google"
}

variable "google_dkim_value" {
  description = "Google only: the DKIM TXT value from Admin console > Apps > Google Workspace > Gmail > Authenticate email, starting \"v=DKIM1;\". Paste it as shown; quotes and line breaks are cleaned up and long keys are split for Route 53. Leave null until you have generated the key."
  type        = string
  default     = null

  validation {
    condition     = var.google_dkim_value == null ? true : startswith(trimspace(replace(var.google_dkim_value, "\"", "")), "v=DKIM1")
    error_message = "google_dkim_value must be the TXT value from the Admin console, starting with v=DKIM1."
  }
}

variable "m365_dkim_selector1_target" {
  description = "Microsoft 365 only: where selector1._domainkey points (the Selector1CNAME value in the Defender portal or Get-DkimSigningConfig). Takes precedence over m365_initial_domain."
  type        = string
  default     = null
}

variable "m365_dkim_selector2_target" {
  description = "Microsoft 365 only: where selector2._domainkey points (the Selector2CNAME value)."
  type        = string
  default     = null
}

variable "m365_initial_domain" {
  description = "Microsoft 365 only: your tenant's initial domain, e.g. contoso.onmicrosoft.com, used to build the two DKIM CNAME targets when the selector targets are not given."
  type        = string
  default     = null

  validation {
    condition     = var.m365_initial_domain == null ? true : can(regex("^[a-z0-9-]+(\\.onmicrosoft\\.com)?$", lower(var.m365_initial_domain)))
    error_message = "m365_initial_domain must look like contoso.onmicrosoft.com (or just contoso)."
  }
}

variable "m365_dkim_partition" {
  description = "Microsoft 365 only: the one-letter partition in DKIM targets ending -v1.dkim.mail.microsoft (e.g. \"n\" in contoso.n-v1.dkim.mail.microsoft). Domains added from May 2025 use this format; leave null for the older <prefix>.onmicrosoft.com format."
  type        = string
  default     = null

  validation {
    condition     = var.m365_dkim_partition == null ? true : can(regex("^[a-z0-9]$", var.m365_dkim_partition))
    error_message = "m365_dkim_partition is a single letter or digit, e.g. \"n\" or \"r\"."
  }
}

# --------------------------------------------------------------------------- #
# DMARC: the policy that tells receivers what to do with forged mail
# --------------------------------------------------------------------------- #

variable "create_dmarc" {
  description = "Publish a DMARC record at _dmarc.<domain>."
  type        = bool
  default     = true
}

variable "dmarc_policy" {
  description = "What receivers should do with mail that fails SPF and DKIM alignment: \"none\" (watch only, the safe start), \"quarantine\" (spam folder) or \"reject\" (bounce)."
  type        = string
  default     = "none"

  validation {
    condition     = contains(["none", "quarantine", "reject"], var.dmarc_policy)
    error_message = "dmarc_policy must be none, quarantine or reject."
  }
}

variable "dmarc_subdomain_policy" {
  description = "Policy for subdomains (sp=). Leave null to apply dmarc_policy to subdomains too."
  type        = string
  default     = null

  validation {
    condition     = var.dmarc_subdomain_policy == null ? true : contains(["none", "quarantine", "reject"], var.dmarc_subdomain_policy)
    error_message = "dmarc_subdomain_policy must be null, none, quarantine or reject."
  }
}

variable "dmarc_rua" {
  description = "Addresses that receive the daily DMARC summary reports, e.g. [\"dmarc@example.com\"]. A mailto: prefix is added when missing. Strongly recommended: the reports are how you learn it is safe to move to quarantine."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for a in var.dmarc_rua : can(regex("^(mailto:)?[^@\\s,;]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,63}$", a))])
    error_message = "dmarc_rua entries must be email addresses (optionally prefixed mailto:)."
  }
}

variable "dmarc_pct" {
  description = "Percentage of failing mail the policy applies to (pct=). Lower it while stepping up to quarantine or reject; 100 is left out of the record because it is the default."
  type        = number
  default     = 100

  validation {
    condition     = var.dmarc_pct >= 0 && var.dmarc_pct <= 100 && floor(var.dmarc_pct) == var.dmarc_pct
    error_message = "dmarc_pct must be a whole number from 0 to 100."
  }
}

variable "dmarc_adkim" {
  description = "DKIM alignment: \"r\" (relaxed, subdomains count; the default) or \"s\" (strict, exact domain only)."
  type        = string
  default     = "r"

  validation {
    condition     = contains(["r", "s"], var.dmarc_adkim)
    error_message = "dmarc_adkim must be \"r\" or \"s\"."
  }
}

variable "dmarc_aspf" {
  description = "SPF alignment: \"r\" (relaxed; the default) or \"s\" (strict)."
  type        = string
  default     = "r"

  validation {
    condition     = contains(["r", "s"], var.dmarc_aspf)
    error_message = "dmarc_aspf must be \"r\" or \"s\"."
  }
}

# --------------------------------------------------------------------------- #
# Optional: MTA-STS and TLS reporting (encrypted delivery to you)
# --------------------------------------------------------------------------- #

variable "mta_sts_policy_id" {
  description = "Publish the _mta-sts TXT record with this policy id (letters and digits, change it whenever the policy changes, e.g. \"20261020\"). Off when null. You must also host the policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt; this module does not."
  type        = string
  default     = null

  validation {
    condition     = var.mta_sts_policy_id == null ? true : can(regex("^[A-Za-z0-9]{1,32}$", var.mta_sts_policy_id))
    error_message = "mta_sts_policy_id must be 1 to 32 letters and digits."
  }
}

variable "tls_rpt_rua" {
  description = "Addresses for SMTP TLS reports (_smtp._tls TXT record). Off when empty. A mailto: prefix is added to plain email addresses; https:// endpoints are kept as they are."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for a in var.tls_rpt_rua : can(regex("^((mailto:)?[^@\\s,;]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,63}|https://\\S+)$", a))])
    error_message = "tls_rpt_rua entries must be email addresses or https:// URLs."
  }
}

# --------------------------------------------------------------------------- #
# General
# --------------------------------------------------------------------------- #

variable "ttl" {
  description = "Time to live for every record, in seconds. 3600 (an hour) is a good default; drop it to 300 a day before a change you may want to undo quickly."
  type        = number
  default     = 3600

  validation {
    condition     = var.ttl >= 60 && var.ttl <= 86400
    error_message = "ttl must be between 60 and 86400 seconds."
  }
}

variable "replace_existing_records" {
  description = "Let Terraform take over records that already exist (an old MX, an apex TXT with an old SPF or verification codes). Leave false on the first run: the apply then stops at any existing record instead of changing live mail. Before turning it on, copy the apex TXT values you want to keep into extra_apex_txt."
  type        = bool
  default     = false
}
