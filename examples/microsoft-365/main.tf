# Microsoft 365 (Exchange Online) email for a domain whose DNS is in Route 53.
#
#   terraform init
#   terraform apply -var domain=yourdomain.com -var verification_txt=MS=ms12345678
#
# Copy the exact values from the Microsoft 365 admin center (Settings > Domains)
# and the Defender portal (Email authentication settings > DKIM): MX hosts and
# DKIM targets are specific to each tenant and domain.

variable "domain" {
  type = string
}

variable "verification_txt" {
  description = "The MS=ms... code from the Microsoft 365 domain setup wizard."
  type        = string
  default     = null
}

provider "aws" {
  region = "us-east-1"
}

module "email_dns" {
  # From GitHub: source = "github.com/45squaredLLC/terraform-aws-email-dns?ref=v1.0.0"
  source = "../.."

  domain           = var.domain
  email_provider   = "microsoft_365"
  verification_txt = var.verification_txt

  # The two DKIM CNAME targets, from Get-DkimSigningConfig or the Defender portal:
  # m365_dkim_selector1_target = "selector1-yourdomain-com._domainkey.contoso.n-v1.dkim.mail.microsoft"
  # m365_dkim_selector2_target = "selector2-yourdomain-com._domainkey.contoso.n-v1.dkim.mail.microsoft"

  # Newer Microsoft 365 domains (and any with DNSSEC on) use an mx.microsoft MX host.
  # If the admin center shows one, set it here:
  # mx_records = ["0 yourdomain-com.o-v1.mx.microsoft"]

  dmarc_rua = ["dmarc@${var.domain}"]
}

output "next_steps" {
  value = module.email_dns.next_steps
}

output "records" {
  value = module.email_dns.records
}
