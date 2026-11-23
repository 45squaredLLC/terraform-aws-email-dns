# Google Workspace email for a domain whose DNS is in Route 53.
#
#   terraform init
#   terraform apply -var domain=yourdomain.com
#
# First run: MX, SPF and DMARC. Then generate the DKIM key in the Google Admin
# console, paste it into google_dkim_value, and apply again.

variable "domain" {
  type = string
}

provider "aws" {
  region = "us-east-1"
}

module "email_dns" {
  # From GitHub: source = "github.com/45squaredLLC/terraform-aws-email-dns?ref=v1.0.0"
  source = "../.."

  domain         = var.domain
  email_provider = "google_workspace"

  # From the Google Admin console > Apps > Google Workspace > Gmail >
  # Authenticate email. Paste the whole TXT value; long keys are split for you.
  google_dkim_value = null

  # Other services that send email as you: your newsletter tool, invoicing, etc.
  spf_include_extra = []

  # Daily DMARC reports. Use an address someone reads (or a report service).
  dmarc_rua = ["dmarc@${var.domain}"]
}

output "next_steps" {
  value = module.email_dns.next_steps
}

output "spf_record" {
  value = module.email_dns.spf_record
}

output "dmarc_record" {
  value = module.email_dns.dmarc_record
}
