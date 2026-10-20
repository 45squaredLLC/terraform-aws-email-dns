output "records" {
  description = "Every record the module manages: name, type and values (long TXT values shown as Route 53 stores them, split into 255-character strings)."
  value = {
    for k, r in aws_route53_record.this : k => {
      name    = r.name
      type    = r.type
      records = r.records
    }
  }
}

output "spf_record" {
  description = "The SPF value published at the domain (null when create_spf is false)."
  value       = var.create_spf ? local.spf_record : null
}

output "spf_lookup_count" {
  description = "DNS lookups the SPF record makes at the top level (one per include). Includes nested inside those domains add more; the limit is 10 in total."
  value       = local.spf_lookup_count
}

output "dmarc_record" {
  description = "The DMARC value published at _dmarc.<domain> (null when create_dmarc is false)."
  value       = var.create_dmarc ? local.dmarc_record : null
}

output "mx_records" {
  description = "MX values as \"priority host\" (empty when manage_mx is false)."
  value       = var.manage_mx ? local.mx : []
}

output "zone_id" {
  description = "Route 53 hosted zone the records are in."
  value       = local.zone_id
}

output "next_steps" {
  description = "What is left to do by hand once DNS has propagated."
  value       = local.next_steps
}

output "checklist" {
  description = "A plain-text checklist to paste into a ticket or hand to a client: every record (as you would type it into any DNS host), the dig commands that check them, and what is left to do by hand."
  value       = local.checklist
}
