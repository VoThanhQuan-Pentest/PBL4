output "website_http_url" {
  description = "Lab-only HTTP URL. Tester security-group CIDRs control access."
  value       = "http://${aws_eip.web.public_ip}"
}

output "web_elastic_ip" {
  description = "Stable public IP for the Web EC2."
  value       = aws_eip.web.public_ip
}

output "monitor_elastic_ip" {
  description = "Stable public IP for administrator SSH to Monitor."
  value       = aws_eip.monitor.public_ip
}

output "web_instance_id" {
  value       = aws_instance.web.id
  description = "Web EC2 instance ID."
}

output "monitor_instance_id" {
  value       = aws_instance.monitor.id
  description = "Monitor EC2 instance ID."
}

output "logstash_private_endpoint" {
  description = "Filebeat mTLS destination; reachable only from the Web security group."
  value       = "${local.monitor_private_ip}:5044"
}

output "ssh_web_command" {
  description = "Use an ssh-agent or your local private key; Terraform never receives that private key."
  value       = "ssh ubuntu@${aws_eip.web.public_ip}"
}

output "ssh_monitor_command" {
  description = "Use an ssh-agent or your local private key; Terraform never receives that private key."
  value       = "ssh ubuntu@${aws_eip.monitor.public_ip}"
}

output "kibana_tunnel_command" {
  description = "Kibana has no Internet-facing security-group rule; access it through this SSH tunnel."
  value       = "ssh -L 5601:127.0.0.1:5601 ubuntu@${aws_eip.monitor.public_ip}"
}
