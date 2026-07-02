# Benchmark fixture: RDS instance with explicit misconfigurations.

resource "aws_db_instance" "exposed" {
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  storage_encrypted   = false # -> rds_encryption_required (not storage_encrypted)
  publicly_accessible = true   # -> rds_no_public_access
  backup_retention_period = 0  # -> rds_backup_required
}
