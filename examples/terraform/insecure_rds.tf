# RDS instance without encryption (violation: rds-no-encryption)
resource "aws_db_instance" "unencrypted_db" {
  identifier     = "prod-database"
  engine         = "mysql"
  engine_version = "8.0"
  instance_class = "db.t3.micro"
  
  allocated_storage = 20
  storage_encrypted = false  # VIOLATION: No encryption
  
  username = "admin"
  password = "changeme123!"
}

# RDS instance with public access (violation: rds-public-access)
resource "aws_db_instance" "public_db" {
  identifier     = "public-webapp-db"
  engine         = "postgres"
  engine_version = "13"
  instance_class = "db.t3.small"
  
  allocated_storage    = 50
  publicly_accessible  = true  # VIOLATION: Publicly accessible
  
  username = "dbadmin"
  password = "postgres123!"
}

# RDS instance without backup (violation: rds-no-backup)
resource "aws_db_instance" "no_backup_db" {
  identifier     = "temp-database"
  engine         = "mysql"
  engine_version = "8.0"
  instance_class = "db.t3.micro"
  
  allocated_storage       = 20
  backup_retention_period = 0  # VIOLATION: Backups disabled
  
  username = "root"
  password = "mysql123!"
}

# RDS instance with short backup retention (violation: rds-short-backup)
resource "aws_db_instance" "short_backup_db" {
  identifier     = "app-database"
  engine         = "postgres"
  engine_version = "14"
  instance_class = "db.t3.medium"
  
  allocated_storage       = 100
  backup_retention_period = 3  # VIOLATION: Less than 7 days
  
  username = "appuser"
  password = "apppass123!"
}

# Production RDS without Multi-AZ (violation: rds-no-multi-az)
resource "aws_db_instance" "prod_no_multi_az" {
  identifier     = "production-main-db"
  engine         = "mysql"
  engine_version = "8.0"
  instance_class = "db.r5.large"
  
  allocated_storage = 500
  multi_az         = false  # VIOLATION: No Multi-AZ for production
  
  username = "prodadmin"
  password = "productionpass123!"
  
  tags = {
    Environment = "production"
  }
}

# Production RDS without deletion protection (violation: rds-no-deletion-protection)
resource "aws_db_instance" "prod_no_protection" {
  identifier     = "production-critical-db"
  engine         = "postgres"
  engine_version = "14"
  instance_class = "db.r5.xlarge"
  
  allocated_storage     = 1000
  deletion_protection   = false  # VIOLATION: No deletion protection
  
  username = "admin"
  password = "critical123!"
  
  tags = {
    Environment = "production"
  }
}

# RDS without IAM authentication (violation: rds-no-iam-auth)
resource "aws_db_instance" "no_iam_auth" {
  identifier     = "secure-database"
  engine         = "mysql"
  engine_version = "8.0"
  instance_class = "db.t3.large"
  
  allocated_storage                   = 100
  iam_database_authentication_enabled = false  # VIOLATION: IAM auth disabled
  
  username = "dbuser"
  password = "dbpass123!"
}

# Production RDS without performance insights (violation: rds-no-performance-insights)
resource "aws_db_instance" "prod_no_insights" {
  identifier     = "production-analytics-db"
  engine         = "postgres"
  engine_version = "14"
  instance_class = "db.r5.2xlarge"
  
  allocated_storage           = 2000
  performance_insights_enabled = false  # VIOLATION: No performance insights
  
  username = "analytics"
  password = "analytics123!"
  
  tags = {
    Environment = "production"
  }
}

# RDS without log exports (violation: rds-no-log-exports)
resource "aws_db_instance" "no_logs" {
  identifier     = "audit-database"
  engine         = "mysql"
  engine_version = "8.0"
  instance_class = "db.t3.medium"
  
  allocated_storage = 200
  # VIOLATION: No enabled_cloudwatch_logs_exports
  
  username = "audituser"
  password = "audit123!"
}

# RDS with default parameter group (violation: rds-default-parameter-group)
resource "aws_db_instance" "default_params" {
  identifier     = "app-database-default"
  engine         = "postgres"
  engine_version = "14"
  instance_class = "db.t3.small"
  
  allocated_storage      = 50
  parameter_group_name   = "default.postgres14"  # VIOLATION: Default parameter group
  
  username = "appuser"
  password = "apppass123!"
}

# RDS cluster without encryption (violation: rds-cluster-no-encryption)
resource "aws_rds_cluster" "unencrypted_cluster" {
  cluster_identifier = "aurora-cluster"
  engine            = "aurora-mysql"
  engine_version    = "5.7.mysql_aurora.2.10.1"
  
  master_username = "admin"
  master_password = "aurora123!"
  
  storage_encrypted = false  # VIOLATION: No encryption
}

# RDS cluster without backup (violation: rds-cluster-no-backup)
resource "aws_rds_cluster" "no_backup_cluster" {
  cluster_identifier = "test-aurora-cluster"
  engine            = "aurora-postgresql"
  engine_version    = "13.6"
  
  master_username = "postgres"
  master_password = "postgres123!"
  
  backup_retention_period = 0  # VIOLATION: Backups disabled
}

# Unencrypted DB snapshot (violation: rds-snapshot-no-encryption)
resource "aws_db_snapshot" "unencrypted_snapshot" {
  db_instance_identifier = "source-database"
  db_snapshot_identifier = "manual-snapshot-2024"
  
  encrypted = false  # VIOLATION: Snapshot not encrypted
}

# Public DB snapshot (violation: rds-snapshot-public)
resource "aws_db_snapshot" "public_snapshot" {
  db_instance_identifier = "shared-database"
  db_snapshot_identifier = "public-backup-2024"
  
  restore = ["all"]  # VIOLATION: Public snapshot
}