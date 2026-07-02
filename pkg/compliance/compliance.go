// Package compliance maps PolicyGuard policy IDs to the standardized weakness
// and control identifiers a security reviewer expects (CWE today; CIS/NIST are
// scaffolded for later).
//
// The mapping is deliberately conservative: an entry exists only where the
// weakness class is unambiguous. A policy with no confident mapping returns no
// identifiers rather than a guessed one — an invented CWE is worse than none,
// because it signals false rigor. Coverage is meant to grow as mappings are
// verified, not to be padded.
package compliance

// Mapping holds the standardized identifiers associated with a policy.
type Mapping struct {
	// CWE holds Common Weakness Enumeration IDs in "CWE-NNN" form.
	CWE []string
	// CIS and NIST are reserved for future expansion; populated only when a
	// mapping is verified, never guessed.
	CIS  []string
	NIST []string
}

// CWE identifiers used below, named so the mapping reads as intent rather than
// numbers.
const (
	cweCleartextTransmission = "CWE-319" // Cleartext Transmission of Sensitive Information
	cweMissingEncryption     = "CWE-311" // Missing Encryption of Sensitive Data
	cweExposure              = "CWE-200" // Exposure of Sensitive Information to an Unauthorized Actor
	cweWrongSphere           = "CWE-668" // Exposure of Resource to Wrong Sphere
	cweAccessControl         = "CWE-284" // Improper Access Control
	cwePermissionAssignment  = "CWE-732" // Incorrect Permission Assignment for Critical Resource
	cwePrivilegeMgmt         = "CWE-269" // Improper Privilege Management
	cweSSRF                  = "CWE-918" // Server-Side Request Forgery
	cweInsufficientLogging   = "CWE-778" // Insufficient Logging
	cweKeyManagement         = "CWE-320" // Key Management Errors
)

// mappings is keyed by the policy_id emitted in violations. Only confident
// entries are included; everything else intentionally has no CWE.
var mappings = map[string]Mapping{
	// --- S3 ---
	"s3_bucket_encryption":    {CWE: []string{cweMissingEncryption}},
	"s3_bucket_public_access": {CWE: []string{cweExposure, cweAccessControl}},
	"s3_bucket_logging":       {CWE: []string{cweInsufficientLogging}},

	// --- EC2 / EBS ---
	"ec2_instance_encryption": {CWE: []string{cweMissingEncryption}},
	"ebs_volume_encryption":   {CWE: []string{cweMissingEncryption}},
	"ec2_instance_public_ip":  {CWE: []string{cweWrongSphere}},
	"ec2_instance_imdsv2":     {CWE: []string{cweSSRF}},

	// --- Security groups ---
	"security_group_ssh_open":     {CWE: []string{cweAccessControl}},
	"security_group_unrestricted": {CWE: []string{cweAccessControl}},

	// --- RDS ---
	"rds_encryption_required":  {CWE: []string{cweMissingEncryption}},
	"rds_no_public_access":     {CWE: []string{cweWrongSphere}},
	"rds_cluster_encryption":   {CWE: []string{cweMissingEncryption}},
	"rds_snapshot_encryption":  {CWE: []string{cweMissingEncryption}},
	"rds_snapshot_not_public":  {CWE: []string{cweExposure}},
	"rds_cloudwatch_logs":      {CWE: []string{cweInsufficientLogging}},
	"rds_performance_insights": {CWE: []string{cweInsufficientLogging}},

	// --- IAM ---
	"iam_no_wildcard_actions":   {CWE: []string{cwePrivilegeMgmt}},
	"iam_no_wildcard_resources": {CWE: []string{cwePermissionAssignment}},
	"iam_no_inline_policies":    {CWE: []string{cwePrivilegeMgmt}},

	// --- KMS ---
	"kms_key_rotation":        {CWE: []string{cweKeyManagement}},
	"kms_deletion_protection": {CWE: []string{cweKeyManagement}},

	// --- Encryption at rest across services ---
	"dynamodb_encryption":  {CWE: []string{cweMissingEncryption}},
	"sns_topic_encryption": {CWE: []string{cweMissingEncryption}},
	"sqs_queue_encryption": {CWE: []string{cweMissingEncryption}},
	"ecr_encryption":       {CWE: []string{cweMissingEncryption}},

	// --- Encryption in transit ---
	"sns_encryption_in_transit":     {CWE: []string{cweCleartextTransmission}},
	"api_gateway_https_enforcement": {CWE: []string{cweCleartextTransmission}},
	"alb_https_listener":            {CWE: []string{cweCleartextTransmission}},
	"alb_http_redirect":             {CWE: []string{cweCleartextTransmission}},

	// --- Logging / audit ---
	"cloudtrail_encryption":     {CWE: []string{cweMissingEncryption}},
	"api_gateway_logging":       {CWE: []string{cweInsufficientLogging}},
	"alb_access_logging":        {CWE: []string{cweInsufficientLogging}},
	"vpc-flow-logs-required":    {CWE: []string{cweInsufficientLogging}},
	"cloudtrail_log_validation": {CWE: []string{cweInsufficientLogging}},

	// --- ECR exposure ---
	"ecr_access_control": {CWE: []string{cweAccessControl}},

	// --- Lambda ---
	"lambda-encrypt-env-vars": {CWE: []string{cweMissingEncryption}},
	"lambda-no-public-access": {CWE: []string{cweAccessControl}},
	"lambda-least-privilege":  {CWE: []string{cwePrivilegeMgmt}},

	// --- Azure: Storage ---
	"azure_storage_https_only":    {CWE: []string{cweCleartextTransmission}},
	"azure_storage_min_tls":       {CWE: []string{cweCleartextTransmission}},
	"azure_storage_public_access": {CWE: []string{cweExposure, cweAccessControl}},

	// --- Azure: Network ---
	"azure_nsg_admin_ports": {CWE: []string{cweAccessControl}},

	// --- Azure: SQL ---
	"azure_sql_public_access": {CWE: []string{cweWrongSphere}},
	"azure_sql_min_tls":       {CWE: []string{cweCleartextTransmission}},
}

// cweTitles gives the human-readable name for each CWE used in the mapping, so
// reports can show "CWE-311 (Missing Encryption of Sensitive Data)" rather than
// a bare identifier. Keyed by CWE ID.
var cweTitles = map[string]string{
	cweCleartextTransmission: "Cleartext Transmission of Sensitive Information",
	cweMissingEncryption:     "Missing Encryption of Sensitive Data",
	cweExposure:              "Exposure of Sensitive Information to an Unauthorized Actor",
	cweWrongSphere:           "Exposure of Resource to Wrong Sphere",
	cweAccessControl:         "Improper Access Control",
	cwePermissionAssignment:  "Incorrect Permission Assignment for Critical Resource",
	cwePrivilegeMgmt:         "Improper Privilege Management",
	cweSSRF:                  "Server-Side Request Forgery (SSRF)",
	cweInsufficientLogging:   "Insufficient Logging",
	cweKeyManagement:         "Key Management Errors",
}

// CWETitle returns the human-readable name for a CWE ID, or "" if unknown.
func CWETitle(cwe string) string {
	return cweTitles[cwe]
}

// For returns the mapping for a policy ID. The second return value is false when
// no confident mapping exists; callers should emit no identifiers in that case
// rather than substituting a placeholder.
func For(policyID string) (Mapping, bool) {
	m, ok := mappings[policyID]
	return m, ok
}

// CWEsFor returns just the CWE IDs for a policy, or nil if unmapped.
func CWEsFor(policyID string) []string {
	if m, ok := mappings[policyID]; ok {
		return m.CWE
	}
	return nil
}
