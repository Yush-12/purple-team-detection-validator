from techniques.t1059_cmd_exec import T1059CmdExec
from techniques.t1046_network_scan import T1046NetworkScan
from techniques.t1003_credential_access import T1003CredentialAccess
from techniques.t1078_account_abuse import T1078AccountAbuse
from techniques.t1566_phishing_artifact import T1566PhishingArtifact

# Registry of all available techniques
TECHNIQUE_REGISTRY = {
    "T1059": T1059CmdExec,
    "T1046": T1046NetworkScan,
    "T1003": T1003CredentialAccess,
    "T1078": T1078AccountAbuse,
    "T1566": T1566PhishingArtifact,
}
