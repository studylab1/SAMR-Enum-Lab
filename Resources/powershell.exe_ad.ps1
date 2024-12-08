# Set up credentials
$SecurePassword = ConvertTo-SecureString "LabAdm1!" -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential ("domain-z\administrator", $SecurePassword)

# List of commands to execute
$commands = @(
    { Write-Host "Executing: Get-ADAccountAuthorizationGroup"; Get-ADAccountAuthorizationGroup -Identity "administrator" -Server "zdc1.domain-z.local" -Credential $Cred },
    { Write-Host "Executing: Get-ADAccountResultantPasswordReplicationPolicy"; Get-ADAccountResultantPasswordReplicationPolicy -Identity "administrator" -DomainController "zdc1.domain-z.local" -Credential $Cred },
    { Write-Host "Executing: Get-ADAuthenticationPolicy"; Get-ADAuthenticationPolicy -Filter * -Server "zdc1.domain-z.local" -Credential $Cred },
    { Write-Host "Executing: Get-ADAuthenticationPolicySilo"; Get-ADAuthenticationPolicySilo -Filter * -Server "zdc1.domain-z.local" -Credential $Cred },
    { Write-Host "Executing: Get-ADCentralAccessPolicy"; Get-ADCentralAccessPolicy -Filter * -Server "zdc1.domain-z.local" -Credential $Cred },
    { Write-Host "Executing: Get-ADCentralAccessRule"; Get-ADCentralAccessRule -Filter * -Server "zdc1.domain-z.local" -Credential $Cred },
    { Write-Host "Executing: Get-ADClaimTransformPolicy"; Get-ADClaimTransformPolicy -Filter * -Server "zdc1.domain-z.local" -Credential $Cred },
    { Write-Host "Executing: Get-ADClaimType"; Get-ADClaimType -Filter * -Server "zdc1.domain-z.local" -Credential $Cred },
    { Write-Host "Executing: Get-ADComputerServiceAccount"; Get-ADComputerServiceAccount -Identity "MySvcAcct" -Server "zdc1.domain-z.local" -Credential $Cred },
    { Write-Host "Executing: Get-ADDefaultDomainPasswordPolicy"; Get-ADDefaultDomainPasswordPolicy -Server "zdc1.domain-z.local" -Credential $Cred },
    { Write-Host "Executing: Get-ADDomainControllerPasswordReplicationPolicy"; Get-ADDomainControllerPasswordReplicationPolicy -Identity "zdc1.domain-z.local" -Credential $Cred },
    { Write-Host "Executing: Get-ADDomainControllerPasswordReplicationPolicyUsage"; Get-ADDomainControllerPasswordReplicationPolicyUsage -Identity "zdc1.domain-z.local" -Credential $Cred },
    { Write-Host "Executing: Get-ADFineGrainedPasswordPolicy"; Get-ADFineGrainedPasswordPolicy -Filter * -Server "zdc1.domain-z.local" -Credential $Cred },
    { Write-Host "Executing: Get-ADFineGrainedPasswordPolicySubject"; Get-ADFineGrainedPasswordPolicySubject -Identity "ExistingPolicyName" -Server "zdc1.domain-z.local" -Credential $Cred },
    { Write-Host "Executing: Get-ADObject"; Get-ADObject -Filter * -Server "zdc1.domain-z.local" -Credential $Cred },
    { Write-Host "Executing: Get-ADOptionalFeature"; Get-ADOptionalFeature -Filter * -Server "zdc1.domain-z.local" -Credential $Cred },
    { Write-Host "Executing: Get-ADOrganizationalUnit"; Get-ADOrganizationalUnit -Filter * -Server "zdc1.domain-z.local" -Credential $Cred },
    { Write-Host "Executing: Get-ADPrincipalGroupMembership"; Get-ADPrincipalGroupMembership -Identity "administrator" -Server "zdc1.domain-z.local" -Credential $Cred },
    { Write-Host "Executing: Get-ADReplicationAttributeMetadata"; Get-ADReplicationAttributeMetadata -Object "CN=Administrator,CN=Users,DC=domain-z,DC=local" -Server "zdc1.domain-z.local" -Credential $Cred },
    { Write-Host "Executing: Get-ADReplicationConnection"; Get-ADReplicationConnection -Filter * -Server "zdc1.domain-z.local" -Credential $Cred },
    { Write-Host "Executing: Get-ADReplicationFailure"; Get-ADReplicationFailure -Target "zdc1.domain-z.local" -Credential $Cred },
    { Write-Host "Executing: Get-ADReplicationPartnerMetadata"; Get-ADReplicationPartnerMetadata -Target "zdc1.domain-z.local" -Credential $Cred },
    { Write-Host "Executing: Get-ADReplicationQueueOperation"; Get-ADReplicationQueueOperation -Server "zdc1.domain-z.local" -Credential $Cred },
    { Write-Host "Executing: Get-ADReplicationSite"; Get-ADReplicationSite -Filter * -Server "zdc1.domain-z.local" -Credential $Cred },
    { Write-Host "Executing: Get-ADReplicationSiteLink"; Get-ADReplicationSiteLink -Filter * -Server "zdc1.domain-z.local" -Credential $Cred },
    { Write-Host "Executing: Get-ADReplicationSiteLinkBridge"; Get-ADReplicationSiteLinkBridge -Filter * -Server "zdc1.domain-z.local" -Credential $Cred },
    { Write-Host "Executing: Get-ADReplicationSubnet"; Get-ADReplicationSubnet -Filter * -Server "zdc1.domain-z.local" -Credential $Cred },
    { Write-Host "Executing: Get-ADResourceProperty"; Get-ADResourceProperty -Filter * -Server "zdc1.domain-z.local" -Credential $Cred },
    { Write-Host "Executing: Get-ADResourcePropertyList"; Get-ADResourcePropertyList -Filter * -Server "zdc1.domain-z.local" -Credential $Cred },
    { Write-Host "Executing: Get-ADResourcePropertyValueType"; Get-ADResourcePropertyValueType -Filter * -Server "zdc1.domain-z.local" -Credential $Cred },
    { Write-Host "Executing: Get-ADRootDSE"; Get-ADRootDSE -Server "zdc1.domain-z.local" -Credential $Cred },
    { Write-Host "Executing: Get-ADServiceAccount"; Get-ADServiceAccount -Identity "MySvcAcct" -Server "zdc1.domain-z.local" -Credential $Cred },
    { Write-Host "Executing: Get-ADTrust"; Get-ADTrust -Filter * -Server "zdc1.domain-z.local" -Credential $Cred },
    { Write-Host "Executing: Get-ADUserResultantPasswordPolicy"; Get-ADUserResultantPasswordPolicy -Identity "administrator" -Server "zdc1.domain-z.local" -Credential $Cred },
    { Write-Host "Executing: Sync-ADObjecty"; Sync-ADObject -Object "CN=Administrator,CN=Users,DC=domain-z,DC=local" -Server "zdc1.domain-z.local" -Credential $Cred },
    { Write-Host "Executing: Executing: Search-ADAccount for disabled accounts"; Search-ADAccount -AccountDisabled -Server "zdc1.domain-z.local" -Credential $Cred },
    { Write-Host "Executing: Get-ADUser"; Get-ADUser -Filter * -Server "zdc1.domain-z.local" -Credential $Cred },
    { Write-Host "Executing: Get-ADGroup"; Get-ADGroup -Filter * -Server "zdc1.domain-z.local" -Credential $Cred },
    { Write-Host "Executing: Get-ADComputer"; Get-ADComputer -Filter * -Server "zdc1.domain-z.local" -Credential $Cred },
    { Write-Host "Executing: Get-ADDomain"; Get-ADDomain -Server "zdc1.domain-z.local" -Credential $Cred },
    { Write-Host "Executing: Get-ADDomainController"; Get-ADDomainController -Filter * -Server "zdc1.domain-z.local" -Credential $Cred }
    
)

# Execute each command in sequence
foreach ($command in $commands) {
    try {
        $command.Invoke()
    } catch {
        Write-Host "Error executing command: $_"
    }
}