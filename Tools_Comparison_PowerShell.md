# Active Directory Module Cmdlets: Protocol Observations

Cmdlets from the **Active Directory module** in PowerShell did not use the SAMR for communication. Instead, these cmdlets primarily relied on the **Microsoft .NET Naming Service (MS-NNS)** and **Microsoft .NET Message Framing Protocol (MS-NMF)** for their operations.

## Explanation of MS-NNS and MS-NMF Protocols

1. **Microsoft .NET Naming Service (MS-NNS):**
   - MS-NNS is a protocol for accessing and managing objects within Microsoft’s Directory Service framework.
   - It supports communication between the client and the Active Directory by using a .NET-based directory service API.

2. **Microsoft .NET Message Framing Protocol (MS-NMF):**
   - MS-NMF is a protocol designed for packaging and exchanging data between applications over a network.
   - This protocol structures the communication between the PowerShell client and the server to ensure reliable transmission of requests and responses.
   
## Execution Details
The cmdlets and parameters used during testing are listed below. These commands targeted a domain controller in a foreign forest using cross-forest authentication with explicitly defined credentials. Each command’s parameters were selected to evaluate the cmdlets’ behavior.

### Commands Executed

# List of Executed Commands with Parameters

1. **Get-ADAccountAuthorizationGroup**
   - `-Identity "administrator"`
   - `-Server "zdc1.domain-z.local"`
   - `-Credential $Cred`

2. **Get-ADAccountResultantPasswordReplicationPolicy**
   - `-Identity "administrator"`
   - `-DomainController "zdc1.domain-z.local"`
   - `-Credential $Cred`

3. **Get-ADAuthenticationPolicy**
   - `-Filter *`
   - `-Server "zdc1.domain-z.local"`
   - `-Credential $Cred`

4. **Get-ADAuthenticationPolicySilo**
   - `-Filter *`
   - `-Server "zdc1.domain-z.local"`
   - `-Credential $Cred`

5. **Get-ADCentralAccessPolicy**
   - `-Filter *`
   - `-Server "zdc1.domain-z.local"`
   - `-Credential $Cred`

6. **Get-ADCentralAccessRule**
   - `-Filter *`
   - `-Server "zdc1.domain-z.local"`
   - `-Credential $Cred`

7. **Get-ADClaimTransformPolicy**
   - `-Filter *`
   - `-Server "zdc1.domain-z.local"`
   - `-Credential $Cred`

8. **Get-ADClaimType**
   - `-Filter *`
   - `-Server "zdc1.domain-z.local"`
   - `-Credential $Cred`

9. **Get-ADComputerServiceAccount**
   - `-Identity "MySvcAcct"`
   - `-Server "zdc1.domain-z.local"`
   - `-Credential $Cred`

10. **Get-ADDefaultDomainPasswordPolicy**
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

11. **Get-ADDomainControllerPasswordReplicationPolicy**
    - `-Identity "zdc1.domain-z.local"`
    - `-Credential $Cred`

12. **Get-ADDomainControllerPasswordReplicationPolicyUsage**
    - `-Identity "zdc1.domain-z.local"`
    - `-Credential $Cred`

13. **Get-ADFineGrainedPasswordPolicy**
    - `-Filter *`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

14. **Get-ADFineGrainedPasswordPolicySubject**
    - `-Identity "ExistingPolicyName"`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

15. **Get-ADObject**
    - `-Filter *`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

16. **Get-ADOptionalFeature**
    - `-Filter *`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

17. **Get-ADOrganizationalUnit**
    - `-Filter *`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

18. **Get-ADPrincipalGroupMembership**
    - `-Identity "administrator"`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

19. **Get-ADReplicationAttributeMetadata**
    - `-Object "CN=Administrator,CN=Users,DC=domain-z,DC=local"`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

20. **Get-ADReplicationConnection**
    - `-Filter *`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

21. **Get-ADReplicationFailure**
    - `-Target "zdc1.domain-z.local"`
    - `-Credential $Cred`

22. **Get-ADReplicationPartnerMetadata**
    - `-Target "zdc1.domain-z.local"`
    - `-Credential $Cred`

23. **Get-ADReplicationQueueOperation**
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

24. **Get-ADReplicationSite**
    - `-Filter *`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

25. **Get-ADReplicationSiteLink**
    - `-Filter *`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

26. **Get-ADReplicationSiteLinkBridge**
    - `-Filter *`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

27. **Get-ADReplicationSubnet**
    - `-Filter *`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

28. **Get-ADResourceProperty**
    - `-Filter *`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

29. **Get-ADResourcePropertyList**
    - `-Filter *`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

30. **Get-ADResourcePropertyValueType**
    - `-Filter *`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

31. **Get-ADRootDSE**
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

32. **Get-ADServiceAccount**
    - `-Identity "MySvcAcct"`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

33. **Get-ADTrust**
    - `-Filter *`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

34. **Get-ADUserResultantPasswordPolicy**
    - `-Identity "administrator"`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

35. **Sync-ADObject**
    - `-Object "CN=Administrator,CN=Users,DC=domain-z,DC=local"`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

36. **Search-ADAccount**
    - `-AccountDisabled`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

37. **Get-ADUser**
    - `-Filter *`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

38. **Get-ADGroup**
    - `-Filter *`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

39. **Get-ADComputer**
    - `-Filter *`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

40. **Get-ADDomain**
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

41. **Get-ADDomainController**
    - `-Filter *`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

42. **Get-ADGroupMember**
    - `-Identity "Domain Admins"`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`
