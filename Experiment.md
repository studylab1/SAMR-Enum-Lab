(In progress)

<table cellpadding="4" cellspacing="0">
  <thead>
    <tr>
      <th>Scenario ID</th>  <!-- 1 -->
      <th>Forest Trust Type</th>  <!-- 2 -->
      <th>Enumerated Object Name</th>  <!-- 3 -->
      <th>Enumerated Object Class</th>  <!-- 4 -->
      <th>Member of</th>  <!-- 5 -->
      <th>Access</th>  <!-- 6 -->
      <th>Access Type</th>  <!-- 7 -->
      <th>Access Applied to</th>  <!-- 8 -->
      <th>OpNums</th>  <!-- 9 -->
      <th>Error in SAMR Traffic</th>  <!-- 10 -->
      <th>Results</th>  <!-- 11 -->
      <th>Notes</th>  <!-- 12 --> 
      <th>Execution</th>  <!-- 13 -->
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>acl0/1</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>UserB1</td> <!-- Enumerated Object Name -->
      <td>user</td>  <!-- Enumerated Object Class -->
      <td>Domain Users</td> <!-- Member of -->
      <td>Default</td>  <!-- Access -->
      <td>N/A</td> <!-- Access Type -->
      <td>N/A</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 17, 34, 47, 3, 1.</td> <!-- OpNums -->
      <td>No</td>  <!-- Errors in Traffic -->
      <td>Object and its attributes are returned</td> <!-- Results -->
      <td>Regular account</td>  <!-- Notes -->
      <td>python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! enumerate=account-details user=userb1 acl</td> <!-- Execution -->
    </tr>
    <tr>
      <td>acl0/2</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>UserB3</td> <!-- Enumerated Object Name -->
      <td>user</td>  <!-- Enumerated Object Class -->
      <td>Domain Users</td> <!-- Member of -->
      <td>Default</td>  <!-- Access -->
      <td>N/A</td> <!-- Access Type -->
      <td>N/A</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 17, 34, 47, 3, 1</td> <!-- OpNums -->
      <td>No</td>  <!-- Errors in Traffic -->
      <td>Object and its attributes are returned</td> <!-- Results -->
      <td>Disabled account</td>  <!-- Notes -->
      <td>python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! enumerate=account-details user=userb3 acl</td> <!-- Execution -->
    </tr>
    <tr>
      <td>acl0/3</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>Guest</td> <!-- Enumerated Object Name -->
      <td>user</td>  <!-- Enumerated Object Class -->
      <td>Domain Guests, Guests.</td> <!-- Member of -->
      <td>Default</td>  <!-- Access -->
      <td>N/A</td> <!-- Access Type -->
      <td>N/A</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 17, 34, 47, 3, 1</td> <!-- OpNums -->
      <td>No</td>  <!-- Errors in Traffic -->
      <td>Object and its attributes are returned</td> <!-- Results -->
      <td>Default Guest account. Disabled.</td>  <!-- Notes -->
      <td>python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! enumerate=account-details user=guest acl</td> <!-- Execution -->
    </tr>
    <tr>
      <td>acl0/4</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>SvcB1</td> <!-- Enumerated Object Name -->
      <td>user</td>  <!-- Enumerated Object Class -->
      <td>Domain Users, ServiceAccounts.</td> <!-- Member of -->
      <td>Default</td>  <!-- Access -->
      <td>N/A</td> <!-- Access Type -->
      <td>N/A</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 17, 34, 47, 3, 1</td> <!-- OpNums -->
      <td>No</td>  <!-- Errors in Traffic -->
      <td>Object and its attributes are returned</td> <!-- Results -->
      <td>Service Account. It has Service Principal Name "HTTP/web01.domain-b.local"</td>  <!-- Notes -->
      <td>python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! enumerate=account-details user=svcb1 acl</td> <!-- Execution -->
    </tr>
    <tr>
      <td>acl0/5</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>SvcB1</td> <!-- Enumerated Object Name -->
      <td>msDS-ManagedServiceAccount</td>  <!-- Enumerated Object Class -->
      <td>N/A</td> <!-- Member of -->
      <td>Default</td>  <!-- Access -->
      <td>N/A</td> <!-- Access Type -->
      <td>N/A</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 13, 34, 47, 1</td> <!-- OpNums -->
      <td>No</td>  <!-- Errors in Traffic -->
      <td>Object is returned as computer object</td> <!-- Results -->
      <td>Managed Service Account (MSA)</td>  <!-- Notes -->
      <td>python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! acl enumerate=display-info type=computers</td> <!-- Execution -->
    </tr>
    <tr>
      <td>acl0/6</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>SvcB3</td> <!-- Enumerated Object Name -->
      <td>msDS-GroupManagedServiceAccount</td>  <!-- Enumerated Object Class -->
      <td>N/A</td> <!-- Member of -->
      <td>Default</td>  <!-- Access -->
      <td>N/A</td> <!-- Access Type -->
      <td>N/A</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 13, 34, 47, 1</td> <!-- OpNums -->
      <td>No</td>  <!-- Errors in Traffic -->
      <td>Object and its attributes are returned</td> <!-- Results -->
      <td>Group Managed Service Account (gMSA) <!-- Notes -->
      <td>python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! acl enumerate=display-info type=computers</td> <!-- Execution -->
    </tr>
    <tr>
      <td>acl0/7</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>AdminB1</td> <!-- Enumerated Object Name -->
      <td>user</td>  <!-- Enumerated Object Class -->
      <td>Domain Users, Domain Admins</td> <!-- Member of -->
      <td>Default</td>  <!-- Access -->
      <td>N/A</td> <!-- Access Type -->
      <td>N/A</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 17, 34, 47, 3, 1</td> <!-- OpNums -->
      <td>No</td>  <!-- Errors in Traffic -->
      <td>Object and its attributes are returned</td> <!-- Results -->
      <td>Privileged account and has AdminSDHolder protection</td>  <!-- Notes -->
      <td>python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! enumerate=account-details acl user=adminb1</td> <!-- Execution -->
    </tr>
    <tr>
      <td>acl0/8</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>GroupB1_DG</td> <!-- Enumerated Object Name -->
      <td>group</td>  <!-- Enumerated Object Class -->
      <td>None</td> <!-- Member of -->
      <td>Default</td>  <!-- Access -->
      <td>N/A</td> <!-- Access Type -->
      <td>N/A</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 17, 1.</td> <!-- OpNums -->
      <td>No</td>  <!-- Errors in Traffic -->
      <td>Object is not returned</td> <!-- Results -->
      <td>Domain Local Security Group</td>  <!-- Notes -->
      <td>python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! enumerate=domain-group-details group="GroupB1_DG"</td> <!-- Execution -->
    </tr>
    <tr>
      <td>acl0/9</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>GroupB2_GG</td> <!-- Enumerated Object Name -->
      <td>group</td>  <!-- Enumerated Object Class -->
      <td>None</td> <!-- Member of -->
      <td>Default</td>  <!-- Access -->
      <td>N/A</td> <!-- Access Type -->
      <td>N/A</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 17, 19, 25, 18, 1.</td> <!-- OpNums -->
      <td>No</td>  <!-- Errors in Traffic -->
      <td>Object and its attributes are returned</td> <!-- Results -->
      <td>Global Security Group</td>  <!-- Notes -->
      <td>python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! enumerate=domain-group-details group="GroupB2_GG"</td> <!-- Execution -->
    </tr>
    <tr>
      <td>acl0/10</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>GroupB3_UG</td> <!-- Enumerated Object Name -->
      <td>group</td>  <!-- Enumerated Object Class -->
      <td>None</td> <!-- Member of -->
      <td>Default</td>  <!-- Access -->
      <td>N/A</td> <!-- Access Type -->
      <td>N/A</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 17, 19, 25, 18, 1.</td> <!-- OpNums -->
      <td>No</td>  <!-- Errors in Traffic -->
      <td>Object and its attributes are returned</td> <!-- Results -->
      <td>Universal Security Group</td>  <!-- Notes -->
      <td>python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! enumerate=domain-group-details group="GroupB3_UG"</td> <!-- Execution -->
    </tr>
    <tr>
      <td>acl0/11</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>Domain Users</td> <!-- Enumerated Object Name -->
      <td>group</td>  <!-- Enumerated Object Class -->
      <td>Users</td> <!-- Member of -->
      <td>Default</td>  <!-- Access -->
      <td>N/A</td> <!-- Access Type -->
      <td>N/A</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 17, 19, 25, 18, 1.</td> <!-- OpNums -->
      <td>No</td>  <!-- Errors in Traffic -->
      <td>Object and its attributes are returned. The output contains also the record "DOMAIN-A$" which corresponds the domain name which has the trust established with the current domain. THe output contains object svcb1</td> <!-- Results -->
      <td>Global Security Group</td>  <!-- Notes -->
      <td>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! acl enumerate=domain-group-details  group="Domain Users" <br><br>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! acl enumerate=account-details user=1139
      </td> <!-- Execution -->
    </tr>
    <tr>
      <td>acl0/12</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>GroupB4_DL_DG</td> <!-- Enumerated Object Name -->
      <td>group</td>  <!-- Enumerated Object Class -->
      <td>None</td> <!-- Member of -->
      <td>Default</td>  <!-- Access -->
      <td>N/A</td> <!-- Access Type -->
      <td>N/A</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 17, 1.</td> <!-- OpNums -->
      <td>No</td>  <!-- Errors in Traffic -->
      <td>Object is not returned</td> <!-- Results -->
      <td>Domain Local Distribution Group</td>  <!-- Notes -->
      <td>python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! enumerate=domain-group-details group="GroupB4_DL_DG"</td> <!-- Execution -->
    </tr>
    <tr>
      <td>acl0/13</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>GroupB5_DL_GG</td> <!-- Enumerated Object Name -->
      <td>group</td>  <!-- Enumerated Object Class -->
      <td>None</td> <!-- Member of -->
      <td>Default</td>  <!-- Access -->
      <td>N/A</td> <!-- Access Type -->
      <td>N/A</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 17, 19, 25, 18, 1.</td> <!-- OpNums -->
      <td>No</td>  <!-- Errors in Traffic -->
      <td>Object and its attributes are returned. The output contains all users in the group including regular, disabled and privileged users; regular service account, MSA and gMSA. The group is not listed when searching local and domain groups</td> <!-- Results -->
      <td>Global Distribution Group</td>  <!-- Notes -->
      <td>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! enumerate=domain-group-details group="GroupB5_DL_GG" <br><br>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! acl enumerate=domain-groups <br><br>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! acl enumerate=local-groups
      </td> <!-- Execution -->
    </tr>
    <tr>
      <td>acl0/14</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>GroupB6_DL_UG</td> <!-- Enumerated Object Name -->
      <td>group</td> <!-- Enumerated Object Class -->
      <td>None</td> <!-- Member of -->
      <td>Default</td>  <!-- Access -->
      <td>N/A</td> <!-- Access Type -->
      <td>N/A</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 17, 19, 25, 18, 1.</td> <!-- OpNums -->
      <td>No</td>  <!-- Errors in Traffic -->
      <td>Object and its attributes are returned. The output contains all users in the group including regular, disabled and privileged users; regular service account, MSA and gMSA. The group is not listed when searching local and domain groups</td> <!-- Results -->
      <td>Universal Distribution Group</td>  <!-- Notes -->
      <td>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! enumerate=domain-group-details group="GroupB6_DL_UG" <br><br>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! acl enumerate=domain-groups <br><br>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! acl enumerate=local-groups
      </td> <!-- Execution -->
    </tr>
    <tr>
      <td>acl0/15</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>domain-b.local</td> <!-- Enumerated Object Name -->
      <td>domainDNS</td>  <!-- Enumerated Object Class -->
      <td>N/A</td> <!-- Member of -->
      <td>Default</td>  <!-- Access -->
      <td>N/A</td> <!-- Access Type -->
      <td>N/A</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 46, 13, 11, 15, 1, 18, 34, 47.</td> <!-- OpNums -->
      <td>No</td>  <!-- Errors in Traffic -->
      <td>Object and its attributes are returned</td> <!-- Results -->
      <td></td>  <!-- Notes -->
      <td>
          python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! enumerate=summary <br><br>
          python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! acl enumerate=domain-groups <br><br>
          python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! acl enumerate=local-groups <br><br>
          python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! enumerate=users
      </td> <!-- Execution -->
    </tr>
    <tr>
      <td>acl1/1</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>UserB2</td> <!-- Enumerated Object Name -->
      <td>user</td>  <!-- Enumerated Object Class -->
      <td>Domain Users</td> <!-- Member of -->
      <td>All</td>  <!-- Access -->
      <td>Deny</td> <!-- Access Type -->
      <td>Authenticated users</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 17, 34, 47, 3, 1</td> <!-- OpNums -->
      <td>No</td>  <!-- Errors in Traffic -->
      <td>Object and its attributes are returned</td> <!-- Results -->
      <td></td>  <!-- Notes -->
      <td>python samr-enum.py target=bdc1.domain-b.local username=enum-a3 password=LabAdm1! enumerate=account-details user=userb2 acl</td> <!-- Execution -->
    </tr>
    <tr>
      <td>acl1/2</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>UserB2</td> <!-- Enumerated Object Name -->
      <td>user</td>  <!-- Enumerated Object Class -->
      <td>Domain Users</td> <!-- Member of -->
      <td>All</td>  <!-- Access -->
      <td>Deny</td> <!-- Access Type -->
      <td>Pre-Windows 2000 Compatible Access</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 17, 34, 1</td> <!-- OpNums -->
      <td>0x00000022 (STATUS_ACCESS_DENIED)</td>  <!-- Errors in Traffic -->
      <td>Object is not returned in both: "enumerate=account-details" and "enumerate=users"</td> <!-- Results -->
      <td>Authenticated users group is kept in ACL</td>  <!-- Notes -->
      <td>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a3 password=LabAdm1! enumerate=account-details user=userb2 acl <br><br>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! acl enumerate=users      
      </td> <!-- Execution -->
    </tr>
    <tr>
      <td>acl1/3</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>UserB2</td> <!-- Enumerated Object Name -->
      <td>user</td>  <!-- Enumerated Object Class -->
      <td>Domain Users</td> <!-- Member of -->
      <td>List contents</td>  <!-- Access -->
      <td>Allow</td> <!-- Access Type -->
      <td>domain-a\enum-a</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 17, 34, 1.</td> <!-- OpNums -->
      <td>0x00000022 (STATUS_ACCESS_DENIED)</td>  <!-- Errors in Traffic -->
      <td>Object is not returned</td> <!-- Results -->
      <td>Additional to scenario acl1/2 where group "Pre-Windows 2000 Compatible Access" is removed</td>  <!-- Notes -->
      <td>python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! enumerate=account-details user=userb2 acl</td> <!-- Execution -->
    </tr>
    <tr>
      <td>acl1/4</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>UserB2</td> <!-- Enumerated Object Name -->
      <td>user</td>  <!-- Enumerated Object Class -->
      <td>Domain Users</td> <!-- Member of -->
      <td>Read all properties</td>  <!-- Access -->
      <td>Allow</td> <!-- Access Type -->
      <td>domain-a\enum-a</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 17, 34, 47, 3, 1.</td> <!-- OpNums -->
      <td>No</td>  <!-- Errors in Traffic -->
      <td>Object and all attributes are returned</td> <!-- Results -->
      <td>Additional to scenario acl1/2 where group "Pre-Windows 2000 Compatible Access" is removed</td>  <!-- Notes -->
      <td>python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! enumerate=account-details user=userb2 acl</td> <!-- Execution -->
    </tr>
    <tr>
      <td>acl1/5</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>UserB2</td> <!-- Enumerated Object Name -->
      <td>user</td>  <!-- Enumerated Object Class -->
      <td>Domain Users</td> <!-- Member of -->
      <td>Read General Information</td>  <!-- Access -->
      <td>Allow</td> <!-- Access Type -->
      <td>domain-a\enum-a</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 17, 34, 1.</td> <!-- OpNums -->
      <td>0x00000022 (STATUS_ACCESS_DENIED)</td>  <!-- Errors in Traffic -->
      <td>Object is not returned</td> <!-- Results -->
      <td>Additional to scenario acl1/2 where group "Pre-Windows 2000 Compatible Access" is removed</td>  <!-- Notes -->
      <td>python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! enumerate=account-details user=userb2 acl</td> <!-- Execution -->
    </tr>
    <tr>
      <td>acl1/6</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>GroupB2_GG</td> <!-- Enumerated Object Name -->
      <td>group</td>  <!-- Enumerated Object Class -->
      <td>None</td> <!-- Member of -->
      <td>Default</td>  <!-- Access -->
      <td>N/A</td> <!-- Access Type -->
      <td>N/A</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 17, 19, 25, 18, 1.</td> <!-- OpNums -->
      <td>No</td>  <!-- Errors in Traffic -->
      <td>Object and its attributes are returned including userb2</td> <!-- Results -->
      <td>Global Security Group. The "Pre-Windows 2000 Compatible Access" group is removed from userb2 ACL but it is listed in the output</td>  <!-- Notes -->
      <td>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! acl enumerate=domain-group-details  group=groupb2_gg <br><br>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! enumerate=account-details user=userb2 acl
      </td> <!-- Execution -->
    </tr>
    <tr>
      <td>acl1/7</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>GroupB3_UG</td> <!-- Enumerated Object Name -->
      <td>group</td>  <!-- Enumerated Object Class -->
      <td>None</td> <!-- Member of -->
      <td>Default</td>  <!-- Access -->
      <td>N/A</td> <!-- Access Type -->
      <td>N/A</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 17, 19, 25, 18, 1.</td> <!-- OpNums -->
      <td>No</td>  <!-- Errors in Traffic -->
      <td>Object and its attributes are returned including userb2</td> <!-- Results -->
      <td>Universal Security Group. The "Pre-Windows 2000 Compatible Access" group is removed from userb2 ACL but it is listed in the output</td>  <!-- Notes -->
      <td>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! acl enumerate=domain-group-details  group=groupb3_ug <br><br>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! enumerate=account-details user=userb2 acl
      </td> <!-- Execution -->
    </tr>
    <tr>
      <td>acl1/8</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>GroupB5_DL_GG</td> <!-- Enumerated Object Name -->
      <td>group</td>  <!-- Enumerated Object Class -->
      <td>None</td> <!-- Member of -->
      <td>Default</td>  <!-- Access -->
      <td>N/A</td> <!-- Access Type -->
      <td>N/A</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 17, 19, 25, 18, 1.</td> <!-- OpNums -->
      <td>No</td>  <!-- Errors in Traffic -->
      <td>Object and its attributes are returned including userb2</td> <!-- Results -->
      <td>Global Distribution Group. The "Pre-Windows 2000 Compatible Access" group is removed from userb2 ACL but it is listed in the output</td>  <!-- Notes -->
      <td>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! acl enumerate=domain-group-details  group=groupb5_dl_gg <br><br>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! enumerate=account-details user=userb2 acl
      </td> <!-- Execution -->
    </tr>
    <tr>
      <td>acl1/9</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>GroupB6_DL_UG</td> <!-- Enumerated Object Name -->
      <td>group</td>  <!-- Enumerated Object Class -->
      <td>None</td> <!-- Member of -->
      <td>Default</td>  <!-- Access -->
      <td>N/A</td> <!-- Access Type -->
      <td>N/A</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 17, 19, 25, 18, 1.</td> <!-- OpNums -->
      <td>No</td>  <!-- Errors in Traffic -->
      <td>Object and its attributes are returned including userb2</td> <!-- Results -->
      <td>Universal Distribution Group. The "Pre-Windows 2000 Compatible Access" group is removed from userb2 ACL but it is listed in the output</td>  <!-- Notes -->
      <td>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! acl enumerate=domain-group-details  group=groupb6_dl_ug <br><br>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! enumerate=account-details user=userb2 acl
      </td> <!-- Execution -->
    </tr>
    <tr>
      <td>acl1/10</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>GroupB7_GG</td> <!-- Enumerated Object Name -->
      <td>group</td>  <!-- Enumerated Object Class -->
      <td>None</td> <!-- Member of -->
      <td>Default</td>  <!-- Access -->
      <td>N/A</td> <!-- Access Type -->
      <td>N/A</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 17, 19, 25, 18, 1.</td> <!-- OpNums -->
      <td>No</td>  <!-- Errors in Traffic -->
      <td>Object and its attributes are returned including userb2</td> <!-- Results -->
      <td>Global Security Group. The "Pre-Windows 2000 Compatible Access" group is removed from OU2 organization unit where computer object "computerb3" is located and which is part of the enumerated group. The "computerb3" object is listed in the current program output but is not listed with parameter "enumerate=computers"</td>  <!-- Notes -->
      <td>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! acl enumerate=domain-group-details  group=groupb7_gg <br><br>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! acl enumerate=computers
      </td> <!-- Execution -->
    </tr>
    <tr>
      <td>acl1/11</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>GroupB8_GG</td> <!-- Enumerated Object Name -->
      <td>group</td>  <!-- Enumerated Object Class -->
      <td>None</td> <!-- Member of -->
      <td>All</td>  <!-- Access -->
      <td>Deny</td> <!-- Access Type -->
      <td>Authenticated Users</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 17, 19, 25, 1.</td> <!-- OpNums -->
      <td>No</td>  <!-- Errors in Traffic -->
      <td>Object and its attributes are returned</td> <!-- Results -->
      <td>Global Security Group</td>  <!-- Notes -->
      <td>python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! acl enumerate=domain-group-details  group=groupb8_gg</td> <!-- Execution -->
    </tr>
    <tr>
      <td>acl1/12</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>GroupB8_GG</td> <!-- Enumerated Object Name -->
      <td>group</td>  <!-- Enumerated Object Class -->
      <td>None</td> <!-- Member of -->
      <td>All</td>  <!-- Access -->
      <td>Deny</td> <!-- Access Type -->
      <td>Pre-Windows 2000 Compatible Access</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 17, 19, 25, 1.</td> <!-- OpNums -->
      <td>No</td>  <!-- Errors in Traffic -->
      <td>Object and its attributes are returned</td> <!-- Results -->
      <td>Global Security Group</td>  <!-- Notes -->
      <td>python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! acl enumerate=domain-group-details  group=groupb8_gg</td> <!-- Execution -->
    </tr>
    <tr>
      <td>acl1/13</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>GroupB8_GG</td> <!-- Enumerated Object Name -->
      <td>group</td>  <!-- Enumerated Object Class -->
      <td>None</td> <!-- Member of -->
      <td>All</td>  <!-- Access -->
      <td>Deny</td> <!-- Access Type -->
      <td>Pre-Windows 2000 Compatible Access, Authenticated Users</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 19, 1.</td> <!-- OpNums -->
      <td>0x00000022 (STATUS_ACCESS_DENIED)</td>  <!-- Errors in Traffic -->
      <td>Object and its attributes are returned</td> <!-- Results -->
      <td>Global Security Group</td>  <!-- Notes -->
      <td>python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! acl enumerate=domain-group-details  group=groupb8_gg</td> <!-- Execution -->
    </tr>
    <tr>
      <td>acl2/0</td> <!-- Scenario ID -->
      <td>Selective Authentication</td>  <!-- Forest Trust Type -->
      <td>domain-a.local</td> <!-- Enumerated Object Name -->
      <td>domainDNS</td>  <!-- Enumerated Object Class -->
      <td>N/A</td> <!-- Member of -->
      <td>N/A</td>  <!-- Access -->
      <td>N/A</td> <!-- Access Type -->
      <td>N/A</td>  <!-- Access Applied to -->
      <td>N/A</td> <!-- OpNums -->
      <td>No</td>  <!-- Errors in Traffic -->
      <td>Object is not returned</td> <!-- Results -->
      <td>No access is granted to domain-a\enum-a account in current domain-b.local domain</td>  <!-- Notes -->
      <td>python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! acl enumerate=summary</td> <!-- Execution -->
    </tr>
    <tr>
      <td>acl2/1</td> <!-- Scenario ID -->
      <td>Selective Authentication</td>  <!-- Forest Trust Type -->
      <td>domain-a.local</td> <!-- Enumerated Object Name -->
      <td>domainDNS</td>  <!-- Enumerated Object Class -->
      <td>N/A</td> <!-- Member of -->
      <td>Allow to authenticate - Descendant Computer Objects</td>  <!-- Access -->
      <td>Allow</td> <!-- Access Type -->
      <td>Domain-a\enum-a</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 13, 34, 47, 1, 19, 25, 20, 18, 17, 46, 11, 15.</td> <!-- OpNums -->
      <td>No</td>  <!-- Errors in Traffic -->
      <td>All objects and their attributes are returned</td> <!-- Results -->
      <td>Access is granted on the domain-a.local object</td>  <!-- Notes -->
      <td>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! opnums enumerate=display-info type=computers <br><br>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! opnums enumerate=display-info type=domain-groups <br><br>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! opnums enumerate=display-info type=local-groups <br><br>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! opnums enumerate=summary <br><br>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! opnums enumerate=display-info type=users
      </td> <!-- Execution -->
    </tr>
    <tr>
      <td>acl2/2</td> <!-- Scenario ID -->
      <td>Selective Authentication</td>  <!-- Forest Trust Type -->
      <td>domain-a.local</td> <!-- Enumerated Object Name -->
      <td>domainDNS</td>  <!-- Enumerated Object Class -->
      <td>N/A</td> <!-- Member of -->
      <td>Allow to authenticate - Descendant Computer Objects</td>  <!-- Access -->
      <td>Allow</td> <!-- Access Type -->
      <td>Domain-a\enum-a</td>  <!-- Access Applied to -->
      <td>None</td> <!-- OpNums -->
      <td>No</td>  <!-- Errors in Traffic -->
      <td>Computers, users and groups objects are not returned even if these objects are located in the organization unit where the access is granted. /td> <!-- Results -->
      <td>Access is granted on OU1 organization unit only</td>  <!-- Notes -->
      <td>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! opnums enumerate=summary <br><br>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! opnums enumerate=display-info type=computers <br><br>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! opnums enumerate=display-info type=domain-groups <br><br>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! opnums enumerate=display-info type=local-groups <br><br>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! opnums enumerate=display-info type=users <br><br>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! acl enumerate=domain-group-details  group=groupb2_gg <br><br>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! acl enumerate=domain-group-details  group=groupb3_ug <br><br>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! enumerate=user-memberships-domaingroups user=userb1 <br><br>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! enumerate=account-details user=userb1 
      </td> <!-- Execution -->
    </tr>
  </tbody>
</table>

