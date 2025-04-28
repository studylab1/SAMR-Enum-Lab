(In progress)

<table cellpadding="4" cellspacing="0" border="1">
  <thead>
    <tr>
      <th>Scenario ID</th>  <!-- 1 -->
      <th>Forest Trust Type</th>  <!-- 2 -->
      <th>Enumerated Object Name</th>  <!-- 3 -->
      <th>Enumerated Object Class</th>  <!-- 4 -->
      <th>Member of</th>  <!-- 5 -->
      <th>Access</th>  <!-- 6 -->
      <th>Access Type</th>  <!-- 7 -->
      <th>Access Applied to / Action</th>  <!-- 8 -->
      <th>OpNums</th>  <!-- 9 -->
      <th>Error in SAMR Traffic</th>  <!-- 10 -->
      <th>Results</th>  <!-- 11 -->
      <th>Notes</th>  <!-- 12 -->
      <th>Execution</th>  <!-- 13 -->
      <th>Links</th>  <!-- 14 -->
            </tr>
  </thead>
  <tbody>
    <tr>
      <td>acl0/1</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>domain-b\UserB1</td> <!-- Enumerated Object -->
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
      <td>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_0.1_userb1.pcapng">Download PCAPNG File</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_0.1_userb1.txt">View Program Output</a>
      </td> <!-- Link -->
    </tr>
    <tr>
      <td>acl0/2</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>domain-b\UserB3</td> <!-- Enumerated Object -->
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
<td>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_0.2_userb3.pcapng">Download PCAPNG File</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_0.2_userb3.txt">View Program Output</a>
      </td> <!-- Link -->
    </tr>
    <tr>
      <td>acl0/3</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>domain-b\Guest</td> <!-- Enumerated Object -->
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
    <td>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_0.3_guest.pcapng">Download PCAPNG File</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_0.3_guest.txt">View Program Output</a>
      </td> <!-- Link -->
    </tr>
    <tr>
      <td>acl0/4</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>domain-b\SvcB1</td> <!-- Enumerated Object -->
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
    <td>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_0.4_svcb1.pcapng">Download PCAPNG File</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_0.4_svcb1.txt">View Program Output</a>
      </td> <!-- Link -->
    </tr>
    <tr>
      <td>acl0/5</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>domain-b\SvcB1</td> <!-- Enumerated Object -->
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
    <td>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_0.5_enumerate_computers.pcapng">Download PCAPNG File</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_0.5_enumerate_computers.txt">View Program Output</a>
      </td> <!-- Link -->
    </tr>
    <tr>
      <td>acl0/6</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>domain-b\SvcB3</td> <!-- Enumerated Object -->
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
    <td>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_0.6_enumerate_computers.pcapng">Download PCAPNG File</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_0.6_enumerate_computers.txt">View Program Output</a>
      </td> <!-- Link -->
    </tr>
    <tr>
      <td>acl0/7</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>domain-b\AdminB1</td> <!-- Enumerated Object -->
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
    <td>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_0.7_adminb1.pcapng">Download PCAPNG File</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_0.7_adminb1.txt">View Program Output</a>
      </td> <!-- Link -->
    </tr>
    <tr>
      <td>acl0/8</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>domain-b\GroupB1_DG</td> <!-- Enumerated Object -->
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
    <td>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_0.8_groupb1_dg.pcapng">Download PCAPNG File</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_0.8_groupb1_dg.txt">View Program Output</a>
      </td> <!-- Link -->
    </tr>
    <tr>
      <td>acl0/9</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>domain-b\GroupB2_GG</td> <!-- Enumerated Object -->
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
    <td>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_0.9_groupb2_gg.pcapng">Download PCAPNG File</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_0.9_groupb2_gg.txt">View Program Output</a>
      </td> <!-- Link -->
    </tr>
    <tr>
      <td>acl0/10</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>domain-b\GroupB3_UG</td> <!-- Enumerated Object -->
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
    <td>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_0.10_groupb3_ug.pcapng">Download PCAPNG File</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_0.10_groupb3_ug.txt">View Program Output</a>
      </td> <!-- Link -->
    </tr>
    <tr>
      <td>acl0/11</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>domain-b\Domain Users</td> <!-- Enumerated Object -->
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
    <td>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_0.11_domain_users.pcapng">Download PCAPNG File</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_0.11_domain_users.txt">View Program Output</a>
      </td> <!-- Link -->
    </tr>
    <tr>
      <td>acl0/12</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>domain-b\GroupB4_DL_DG</td> <!-- Enumerated Object -->
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
    <td>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_0.12_groupb4_dl_dg.pcapng">Download PCAPNG File</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_0.12_groupb4_dl_dg.txt">View Program Output</a>
      </td> <!-- Link -->
    </tr>
    <tr>
      <td>acl0/13</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>domain-b\GroupB5_DL_GG</td> <!-- Enumerated Object -->
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
<td>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_0.13_groupb5_dl_gg.pcapng">Download PCAPNG File</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_0.13_groupb5_dl_gg.txt">View Program Output</a>
      </td> <!-- Link -->
    </tr>
    <tr>
      <td>acl0/14</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>domain-b\GroupB6_DL_UG</td> <!-- Enumerated Object -->
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
    <td>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_0.14_groupb6_dl_ug.pcapng">Download PCAPNG File</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_0.14_groupb6_dl_ug.txt">View Program Output</a>
      </td> <!-- Link -->
    </tr>
    <tr>
      <td>acl0/15</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>domain-b.local</td> <!-- Enumerated Object -->
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
    <td>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_0.15_enumerate_computers.pcapng">Download PCAPNG File (computers)</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_0.15_enumerate_computers.txt">View Program Output (computers)</a><br><br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_0.15_enumerate_domain_groups.pcapng">Download PCAPNG File (domain groups)</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_0.15_enumerate_domain_groups.txt">View Program Output (domain groups)</a><br><br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_0.15_enumerate_local_groups.pcapng">Download PCAPNG File (local groups)</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_0.15_enumerate_local_groups.txt">View Program Output (local groups)</a><br><br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_0.15_enumerate_users.pcapng">Download PCAPNG File (users)</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_0.15_enumerate_users.txt">View Program Output (users)</a><br><br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_0.15_summary.pcapng">Download PCAPNG File (summary)</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_0.15_summary.txt">View Program Output (summary)</a><br><br> <br>
      </td> <!-- Link -->
    </tr>
    <tr>
      <td>acl1/1</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>domain-b\UserB2</td> <!-- Enumerated Object -->
      <td>user</td>  <!-- Enumerated Object Class -->
      <td>Domain Users</td> <!-- Member of -->
      <td>All</td>  <!-- Access -->
      <td>N/A</td> <!-- Access Type -->
      <td>Authenticated users / Remove</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 17, 34, 47, 3, 1</td> <!-- OpNums -->
      <td>No</td>  <!-- Errors in Traffic -->
      <td>Object and its attributes are returned</td> <!-- Results -->
      <td></td>  <!-- Notes -->
      <td>
         python samr-enum.py target=bdc1.domain-b.local username=enum-a3 password=LabAdm1! enumerate=account-details user=userb2 acl
      </td> <!-- Execution -->
      <td>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_1.1_userb2.pcapng">Download PCAPNG File</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_1.1_userb2.txt">View Program Output</a>
      </td> <!-- Link -->
    </tr>
    <tr>
      <td>acl1/2</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>domain-b\UserB2</td> <!-- Enumerated Object -->
      <td>user</td>  <!-- Enumerated Object Class -->
      <td>Domain Users</td> <!-- Member of -->
      <td>All</td>  <!-- Access -->
      <td>N/A</td> <!-- Access Type -->
      <td>Pre-Windows 2000 Compatible Access / Remove</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 17, 34, 1</td> <!-- OpNums -->
      <td>0x00000022 (STATUS_ACCESS_DENIED)</td>  <!-- Errors in Traffic -->
      <td>Object is not returned in both: "enumerate=account-details" and "enumerate=users"</td> <!-- Results -->
      <td>Authenticated users group is kept in ACL</td>  <!-- Notes -->
      <td>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a3 password=LabAdm1! enumerate=account-details user=userb2 acl <br><br>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! acl enumerate=users
      </td> <!-- Execution -->
      <td>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_1.2_userb2.pcapng">Download PCAPNG File</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_1.2_userb2.txt">View Program Output</a>
      </td> <!-- Link -->
    </tr>
    <tr>
      <td>acl1/3</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>domain-b\UserB2</td> <!-- Enumerated Object -->
      <td>user</td>  <!-- Enumerated Object Class -->
      <td>Domain Users</td> <!-- Member of -->
      <td>List contents</td>  <!-- Access -->
      <td>Allow</td> <!-- Access Type -->
      <td>domain-a\enum-a / Add</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 17, 34, 1.</td> <!-- OpNums -->
      <td>0x00000022 (STATUS_ACCESS_DENIED)</td>  <!-- Errors in Traffic -->
      <td>Object is not returned</td> <!-- Results -->
      <td>Additional to scenario acl1/2 where group "Pre-Windows 2000 Compatible Access" is removed</td>  <!-- Notes -->
      <td>python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! enumerate=account-details user=userb2 acl</td> <!-- Execution -->
      <td>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_1.3_userb2.pcapng">Download PCAPNG File</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_1.3_userb2.txt">View Program Output</a>
      </td> <!-- Link -->
    </tr>
    <tr>
      <td>acl1/4</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>domain-b\UserB2</td> <!-- Enumerated Object -->
      <td>user</td>  <!-- Enumerated Object Class -->
      <td>Domain Users</td> <!-- Member of -->
      <td>Read all properties</td>  <!-- Access -->
      <td>Allow</td> <!-- Access Type -->
      <td>domain-a\enum-a / Add</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 17, 34, 47, 3, 1.</td> <!-- OpNums -->
      <td>No</td>  <!-- Errors in Traffic -->
      <td>Object and all attributes are returned</td> <!-- Results -->
      <td>Additional to scenario acl1/2 where group "Pre-Windows 2000 Compatible Access" is removed</td>  <!-- Notes -->
      <td>python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! enumerate=account-details user=userb2 acl</td> <!-- Execution -->
      <td>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_1.4_userb2.pcapng">Download PCAPNG File</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_1.4_userb2.txt">View Program Output</a>
      </td> <!-- Link -->
    </tr>
    <tr>
      <td>acl1/5</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>domain-b\UserB2</td> <!-- Enumerated Object -->
      <td>user</td>  <!-- Enumerated Object Class -->
      <td>Domain Users</td> <!-- Member of -->
      <td>Read General Information</td>  <!-- Access -->
      <td>Allow</td> <!-- Access Type -->
      <td>domain-a\enum-a / Add</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 17, 34, 1.</td> <!-- OpNums -->
      <td>0x00000022 (STATUS_ACCESS_DENIED)</td>  <!-- Errors in Traffic -->
      <td>Object is not returned</td> <!-- Results -->
      <td>Additional to scenario acl1/2 where group "Pre-Windows 2000 Compatible Access" is removed</td>  <!-- Notes -->
      <td>python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! enumerate=account-details user=userb2 acl</td> <!-- Execution -->
      <td>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_1.5_userb2.pcapng">Download PCAPNG File</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_1.5_userb2.txt">View Program Output</a>
      </td> <!-- Link -->
    </tr>
    <tr>
      <td>acl1/6</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>domain-b\GroupB2_GG</td> <!-- Enumerated Object -->
      <td>group</td>  <!-- Enumerated Object Class -->
      <td>None</td> <!-- Member of -->
      <td>Default</td>  <!-- Access -->
      <td>N/A</td> <!-- Access Type -->
      <td>N/A</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 17, 19, 25, 18, 1.</td> <!-- OpNums -->
      <td>No</td>  <!-- Errors in Traffic -->
      <td>Object and its attributes are returned including userb2</td> <!-- Results -->
      <td>Global Security Group. The "Pre-Windows 2000 Compatible Access" group is removed from userb2 ACL, but it is listed in the output</td>  <!-- Notes -->
      <td>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! acl enumerate=domain-group-details  group=groupb2_gg <br><br>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! enumerate=account-details user=userb2 acl
      </td> <!-- Execution -->
      <td>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_1.6_groupb2_gg.pcapng">Download PCAPNG File</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_1.6_groupb2_gg.txt">View Program Output</a>
      </td> <!-- Link -->
    </tr>
    <tr>
      <td>acl1/7</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>domain-b\GroupB3_UG</td> <!-- Enumerated Object -->
      <td>group</td>  <!-- Enumerated Object Class -->
      <td>None</td> <!-- Member of -->
      <td>Default</td>  <!-- Access -->
      <td>N/A</td> <!-- Access Type -->
      <td>N/A</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 17, 19, 25, 18, 1.</td> <!-- OpNums -->
      <td>No</td>  <!-- Errors in Traffic -->
      <td>Object and its attributes are returned including userb2</td> <!-- Results -->
      <td>Universal Security Group. The "Pre-Windows 2000 Compatible Access" group is removed from userb2 ACL, but it is listed in the output</td>  <!-- Notes -->
      <td>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! acl enumerate=domain-group-details  group=groupb3_ug <br><br>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! enumerate=account-details user=userb2 acl
      </td> <!-- Execution -->
      <td>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_1.7_groupb3_ug.pcapng">Download PCAPNG File</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_1.7_groupb3_ug.txt">View Program Output</a>
      </td> <!-- Link -->
    </tr>
    <tr>
      <td>acl1/8</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>domain-b\GroupB5_DL_GG</td> <!-- Enumerated Object -->
      <td>group</td>  <!-- Enumerated Object Class -->
      <td>None</td> <!-- Member of -->
      <td>Default</td>  <!-- Access -->
      <td>N/A</td> <!-- Access Type -->
      <td>N/A</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 17, 19, 25, 18, 1.</td> <!-- OpNums -->
      <td>No</td>  <!-- Errors in Traffic -->
      <td>Object and its attributes are returned including userb2</td> <!-- Results -->
      <td>Global Distribution Group. The "Pre-Windows 2000 Compatible Access" group is removed from userb2 ACL, but it is listed in the output</td>  <!-- Notes -->
      <td>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! acl enumerate=domain-group-details  group=groupb5_dl_gg <br><br>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! enumerate=account-details user=userb2 acl
      </td> <!-- Execution -->
      <td>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_1.8_groupb5_dl_gg.pcapng">Download PCAPNG File</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_1.8_groupb5_dl_gg.txt">View Program Output</a>
      </td> <!-- Link -->
    </tr>
    <tr>
      <td>acl1/9</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>domain-b\GroupB6_DL_UG</td> <!-- Enumerated Object -->
      <td>group</td>  <!-- Enumerated Object Class -->
      <td>None</td> <!-- Member of -->
      <td>Default</td>  <!-- Access -->
      <td>N/A</td> <!-- Access Type -->
      <td>N/A</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 17, 19, 25, 18, 1.</td> <!-- OpNums -->
      <td>No</td>  <!-- Errors in Traffic -->
      <td>Object and its attributes are returned including userb2</td> <!-- Results -->
      <td>Universal Distribution Group. The "Pre-Windows 2000 Compatible Access" group is removed from userb2 ACL, but it is listed in the output</td>  <!-- Notes -->
      <td>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! acl enumerate=domain-group-details  group=groupb6_dl_ug <br><br>
        python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! enumerate=account-details user=userb2 acl
      </td> <!-- Execution -->
      <td>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_1.9_groupb6_dl_ug.pcapng">Download PCAPNG File</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_1.9_groupb6_dl_ug.txt">View Program Output</a>
      </td> <!-- Link -->
    </tr>
    <tr>
      <td>acl1/10</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>domain-b\GroupB7_GG</td> <!-- Enumerated Object -->
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
      <td>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_1.10_groupb7_gg.pcapng">Download PCAPNG File</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_1.10_groupb7_gg.txt">View Program Output</a>
      </td> <!-- Link -->
    </tr>
    <tr>
      <td>acl1/11</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>domain-b\GroupB8_GG</td> <!-- Enumerated Object -->
      <td>group</td>  <!-- Enumerated Object Class -->
      <td>None</td> <!-- Member of -->
      <td>All</td>  <!-- Access -->
      <td>N/A</td> <!-- Access Type -->
      <td>Authenticated Users / Remove</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 17, 19, 25, 1.</td> <!-- OpNums -->
      <td>No</td>  <!-- Errors in Traffic -->
      <td>Object and its attributes are returned</td> <!-- Results -->
      <td>Global Security Group</td>  <!-- Notes -->
      <td>python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! acl enumerate=domain-group-details  group=groupb8_gg</td> <!-- Execution -->
      <td>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_1.11_groupb8_gg.pcapng">Download PCAPNG File</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_1.11_groupb8_gg.txt">View Program Output</a>
      </td> <!-- Link -->
    </tr>
    <tr>
      <td>acl1/12</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>domain-b\GroupB8_GG</td> <!-- Enumerated Object -->
      <td>group</td>  <!-- Enumerated Object Class -->
      <td>None</td> <!-- Member of -->
      <td>All</td>  <!-- Access -->
      <td>N/A</td> <!-- Access Type -->
      <td>Pre-Windows 2000 Compatible Access / Remove</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 17, 19, 25, 1.</td> <!-- OpNums -->
      <td>No</td>  <!-- Errors in Traffic -->
      <td>Object and its attributes are returned</td> <!-- Results -->
      <td>Global Security Group</td>  <!-- Notes -->
      <td>python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! acl enumerate=domain-group-details  group=groupb8_gg</td> <!-- Execution -->
      <td>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_1.12_groupb8_gg.pcapng">Download PCAPNG File</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_1.12_groupb8_gg.txt">View Program Output</a>
      </td> <!-- Link -->
    </tr>
    <tr>
      <td>acl1/13</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>domain-b\GroupB8_GG</td> <!-- Enumerated Object -->
      <td>group</td>  <!-- Enumerated Object Class -->
      <td>None</td> <!-- Member of -->
      <td>All</td>  <!-- Access -->
      <td>N/A</td> <!-- Access Type -->
      <td>Pre-Windows 2000 Compatible Access, Authenticated Users / Remove</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 19, 1.</td> <!-- OpNums -->
      <td>0x00000022 (STATUS_ACCESS_DENIED)</td>  <!-- Errors in Traffic -->
      <td>Object and its attributes are returned</td> <!-- Results -->
      <td>Global Security Group</td>  <!-- Notes -->
      <td>python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! acl enumerate=domain-group-details  group=groupb8_gg</td> <!-- Execution -->
      <td>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_1.13_groupb8_gg.pcapng">Download PCAPNG File</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_1.13_groupb8_gg.txt">View Program Output</a>
      </td> <!-- Link -->
    </tr>
    <tr>
      <td>acl1/14</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>domain-b\UserB5</td> <!-- Enumerated Object -->
      <td>user</td>  <!-- Enumerated Object Class -->
      <td>Domain Users</td> <!-- Member of -->
      <td>All</td>  <!-- Access -->
      <td>N/A</td> <!-- Access Type -->
      <td>Removed all principals except Pre-Windows 2000 Compatible Access / Remove</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 34, 47, 3, 1.</td> <!-- OpNums -->
      <td>No</td>  <!-- Errors in Traffic -->
      <td>Object and its attributes are returned</td> <!-- Results -->
      <td>The server returns default ACL </td>  <!-- Notes -->
      <td>python samr-enum.py target=bdc1.domain-b.local username=enum-a password=LabAdm1! acl enumerate=account-details user=userb5</td> <!-- Execution -->
      <td>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_1.14_userb5.pcapng">Download PCAPNG File</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_1.14_userb5.txt">View Program Output (samr-enum output)</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_1.14_userb5_powershell.txt">View Program Output (ACL check on domain controller)</a>
      </td> <!-- Link -->
    </tr>
    <tr>
      <td>acl2/0</td> <!-- Scenario ID -->
      <td>Selective Authentication</td>  <!-- Forest Trust Type -->
      <td>bdc1.domain-b.local</td> <!-- Enumerated Object -->
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
      <td>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_2.0_summary.pcapng">Download PCAPNG File</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_2.0_summary.txt">View Program Output</a>
      </td> <!-- Link -->
    </tr>
    <tr>
      <td>acl2/1</td> <!-- Scenario ID -->
      <td>Selective Authentication</td>  <!-- Forest Trust Type -->
      <td>bdc1.domain-b.local</td> <!-- Enumerated Object -->
      <td>domainDNS</td>  <!-- Enumerated Object Class -->
      <td>N/A</td> <!-- Member of -->
      <td>Allow to authenticate - Descendant Computer Objects</td>  <!-- Access -->
      <td>Allow</td> <!-- Access Type -->
      <td>Domain-a\enum-a / Add</td>  <!-- Access Applied to -->
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
      <td>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_2.1_computers.pcapng">Download PCAPNG File (computers)</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_2.1_computers.txt">View Program Output (computers)</a> <br> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_2.1_domain_groups.pcapng">Download PCAPNG File (domain groups)</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_2.1_domain_groups.txt">View Program Output (domain groups)</a> <br> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_2.1_local_groups.pcapng">Download PCAPNG File (local groups)</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_2.1_local_groups.txt">View Program Output (local groups)</a> <br> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_2.1_summary.pcapng">Download PCAPNG File (summary)</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_2.1_summary.txt">View Program Output (summary)</a><br> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_2.1_users.pcapng">Download PCAPNG File (users)</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_2.1_users.txt">View Program Output (users)</a>
      </td> <!-- Link -->
    </tr>
    <tr>
      <td>acl2/2</td> <!-- Scenario ID -->
      <td>Selective Authentication</td>  <!-- Forest Trust Type -->
      <td>bdc1.domain-b.local</td> <!-- Enumerated Object -->
      <td>domainDNS</td>  <!-- Enumerated Object Class -->
      <td>N/A</td> <!-- Member of -->
      <td>Allow to authenticate - Descendant Computer Objects</td>  <!-- Access -->
      <td>Allow</td> <!-- Access Type -->
      <td>Domain-a\enum-a / Add</td>  <!-- Access Applied to -->
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
      <td>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_2.2_summary.pcapng">Download PCAPNG File (summary)</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_2.2_summary.txt">View Program Output (summary)</a> <br> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_2.2_computers.pcapng">Download PCAPNG File (computers)</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_2.2_computers.txt">View Program Output (computers)</a> <br> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_2.2_domain_groups.pcapng">Download PCAPNG File (domain groups)</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_2.2_domain_groups.txt">View Program Output (domain groups)</a> <br> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_2.2_local_groups.pcapng">Download PCAPNG File (local groups)</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_2.2_local_groups.txt">View Program Output (local groups)</a><br> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_2.2_users.pcapng">Download PCAPNG File (users)</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_2.2_users.txt">View Program Output (users)</a>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_2.2_group=groupb2_gg.pcapng">Download PCAPNG File (groupb2_gg)</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_2.2_group=groupb2_gg.txt">View Program Output (groupb2_gg)</a>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_2.2_group=groupb3_ug.pcapng">Download PCAPNG File (groupb3_gg)</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_2.2_group=groupb3_ug.txt">View Program Output (groupb3_gg)</a>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_2.2_userb1_membership.pcapng">Download PCAPNG File (membership)</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_2.2_userb1_membership.txt">View Program Output (membership)</a>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_2.2_userb1.pcapng">Download PCAPNG File (userb1)</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_2.2_userb1.txt">View Program Output (userb1)</a>
      </td> <!-- Link -->
    </tr>
    <tr>
      <td>acl3/1</td> <!-- Scenario ID -->
      <td>Forest Level Authentication</td>  <!-- Forest Trust Type -->
      <td>domain-x.local</td> <!-- Enumerated Object -->
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
          python samr-enum.py target=xdc1.domain-x.local username=enum-a password=LabAdm1! opnums enumerate=users <br><br>
          python samr-enum.py target=xdc1.domain-x.local username=enum-a password=LabAdm1! opnums enumerate=computers <br><br>
          python samr-enum.py target=xdc1.domain-x.local username=Administrator password=LabAdm1@ opnums enumerate=computers <br><br>
          python samr-enum.py target=xdc1.domain-x.local username=Administrator password=LabAdm1@ opnums enumerate=users
      </td> <!-- Execution -->
    <td>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_3.1_users.pcapng">Download PCAPNG File (users)</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_3.1_users.txt">View Program Output (computers)</a><br><br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_3.1_computers.pcapng">Download PCAPNG File (users)</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_3.1_computers.txt">View Program Output (computers)</a><br><br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_3.1_users_as_local_Administrator.pcapng">Download PCAPNG File (users)</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_3.1_users_as_local_Administrator.txt">View Program Output (computers)</a><br><br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_3.1_computers_as_local_Administrator.pcapng">Download PCAPNG File (users)</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_3.1_computers_as_local_Administrator.txt">View Program Output (computers)</a><br><br> <br>
      </td> <!-- Link -->
    </tr>
    <tr>
      <td>acl3/2</td> <!-- Scenario ID -->
      <td>Selective Authentication</td>  <!-- Forest Trust Type -->
      <td>xdc1.domain-x.local</td> <!-- Enumerated Object -->
      <td>domainDNS</td>  <!-- Enumerated Object Class -->
      <td>N/A</td> <!-- Member of -->
      <td>Allow to authenticate - Descendant Computer Objects</td>  <!-- Access -->
      <td>Allow</td> <!-- Access Type -->
      <td>Domain-a\enum-a / Add</td>  <!-- Access Applied to -->
      <td>0, 6, 5, 7, 13, 34, 47, 1, 19, 25, 20, 18, 17, 46, 11, 15.</td> <!-- OpNums -->
      <td>No</td>  <!-- Errors in Traffic -->
      <td>All objects and their attributes are returned</td> <!-- Results -->
      <td>Access is granted on the domain-a.local object</td>  <!-- Notes -->
     <td>
          python samr-enum.py target=xdc1.domain-x.local username=enum-a password=LabAdm1! opnums enumerate=users <br><br>
          python samr-enum.py target=xdc1.domain-x.local username=enum-a password=LabAdm1! opnums enumerate=computers <br><br>
          python samr-enum.py target=xdc1.domain-x.local username=Administrator password=LabAdm1@ opnums enumerate=users <br><br>
          python samr-enum.py target=xdc1.domain-x.local username=Administrator password=LabAdm1@ opnums enumerate=computers
      </td> <!-- Execution -->
    <td>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_3.2_users.pcapng">Download PCAPNG File (users)</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_3.2_users.txt">View Program Output (computers)</a><br><br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_3.2_computers.pcapng">Download PCAPNG File (users)</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_3.2_computers.txt">View Program Output (computers)</a><br><br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_3.2_users_as_local_Administrator.pcapng">Download PCAPNG File (users)</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_3.2_users_as_local_Administrator.txt">View Program Output (computers)</a><br><br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_3.2_computers_as_local_Administrator.pcapng">Download PCAPNG File (users)</a> <br> <br>
          <a href="https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/acl_3.2_computers_as_local_Administrator.txt">View Program Output (computers)</a><br><br> <br>
      </td> <!-- Link -->
    </tr>
    <tr>
      <th>Scenario ID</th>  <!-- 1 -->
      <th>Forest Trust Type</th>  <!-- 2 -->
      <th>Enumerated Object Name</th>  <!-- 3 -->
      <th>Enumerated Object Class</th>  <!-- 4 -->
      <th>Member of</th>  <!-- 5 -->
      <th>Access</th>  <!-- 6 -->
      <th>Access Type</th>  <!-- 7 -->
      <th>Access Applied to / Action</th>  <!-- 8 -->
      <th>OpNums</th>  <!-- 9 -->
      <th>Error in SAMR Traffic</th>  <!-- 10 -->
      <th>Results</th>  <!-- 11 -->
      <th>Notes</th>  <!-- 12 -->
      <th>Execution</th>  <!-- 13 -->
    </tr>
  </tbody>
</table>




