# Get dev authtoken
Function Get-AuthToken($Url, $UserName, $Password, $TenantName )
{
    Import-Module UiPath.PowerShell;
    $token = Get-UiPathAuthToken -URL $Url -Username $UserName -Password $Password -Session -TenantName $TenantName;
    return $token
}

# Parse group name
Function Parse-GroupName($GroupName)
{
    $parts = $GroupName.split("-")
    $length = $parts.length
    $env = $parts[1]
    $tenant = $parts[2]
    $role = $parts[3]
    $folder = $parts[4]
    return $env, $tenant, $role, $folder
}

# Get list of group members by email
Function Get-GroupMembers($GroupName)
{
    $members = @()
    Import-Module ActiveDirectory;
    try {
        $groupMembers = Get-ADGroupMember -Identity $GroupName;
        
    } catch {
        Write-host $Error[0]
        return $null
    }
    foreach($groupMember in $groupMembers)
    {
        $adUser = Get-ADUser -Identity $groupMember;
        $members += $aduser.UserPrincipalName;
    }
    return $members;
}

Function Get-UsersWithTenantRole($Token, $UiPathRoleName)
{
    $UserWithRole = @()
    Import-Module UiPath.PowerShell
    $users = Get-UiPathUser -AuthToken $Token;
    foreach($user in $users) 
    {
        $found  = $user.RolesList|Where { $_ -eq $UiPathRoleName}
        if($found) {
            $UserWithRole += $user.UserName;
        }
    }
    return $UserWithRole;
}

Function Get-UsersWithFolderRole($Token, $UiPathFolderName, $UiPathRoleName)
{
    $UserWithFolderRole = @()
    Import-Module UiPath.PowerShell
    $folder = Get-UiPathFolder -AuthToken $token -DisplayName $UiPathFolderName
    if($folder -eq $null) {
        Write-Host ("Cannot find folder {0}" -f $UiPathFolderName)
        return $null
    }
    $folder_users = Get-UiPathFolderUsers -AuthToken $token -Folder $folder
    foreach($folder_user in $folder_users) {
        $UserEntity = $folder_user.UserEntity
        $FolderUserRoles = $folder_user.Roles
        foreach($roleDto in $FolderUserRoles) {
            $RoleName = $roleDto.Name
            if($RoleName -eq $UiPathRoleName) {
                Write-Host $("User {0} have the role {1}" -f $folder_user.Id, $RoleName)
                $UserWithFolderRole += $UserEntity.UserName
            }
        }
    }
    return $UserWithFolderRole
}
 

# Add a user to a tenant role. Create the account if it does not exist.
Function Add-UserToTenantRole($Token, $UserEmail, $UiPathRoleName, $Tenant, $Env)
{
    Import-Module UiPath.PowerShell;

    # Get the user 
    $UiPathUser = Get-UiPathUser -AuthToken $token -Username $UserEmail

    # Create the user
    if($UiPathUser -eq $null) 
    {
        Write-Host ("[+] Adding user {0} in {1} {2} with Add-UiPathUser." -f $UserEmail, $Tenant, $Env);

        Add-UiPathUser -AuthToken $token -Domain $Domain -EmailAddress $UserEmail;
            
        $UiPathUser = Get-UiPathUser -AuthToken $token -Username $UserEmail
    }
    
    # Get the role    
    $Role = Get-UiPathRole -AuthToken $Token | Where { $_.Name -eq $UiPathRoleName}

    if($Role -eq $null) {
        Write-Host ("The role {0} does not exists in {1}/{2}." -f $UiPathRoleName, $env, $tenant)
        throw "error"
    }
 
    Write-Host ("[+] Adding user: {0} to role: {1} in {2}/{3}" -f $UiPathUser.Id, $role, $tenant, $env)

    # Add role to user in tenant.
    Edit-UiPathRoleUser $Role -Add $UiPathUser.Id
}

# Add a user to folder role. Create the account if it does not exist.
Function Add-UserToFolderRole($Token, $UserEmail, $UiPathFolderName, $UiPathRoleName, $Tenant, $Env)
{
    Import-Module UiPath.PowerShell;
    
    # Get the user 
    $UiPathUser = Get-UiPathUser -AuthToken $Token -Username $UserEmail

    if($UiPathUser -eq $null) 
    {
        # Create the user account
        Write-Host ("[+] Adding user {0} in {1} {2} with Add-UiPathUser." -f $UserEmail, $Tenant, $Env);

        Add-UiPathUser -AuthToken $token -Domain $Domain -EmailAddress $UserEmail;

        $UiPathUser = Get-UiPathUser -AuthToken $Token -Username $UserEmail
    }
    
    # Get the folder
    $UiPathFolder = Get-UiPathFolder -AuthToken $Token -DisplayName $UiPathFolderName

    if($UiPathFolder -eq $null) {
        Write-Host ("The folder {0} does not exists in {1}/{2}." -f $UiPathFolderName, $env, $tenant)
        throw "error"

    }

    # Get the role    
    $Role = Get-UiPathRole -AuthToken $Token | Where { $_.Name -eq $UiPathRoleName}

    if($Role -eq $null) {
        Write-Host ("The role {0} does not exists in {1}/{2}." -f $UiPathRoleName, $env, $tenant)
        throw "error"
    }

    write-host ("[+] Adding user: {0} to folder: {1} in {2}/{3}" -f $UiPathUser.Id, $UiPathFolderName, $tenant, $env)

    # Add user to role in folder.
    Add-UiPathFolderUserRoles -Id $UiPathFolder.Id -AuthToken $Token -UserIds $UiPathUser.Id -RoleIds $Role.Id  

}

Function Compare-Lists($left_group, $right_group)
{
    if($left_group -eq $null) {
        $left_group = @()
    }

    if($right_group -eq $null) {
        $right_group = @()

    }
    $objects = @{
        ReferenceObject = @($left_group)
        DifferenceObject = @($right_group)
    };
    
    $results = $(Compare-Object @objects -IncludeEqual);
    

    $only_in_left_group   = $results|Where { $_.SideIndicator -eq "<=" };
    $only_in_right_group  = $results|Where { $_.SideIndicator -eq "=>" };
    $member_of_both       = $results|Where { $_.SIdeIndicator -eq "==" };

    $result = @{
        MembersToAdd = @()
        MembersToRemove = @()
        MembersTheSame = @()
    }

    if($only_in_left_group) 
    {
        $member_list = $only_in_left_group|Select-Object -Property InputObject -ExpandProperty InputObject;
        $result['MembersToAdd'] = $member_list;
    }

    
    if($only_in_right_group) 
    {
        $member_list = $only_in_right_group|Select-Object -Property InputObject -ExpandProperty InputObject;
        $result['MembersToRemove'] = $member_list;
    }
    
    if($member_of_both) 
    {
        $member_list = $member_of_both|Select-Object -Property InputObject -ExpandProperty InputObject;
        $result['MembersTheSame'] = $member_list;
    }

    return $result;
}

# Convert rpa role name to UiPath Role Name.
Function ConvertToUiPathRoleName($rpa_role_name) {
    return (Get-Culture).TextInfo.ToTitleCase($rpa_role_name)
}

Function Remove-UserFromTenantRole($Token, $UserEmail, $UiPathRoleName, $Tenant, $Env)
{
    Import-Module UiPath.PowerShell;
    $user = Get-UiPathUser -AuthToken $Token -Username $UserEmail; 
    $uipath_role = Get-UiPathRole -AuthToken $token -Name $UiPathRoleName; 
    write-host ("[+] Removing role membership for user: {0} from role: {1} in {2}/{3}" -f $user.Id, $UiPathRoleName, $Tenant, $env)
    Edit-UiPathRoleUser $uipath_role -Remove $user.Id
}

Function Remove-UserFromFolderRole($Token, $UserEmail, $UiPathFolderName, $UiPathRoleName, $Tenant, $Env)
{
    $UiPathFolder = Get-UiPathFolder -AuthToken $Token -DisplayName $UiPathFolderName
    $FolderUsers  = Get-UiPathFolderUsers -Id $UiPathFolder.Id -AuthToken $Token
    $UiPathRole = Get-UiPathRole -AuthToken $Token -Name $UiPathRoleName
    $FolderUsers  = Get-UiPathFolderUsers -Id $UiPathFolder.Id -AuthToken $Token
    $FolderUser = $FolderUsers|Where { $_.UserEntity.UserName -eq $UserEmail }
    $NotRole = $FolderUser.Roles|Where { $_.Id -ne $UiPathRole.Id}
    $RolesToKeep = @()
    foreach($Role in $NotRole) {
        $RolesToKeep += $Role.Id
    }  
    Add-UiPathFolderUserRoles -Id $UiPathFolder.Id -AuthToken $Token -UserIds $UiPathUser.Id -RoleIds  $RolesToKeep
}
 
Function Remove-UserFromUiPathRole($Token, $UserEmail, $UiPathRoleName, $Tenant, $Env)
{
    Import-Module UiPath.PowerShell;
    $user = Get-UiPathUser -AuthToken $Token -Username $UserEmail; 
    $uipath_role = Get-UiPathRole -AuthToken $token -Name $UiPathRoleName; 
    write-host ("[+] Removing role membership for user: {0} from role: {1} in {2}/{3}" -f $user.Id, $UiPathRoleName, $Tenant, $env)
    Edit-UiPathRoleUser $uipath_role -Remove $user.Id
}


Function PerformSync([string]$rpa_group_name, [string]$syncusername=$("syncuser"), [string]$syncuser_password)
{
    # Print group name to sync
    Write-Host ("PerformSync on {0}" -f $rpa_group_name)

    # Parse Group information
    $env_name, $tenant_name, $role_name, $folder_name = Parse-GroupName -GroupName $rpa_group_name;
    $uipath_rolename            = ConvertToUiPathRoleName -rpa_role_name $role_name;

    # Authenticate to env/tenant
    Write-Host ("Get token for {0}/{1}" -f $env_name, $tenant_name)
    try {
        $token =  Get-AuthToken -UserName "syncuser" -Password $syncuser_password -TenantName $tenant_name;
        Write-Host $("Got token:")
        $token

    } catch {
       Write-Host ("Cannot authenticate to {0}/{1}" -f $env_name, $tenant_name)
       Write-Host ("Returning to caller.")
       return $null;
    }

    # Get the role
    Write-Host ("Get role: {0}" -f $uipath_rolename)
    $Role = Get-UiPathRole -AuthToken $token | Where { $_.Name -eq $uipath_rolename}
    if($Role -eq $null) {
        Write-Host ("The role {0} does not exists in {1}/{2}." -f $uipath_rolename, $env_name, $tenant_name)
        throw "error"
    }

    # Get the folder
    Write-Host ("Get folder: {0}" -f $folder_name)
    $folder = Get-UiPathFolder -AuthToken $token -DisplayName $folder_name
    if($folder -eq $null) {
        Write-Host ("Cannot find folder {0}" -f $folder_name)
    }

    # Get member list of the target (tenant or folder)

    Write-Host ("Get target memberslist for  ")
    $TargetMemberList = $()
    if($folder) 
    {
        Write-Host ("the folder/role: {0}/{1}`n" -f $folder_name, $uipath_rolename)
        $TargetMemberList =  Get-UsersWithFolderRole -Token $token -UiPathFolderName $folder_name -UiPathRoleName $uipath_rolename
        if($TargetMemberList  -eq $null) 
        {
            Write-Host $("The role members list for folder {0} is empty in {1}/{2}/{3}.`n" -f $folder_name, $env_name, $tenant_name, $role_name);
        }
    } 
    else 
    {
        Write-Host ("the tenant/role: {0}/{1}`n" -f $tenant_name, $uipath_rolename)
        $TargetMemberList = Get-UsersWithTenantRole -Token $token -UiPathRoleName $uipath_rolename;

        if($TargetMemberList  -eq $null) {
            Write-Host $("The role members list is empty in {0}/{1}/{2}.`n" -f $env_name, $tenant_name, $role_name);
        }
    }
    Write-Host ("The target memberlist has {0} members.`n" -f $TargetMemberList.Count)

    # Get member list of source (AD Group)
    $SourceMemberList = @()
    Write-Host ("Get memberlist for the source group {0}" -f $rpa_group_name)
    $SourceMemberList = Get-GroupMembers -GroupName $rpa_group_name;


    if($SourceMemberList -eq $null) 
    {
        Write-Host ("Memberlist for source group {0} is empty.`n" -f $rpa_group_name)
    }

    Write-Host ("The source memberlist has {0} members.`n" -f $SourceMemberList.Count)

    Write-Host ("Comparing source and target member lists.")
    $compare = Compare-Lists -left_group $SourceMemberList -right_group $TargetMemberList;
    Write-Host "Comparision results:"
    $compare

    if($compare.MembersToAdd) {
        Write-Host ("Found members to ADD from the source to the target list")
        foreach($memberEmail in $compare.MembersToAdd) 
        {
            Write-Host $("Adding member {0} to role {1}/{2}/{3}." -f $memberEmail, $env_name, $tenant_name, $role_name);
            Add-UserToTenantRole -Token $token -UserEmail $memberEmail -UiPathRoleName $uipath_rolename -Tenant $tenant_name -Env $env_name;
            if($folder) 
            {
                Write-Host $("Adding member {0} to folder {1}/{2}/{3}." -f $memberEmail, $env_name, $tenant_name, $folder_name);
                Add-UserToFolderRole -Token $token -UserEmail $memberEmail -UiPathFolderName $folder_name  -UiPathRoleName  $uipath_rolename -Tenant $tenant_name -Env $env_name;
            }
        }
    }

    if($compare.MembersToRemove) {
        Write-Host ("Found members to REMOVE from the target list")
        foreach($memberEmail in $compare.MembersToRemove) 
        {
            Write-Host $("Removing member {0} from {1}/{2}/{3}." -f $memberEmail,$env_name, $tenant_name, $folder_name);
            Remove-UserFromUiPathRole -Token $token -UserEmail $memberEmail -UiPathRoleName  $uipath_rolename -Tenant $tenant_name -Env $env_name;
            if($folder) {
                Write-Host $("Removing member {0} from folder {1}/{2}/{3}." -f $memberEmail, $env_name, $tenant_name, $folder_name);
                $folder = Get-UiPathFolder -AuthToken $token -DisplayName $folder
                $UiPathUser = Get-UiPathUser -AuthToken $token -Username $memberEmail;
                $UserPathUser
                Remove-UserFromFolderRole -AuthToken $token -Folder $folder_name -UserId $UiPathUser.Id
            }
        }
    } 

    if($compare.MembersTheSame) {
        Write-Host ("The member lists are the same in source and target, nothing to do.") 
    } 
}
