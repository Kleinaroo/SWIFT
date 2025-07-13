function Requires-DomainAdmin
{
    <#
        .SYNOPSIS
        Checks if the current user's SamAccountName matches a specific pattern (e.g., ending with "_adm"). Must be configured prior to use.

        .DESCRIPTION
        Returns $true if the current user matches the specified pattern, otherwise returns $false and displays a message.

        .PARAMETER CurrentUser
        The username of the current user. If not provided, defaults to the environment variable UserName.

        .EXAMPLE
        $Variable = Requires-DomainAdmin

        .NOTES
        CODE REVIEW : 2025-07-13

    #>
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [ValidateNotNullOrEmpty()]
        [string] $CurrentUser = $env:UserName
    )
    # --------------- VARIABLES -----------------
    # Configure the domain admin suffix the SamAccountName would have (e.g., "_adm")
    [bool]      $IsDomainAdmin      = $false
    [string]    $DomainAdminSuffix  = ""

    # ------------- VERIFICATIONS ---------------
    # No module required

    # ---------------- ACTIONS ------------------
    # ---- Checks if terminal user is using username_eic account; returns $true or $false
    If ( $CurrentUser -like "*$DomainAdminSuffix" ) { 
        $IsDomainAdmin = $true }
    Else {
        # If the user does not match the pattern, set IsDomainAdmin to false and display an error message
        $IsDomainAdmin = $false
        Write-Error "`nThis cmdlet requires elevation ( Domain Admin ($DomainAdminSuffix) )`n"
    }
    
    # ---- Returns $true or $false
    Return $IsDomainAdmin
}