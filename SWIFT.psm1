# Functions for verifications. 

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
        Author: roothless, Copilot AI
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

function Check-ADComputerExists
{
    <#
        .SYNOPSIS
        Checks if the specified computer exists in Active Directory.

        .DESCRIPTION
        Returns $true if the computer exists in AD, otherwise $false.

        .PARAMETER ComputerName
        The name of the computer to check.

        .EXAMPLE
        Check-ADComputerExists -ComputerName "MTLWKS1234"

        .NOTES
        Author: roothless, Copilot AI
    #>
    param
    (
        [Parameter(Mandatory=$true,Position=0)]
        [ValidateNotNullOrEmpty()]
        [string] $ComputerName
    )

    # --------------- VARIABLES -----------------
    [bool] $ComputerExists = $false

    # ------------- VERIFICATIONS ---------------
    # ---- Requires Active Directory Module (RSAT)
    Check-ModuleImport -ModuleName "ActiveDirectory"

    # ---------------- ACTIONS ------------------
    # ---- Checks if ComputerName exists in AD; returns $true or $false
    Try {
        $ADComputer     = Get-ADComputer -Identity $ComputerName -ErrorAction Stop
        $ComputerExists = $true
    }
    Catch {
        Write-Verbose "Computer '$ComputerName' not found in Active Directory."
        $ComputerExists = $false
    }

    # ---- Returns $true or $false value
    Return $ComputerExists
}
Export-ModuleMember -Function "Check-ADComputerExists"

function Check-ModuleImport
{
    <#
        .SYNOPSIS
        Checks if a specified module is imported or available for import.

        .DESCRIPTION
        If the module is not imported, it attempts to import it. If the module is not installed, it installs and imports it.

        .PARAMETER ModuleName
        The name of the module to check.

        .PARAMETER AutoImport
        If set to $true, the function will attempt to install and import the module if it is not found.

        .EXAMPLE
        Check-ModuleImport -ModuleName "ActiveDirectory"

        .NOTES
    #>
    param
    (
        [Parameter(Mandatory=$true,Position=0)]
        [ValidateNotNullOrEmpty()]
        [string] $ModuleName,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [bool]   $AutoImport = $true
    )

	function Install-MissingModule
	{
		<#
			.SYNOPSIS
			Installs a specified PowerShell module if it is not already installed.

			.DESCRIPTION
			This function checks if a module is available for installation and installs it if it is not already present.

			.PARAMETER ModuleName
			The name of the module to install.

			.EXAMPLE
			Install-MissingModule -ModuleName "AzureAD"

			.NOTES
		#>
		param
		(
			[Parameter(Mandatory=$true,Position=0)]
			[ValidateNotNullOrEmpty()]
			[string] $ModuleName
		)

		# List of all modules you want to install if they are missing.
		# Add more modules as needed.

		Switch($ModuleName)
		{
			"AzureAD"                                       {Install-Module -Name AzureAD -Scope CurrentUser | Out-Null}
			"MicrosoftTeams"                                {Install-Module -Name MicrosoftTeams -Scope CurrentUser | Out-Null}
			"MSolService"                                   {Install-Module -Name MSOnline -Scope CurrentUser | Out-Null}
			"ActiveDirectory"                               {Add-WindowsCapability -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -Online | Out-Null}
			"ImportExcel"                                   {Install-Module -Name ImportExcel -Scope CurrentUser | Out-Null}
			"Microsoft.Graph.DeviceManagement.Enrollment"   {Install-Module -Name Microsoft.Graph.DeviceManagement.Enrollment -Scope CurrentUser | Out-Null}
			"ConfigurationManager"                          {}
			"ExchangeOnlineManagement"                      {Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -RequiredVersion 3.5.1 -Force | Out-Null}
		}

		Return
	}
	
    If( -Not ((Get-Module).Name -contains "$ModuleName") )
    {
        If( $AutoImport -eq $true )
        {
            If( -Not ((get-module -ListAvailable -Name $ModuleName).Name -Contains "$ModuleName") )
            {
                # Not imported, not installed : Installing and Importing
                Write-Verbose "`nMissing Module : $ModuleName" -ForegroundColor Yellow
                Write-Verbose "Installing..."

                Install-MissingModule -ModuleName $ModuleName

                Write-Verbose "Importing...`n"

                Import-MissingModule -ModuleName $ModuleName
            }
            Else
            {
                # Installed, not imported : Importing
                Write-Verbose "`nModule Not Imported : $ModuleName" -ForegroundColor Yellow
                Write-Verbose "Importing...`n"

                Import-MissingModule -ModuleName $ModuleName
            }
        }
    }

    Return
}