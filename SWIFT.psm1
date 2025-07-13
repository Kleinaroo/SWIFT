# Import SWIFT config file
$SWIFTConfig = Join-Path -Path $PSScriptRoot -ChildPath "config.json"
If (Test-Path -Path $SWIFTConfig) 
{
	# Load the configuration file
	$SWIFTConfig = Get-Content -Path $SWIFTConfig | ConvertFrom-Json
	# Set the global variable for SWIFTConfig
	$Global:SWIFTConfig = $SWIFTConfig
}

# Functions for verifications. 

function Check-DomainAdmin
{
    <#
        .SYNOPSIS
        Checks if the current user's SamAccountName matches a specific pattern (e.g., ending with "_adm"). Must be configured prior to use.

        .DESCRIPTION
        Returns $true if the current user matches the specified pattern, otherwise returns $false and displays a message.

        .PARAMETER CurrentUser
        The username of the current user. If not provided, defaults to the environment variable UserName.

        .EXAMPLE
        $Variable = Check-DomainAdmin

        .NOTES
        Author: roothless, Copilot AI
        CODE REVIEW : 2025-07-13

    #>
	[CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [ValidateNotNullOrEmpty()]
        [string] $CurrentUser = $env:UserName
    )
    # --------------- VARIABLES -----------------
    # Configure the domain admin suffix the SamAccountName would have (e.g., "_adm")
    [bool]      $IsDomainAdmin      = $false
    [string]    $DomainAdminSuffix  = $SWIFTConfig.DomainAdminSuffix

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
Export-ModuleMember -Function "Check-DomainAdmin"

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
        Check-ADComputerExists -ComputerName "PC1234"

        .NOTES
        Author: roothless, Copilot AI
    #>
	[CmdletBinding()]
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
        Write-Verbose "Computer '$ComputerName' found in Active Directory."
    }
    Catch {
        $ComputerExists = $false
        Write-Error "Computer '$ComputerName' not found in Active Directory."
    }

    # ---- Returns $true or $false value
    Return $ComputerExists
}
Export-ModuleMember -Function "Check-ADComputerExists"

function Check-ADUserExists
{
    <#
        .SYNOPSIS
        Checks if the specified user exists in Active Directory.

        .DESCRIPTION
        Returns $true if the user exists in AD, otherwise $false.

        .PARAMETER SamAccountName
        The SamAccountName of the user to check.

        .EXAMPLE
        Check-ADUserExists -SamAccountName "jdoe"

        .NOTES
        Author: roothless, Copilot AI
    #>
    param
    (
        # ---------------------------
        [Parameter(Mandatory=$true,Position=0)]
        [ValidateNotNullOrEmpty()]
        [string] $SamAccountName
        # ---------------------------
    )
    # --------------- VARIABLES -----------------
    $UserExists = $false

    # ------------- VERIFICATIONS ---------------
    # ---- Requires Active Directory Module (RSAT)
    Check-ModuleImport -ModuleName "ActiveDirectory"

    # ---------------- ACTIONS ------------------
    # ---- Checks if SamAccountName exists in AD; returns $true or $false
    Try
    {
        $ADComputer = Get-ADUser -Identity $SamAccountName -ErrorAction Stop
        $UserExists = $true
        Write-Verbose "User '$SamAccountName' found in Active Directory."
    }
    Catch 
    {
        $UserExists = $false
        Write-Error "User '$SamAccountName' not found in Active Directory."
    }
    # ---- Returns $true or $false value
    Return $UserExists
}
Export-ModuleMember -Function "Check-ADUserExists"

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

	[CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [ValidateNotNullOrEmpty()]
        [string] $ModuleName,
        [Parameter(Mandatory=$false)]
        [bool]   $AutoImport = $true 
    )

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
Export-ModuleMember -Function "Check-ModuleImport"

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

    [CmdletBinding()]
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
        # M365 Modules
		"AzureAD"                                       { Install-Module -Name AzureAD                  -Scope CurrentUser                        -Force | Out-Null }
		"MicrosoftTeams"                                { Install-Module -Name MicrosoftTeams           -Scope CurrentUser                        -Force | Out-Null }
		"MSolService"                                   { Install-Module -Name MSOnline                 -Scope CurrentUser                        -Force | Out-Null }
        "ExchangeOnlineManagement"                      { Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -RequiredVersion 3.5.1 -Force | Out-Null }
        # PS Gallery Modules
		"ImportExcel"                                   { Install-Module -Name ImportExcel              -Scope CurrentUser                        -Force | Out-Null }
        # Local Modules
		"ConfigurationManager"                          { } # This shit is so ass to import....
        "ActiveDirectory"                               { Add-WindowsCapability -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -Online | Out-Null }
        # Graph API Modules
        "Microsoft.Graph.DeviceManagement.Enrollment"   { Install-Module -Name Microsoft.Graph.DeviceManagement.Enrollment -Scope CurrentUser    -Force | Out-Null }
	}

	Return
}
Export-ModuleMember -Function "Install-MissingModule"

function Check-M365ModuleConnection
{
	<#
		.SYNOPSIS
		Checks if a specified Microsoft 365 module is connected, and if not, attempts to connect.

		.DESCRIPTION
		This function checks the connection status of a specified Microsoft 365 module and connects if necessary.

		.PARAMETER ModuleName
		The name of the Microsoft 365 module to check (e.g., AzureAD, MicrosoftTeams, MsolService).

		.EXAMPLE
		Check-M365ModuleConnection -ModuleName "AzureAD"

		.NOTES
	#>

	[CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
        [string] $ModuleName
    )
	
    Switch($ModuleName)
    {
        "AzureAD"           { Try { Get-AzureADDomain  -ErrorAction Stop | Out-Null } Catch { Connect-AzureAD          | Out-Null }}
        "MicrosoftTeams"    { Try { Get-Team           -ErrorAction Stop | Out-Null } Catch { Connect-MicrosoftTeams   | Out-Null }}
        "MsolService"       { Try { Get-MSolDomain     -ErrorAction Stop | Out-Null } Catch { Connect-MsolService      | Out-Null }}
    }

	Return
}
Export-ModuleMember -Function "Check-M365ModuleConnection"

function Check-ComputerOnline
{
	<#
		.SYNOPSIS
		Tests if a computer is online by pinging it.

		.DESCRIPTION
		Returns $true if the computer responds to a ping, otherwise returns $false.

		.PARAMETER ComputerName
		The name of the computer to check.

		.EXAMPLE
		Check-ComputerOnline -ComputerName "PC1234"

		.NOTES
	#>

	[CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true,Position=0)]
        [ValidateNotNullOrEmpty()]
        [string] $ComputerName
    )

    # --------------- VARIABLES -----------------

    [bool] $ComputerOnline 	= $false

    # ---------------- ACTIONS ------------------

    # Checks if the device is reachable by pinging it
    Write-Verbose "`nChecking if the device $ComputerName is reachable...`n"
    Try
    {
        Test-Connection -ComputerName $ComputerName -Count 1 -ErrorAction Stop | Out-Null
        Write-Verbose "`nThe device $ComputerName is reachable.`n"
        $ComputerOnline = $true
    }
    Catch
    {
        Write-Error "`nThe device $ComputerName is currently not reachable.`n"
        $ComputerOnline = $false
    }

    # Returns $true or $false
    Return $ComputerOnline
}
Export-ModuleMember -Function "Check-ComputerOnline"

function Check-WinRMConfig
{
	<#
		.SYNOPSIS
		Checks if Windows Remote Management (WinRM) is configured and ready for remote management.

		.DESCRIPTION
		Returns $true if WinRM is ready, otherwise returns $false.

		.PARAMETER ComputerName
		The name of the computer to check. If not provided, defaults to the local computer.

		.EXAMPLE
		Check-WinRMConfig -ComputerName "PC1234"

		.NOTES
	#>

	[CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$false,Position=0)]
        [string] $ComputerName = $env:COMPUTERNAME
    )
    # --------------- VARIABLES -----------------
	[bool] $WinRMReady = $false

    # ------------- VERIFICATIONS ---------------
    $PSExecExists 	    = Check-PSExecConfig 
    If( $PSExecExists    -eq $false ){ Return }

    $ComputerOnline     = Check-ComputerOnline -ComputerName $ComputerName
    If( $ComputerOnline  -eq $false ){ Return }

    # ---------------- ACTIONS ------------------


    # ---- Windows Remote Management protocols tests
    Try
    {
		Write-Verbose "`nChecking WinRM service status on $ComputerName...`n"
		$WinRMServiceStatus = (Get-Service WinRM -ComputerName $ComputerName -ErrorAction Stop).Status
    }
    Catch { $WinRMServiceStatus = "Stopped" }
    Try
    {
		Write-Verbose "`nTesting WSMan connection to $ComputerName...`n"
        Test-WSMan -ComputerName $ComputerName -ErrorAction Stop | Out-Null
        $WSManTestPassed = $true
    }
    Catch { $WSManTestPassed = $false }

    If( ($WSManTestPassed -eq $true) -And ($WinRMServiceStatus -ne "Stopped") ) { $WinRMReady = $true 	}
    Else																		{ $WinRMReady = $false 	}
	
    # Returns $true or $false
    Return $WinRMReady
}
Export-ModuleMember -Function "Check-WinRMConfig"

function Install-WinRM
{
    <#
        .SYNOPSIS
        Installs and configures Windows Remote Management (WinRM) on a specified computer.

        .DESCRIPTION
        This function checks if WinRM is configured and ready for remote management. If not, it attempts to enable it using PSExec.

        .PARAMETER ComputerName
        The name of the computer on which to enable WinRM.

        .EXAMPLE
        Install-WinRM -ComputerName "PC1234"

        .NOTES
    #>
	param
	(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[string] $ComputerName
	)
	# --------------- VARIABLES -----------------

	[int] $Attempts = 0

    # ------------- VERIFICATIONS ---------------

    Check-PSExecConfig -ComputerName $ComputerName
    If( $PSExecExists -eq $false ) { Return }
	
    # ---------------- ACTIONS ------------------

	# Tries to enable PS Remoting on target device
	
    Do
	{
		$WinRMReady = Check-WinRMConfig -ComputerName $ComputerName
		# ---- If WinRM is OFF, attempt to turn on using PS Exec
		If( $WinRMReady -eq $false )
		{
			Write-Verbose "`nEnabling PSRemote on $ComputerName..."
			psremote $ComputerName
			$Attempts = $Attempts + 1
		}
		ElseIf( $WinRMReady -eq $true )
		{
			If($Attempts -ge 1)	{Write-Host "`nPowerShell Remoting has been activated successfully on $ComputerName." 	-ForegroundColor Green}
			Else				{Write-Host "`nPowerShell Remoting is already activated on $ComputerName." 				-ForegroundColor Green}
			$Attempts = $Attempts + 1
		}
	}Until( ($WinRMReady -eq $true) -Or ($Attempts -ge 2) )
	
    Return
}
Export-ModuleMember -Function "Install-WinRM"

function Check-PSExecConfig
{
    <#
        .SYNOPSIS
        Checks if PSExec is installed and configured correctly.

        .DESCRIPTION
        Returns $true if PSExec is found at the specified path, otherwise returns $false.

        .PARAMETER ComputerName
        The name of the computer to check.

        .EXAMPLE
        Check-PSExecConfig -ComputerName "PC1234"

        .NOTES
    #>
    param
    (
        [Parameter(Mandatory=$true,Position=0)]
        [string] $ComputerName
    )
    # --------------- VARIABLES -----------------
	# Configure the path to psexec.exe
	# Change this path if psexec.exe is located elsewhere
    [string] $PSExecPath    = If ([string]::IsNullOrWhiteSpace($SWIFTConfig.PSExecPath)) { "C:\Windows\System32\psexec.exe" } `
                              Else                                                       { $SWIFTConfig.PSExecPath }
	[bool]   $PSExecExists  = $false

    # ---------------- ACTIONS ------------------    
    # Check if psexec.exe exists at $PSExecPath
	Write-Verbose "`nChecking if PSExec is installed at $PSExecPath...`n"
    If((Test-Path $PSExecPath -PathType Leaf))
    {
        $PSExecExists = $true
    }
    Else
    {
        Write-Error "`nPSExec does not seem to be installed in $PSExecPath, please add it and try again.`n"
        $PSExecExists = $false
    }

    # Returns $true or $false
    Return $PSExecExists
}
Export-ModuleMember -Function "Check-PSExecConfig"

function psremote 
{
    <#
        .SYNOPSIS
        Enables PowerShell Remoting on a specified computer using PSExec.

        .DESCRIPTION
        This function checks if the specified computer is online, verifies PSExec configuration, and checks if the user is a domain admin before enabling PowerShell Remoting.

        .PARAMETER ComputerName
        The name of the computer on which to enable PowerShell Remoting.

        .EXAMPLE
        psremote -ComputerName "PC1234"

        .NOTES
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [ValidateNotNullOrEmpty]
        [string] $ComputerName
    )

    # ------------- VERIFICATIONS ---------------

    $ComputerOnline     = Check-ComputerOnline -ComputerName $ComputerName
    If($ComputerOnline  -eq $false){Return}

    $PSExecExists       = Check-PSExecConfig -ComputerName $ComputerName
    If($PSExecExists    -eq $false){Return}

    $IsDomainAdmin      = Requires-DomainAdmin -CurrentUser $env:UserName
    If($IsDomainAdmin   -eq $false){Return}

    # ---------------- ACTIONS ------------------
    # ---- Enable PowerShell Remoting on the target computer using PSExec
    Write-Verbose "`nEnabling PowerShell Remoting on $ComputerName...`n"
    psexec.exe \\$ComputerName -nobanner powershell.exe -c "Enable-PSRemoting"

    Return
}
Export-ModuleMember -Function "psremote"

function Get-GPU
{
    <#
        .SYNOPSIS
        Retrieves GPU (graphics card) information from a specified computer.

        .DESCRIPTION
        Connects to the specified computer and retrieves details about installed video controllers (GPUs), including their descriptions.

        .PARAMETER ComputerName
        The name of the computer from which to retrieve GPU information.

        .EXAMPLE
        Get-GPU -ComputerName "PC1234"

        Retrieves GPU information from the computer named PC1234.

        .NOTES
        Author: roothless, Copilot AI
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true,Position=0)]
        [ValidateNotNullOrEmpty()]
        [string] $ComputerName
    )

    # ------------- VERIFICATIONS ---------------

    $ComputerOnline     = Check-ComputerOnline -ComputerName $ComputerName
    If( $ComputerOnline  -eq $false ) { Return }

    $IsDomainAdmin      = Requires-DomainAdmin -CurrentUser  $env:UserName
    If( $IsDomainAdmin   -eq $false ) { Return }

    $WinRMReady         = Check-WinRMConfig             -ComputerName $ComputerName
    If( $WinRMReady      -eq $false ) { Install-WinRM   -ComputerName $ComputerName }

    # ---------------- ACTIONS ------------------

    Write-Verbose "`nRetrieving GPU information from $ComputerName...`n"
    Try 
    { $GPU = Get-WmiObject -Class win32_VideoController -ComputerName $ComputerName | Select-Object Description }
    Catch
    { Write-Error "`nFailed to retrieve GPU information from $ComputerName." ; Return }
    
    Return $GPU
}
Export-ModuleMember -Function "Get-GPU"

function Get-RAM 
{
    <#
        .SYNOPSIS
        Retrieves physical memory (RAM) information from a specified computer.

        .DESCRIPTION
        Connects to the specified computer and retrieves details about installed physical memory modules, including part number, device locator, capacity (in GB), speed, and configured clock speed.

        .PARAMETER ComputerName
        The name of the computer from which to retrieve RAM information.

        .EXAMPLE
        Get-RAM -ComputerName "PC1234"

        Retrieves RAM information from the computer named PC1234.

        .NOTES
        Author: roothless, Copilot AI
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true,Position=0)]
        [ValidateNotNullOrEmpty()]
        [string] $ComputerName
    )

    # ------------- VERIFICATIONS ---------------

    $ComputerOnline     = Check-ComputerOnline -ComputerName $ComputerName
    If( $ComputerOnline  -eq $false ) { Return }

    $IsDomainAdmin      = Requires-DomainAdmin -CurrentUser  $env:UserName
    If( $IsDomainAdmin   -eq $false ) { Return }

    $WinRMReady         = Check-WinRMConfig           -ComputerName $ComputerName
    If( $WinRMReady      -eq $false ) { Install-WinRM -ComputerName $ComputerName }

    # ---------------- ACTIONS ------------------

    Write-Verbose "`nRetrieving RAM information from $ComputerName...`n"
    Try
    { $RAMObject = Get-WmiObject -Class win32_PhysicalMemory -ComputerName $ComputerName | `
                   Select-Object PartNumber,DeviceLocator,@{ Name = 'Capacity (GB)'; Expression = { [math]::round($_.Capacity /1Gb, 3) } },Speed,ConfiguredClockSpeed }
    Catch
    { Write-Error "`nFailed to retrieve RAM information from $ComputerName." ; Return }

    Return $RAMInfo
}
Export-ModuleMember -Function "Get-RAM"

function Get-SerialNumber
{
    <#
        .SYNOPSIS
        Retrieves the BIOS serial number from a specified computer.

        .DESCRIPTION
        Connects to the specified computer and retrieves the BIOS serial number using WMI.

        .PARAMETER ComputerName
        The name of the computer from which to retrieve the BIOS serial number.

        .EXAMPLE
        Get-SerialNumber -ComputerName "PC1234"

        Retrieves the BIOS serial number from the computer named PC1234.

        .NOTES
        Author: roothless, Copilot AI
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$false,Position=0)]
        [ValidateNotNullOrEmpty()]
        [string] $ComputerName
    )

    # ------------- VERIFICATIONS ---------------

    $ComputerOnline     = Check-ComputerOnline -ComputerName $ComputerName
    If( $ComputerOnline  -eq $false ) { Return }

    $IsDomainAdmin      = Requires-DomainAdmin -CurrentUser  $env:UserName
    If( $IsDomainAdmin   -eq $false ) { Return }

    $WinRMReady         = Check-WinRMConfig           -ComputerName $ComputerName
    If( $WinRMReady      -eq $false ) { Install-WinRM -ComputerName $ComputerName }

    # ---------------- ACTIONS ------------------

    Write-Verbose "`nRetrieving BIOS serial number from $ComputerName...`n"
    Try
    { $SerialNumber = Get-WmiObject -Class win32_bios -ComputerName $ComputerName | Select-Object SerialNumber }
    Catch
    { Write-Error "`nFailed to retrieve serial number from $ComputerName." ; Return }
    
    Return $SerialNumber
}
Export-ModuleMember -Function "Get-SerialNumber"