﻿#########################################################################################
#
# Copyright (c) Microsoft Corporation. All rights reserved.
#
# Localized PSGet.Resource.psd1
#
#########################################################################################

ConvertFrom-StringData @'
###PSLOC
        InstallModulewhatIfMessage=Version '{1}' of module '{0}'
        InstallScriptwhatIfMessage=Version '{1}' of script '{0}'
        UpdateModulewhatIfMessage=Version '__OLDVERSION__' of module '{0}', updating to version '{1}'
        UpdateScriptwhatIfMessage=Version '__OLDVERSION__' of script '{0}', updating to version '{1}'
        PublishModulewhatIfMessage=Version '{0}' of module '{1}'
        PublishScriptwhatIfMessage=Version '{0}' of script '{1}'
        NewScriptFileInfowhatIfMessage=Creating the '{0}' PowerShell Script file
        UpdateScriptFileInfowhatIfMessage=Updating the '{0}' PowerShell Script file
        NameShouldNotContainWildcardCharacters=The specified name '{0}' should not contain any wildcard characters, please correct it and try again.
        AllVersionsCannotBeUsedWithOtherVersionParameters=You cannot use the parameter AllVersions with RequiredVersion, MinimumVersion or MaximumVersion in the same command.
        VersionRangeAndRequiredVersionCannotBeSpecifiedTogether=You cannot use the parameters RequiredVersion and either MinimumVersion or MaximumVersion in the same command. Specify only one of these parameters in your command.
        RequiredVersionAllowedOnlyWithSingleModuleName=The RequiredVersion parameter is allowed only when a single module name is specified as the value of the Name parameter, without any wildcard characters.
        MinimumVersionIsGreaterThanMaximumVersion=The specified MinimumVersion '{0}' is greater than the specified MaximumVersion '{1}'.
        InstallModuleNeedsCurrentUserScopeParameterForNonAdminUser=Administrator rights are required to install modules in '{0}'. Log on to the computer with an account that has Administrator rights, and then try again, or install '{1}' by adding "-Scope CurrentUser" to your command. You can also try running the Windows PowerShell session with elevated rights (Run as Administrator).
        InstallScriptNeedsCurrentUserScopeParameterForNonAdminUser=Administrator rights are required to install scripts in '{0}'. Log on to the computer with an account that has Administrator rights, and then try again, or install '{1}' by adding "-Scope CurrentUser" to your command. You can also try running the Windows PowerShell session with elevated rights (Run as Administrator).
        AdministratorRightsNeededOrSpecifyCurrentUserScope=Administrator rights are required to install or update. Log on to the computer with an account that has Administrator rights, and then try again, or install by adding "-Scope CurrentUser" to your command. You can also try running the Windows PowerShell session with elevated rights (Run as Administrator).
        VersionParametersAreAllowedOnlyWithSingleName=The RequiredVersion, MinimumVersion, MaximumVersion or AllVersions parameters are allowed only when you specify a single name as the value of the Name parameter, without any wildcard characters.
        PathIsNotADirectory=The specified path '{0}' is not a valid directory.
        ModuleAlreadyInstalled=Version '{0}' of module '{1}' is already installed at '{2}'. To delete version '{3}' and install version '{4}', run Install-Module, and add the -Force parameter.
        ScriptAlreadyInstalled=Version '{0}' of script '{1}' is already installed at '{2}'. To delete version '{3}' and install version '{4}', run Install-Script, and add the -Force parameter.
        CommandAlreadyAvailable=A command with name '{0}' is already available on this system. This script '{0}' may override the existing command. If you still want to install this script '{0}', use -Force parameter.
        ModuleAlreadyInstalledSxS=Version '{0}' of module '{1}' is already installed at '{2}'. To install version '{3}', run Install-Module and add the -Force parameter, this command will install version '{5}' in side-by-side with version '{4}'.
        ModuleAlreadyInstalledVerbose=Version '{0}' of module '{1}' is already installed at '{2}'.
        ScriptAlreadyInstalledVerbose=Version '{0}' of script '{1}' is already installed at '{2}'.
        ModuleWithRequiredVersionAlreadyInstalled=Version '{0}' of module '{1}' is already installed at '{2}'. To reinstall this version '{3}', run Install-Module or Updated-Module cmdlet with the -Force parameter.
        InvalidPSModule=The module '{0}' cannot be installed or updated because it is not a properly-formed module.
        InvalidPowerShellScriptFile=The script '{0}' cannot be installed or updated because it is not a properly-formed script.
        InvalidAuthenticodeSignature=The module '{0}' cannot be installed or updated because the Authenticode signature for the file '{1}' is not valid.
        ModuleNotInstalledOnThisMachine=Module '{0}' was not updated because no valid module was found in the module directory. Verify that the module is located in the folder specified by $env:PSModulePath.
        ScriptNotInstalledOnThisMachine=Script '{0}' was not updated because no valid script was found in the script directories '{1}' and '{2}'.
        AdminPrivilegesRequiredForUpdate=Module '{0}' (installed at'{1}') cannot be updated because Administrator rights are required to change that directory. Log on to the computer with an account that has Administrator rights, and then try again. You can also try running the Windows PowerShell session with elevated rights (Run as Administrator).
        AdminPrivilegesRequiredForScriptUpdate=Script '{0}' (installed at'{1}') cannot be updated because Administrator rights are required to change that script. Log on to the computer with an account that has Administrator rights, and then try again. You can also try running the Windows PowerShell session with elevated rights (Run as Administrator).
        ModuleNotInstalledUsingPowerShellGet=Module '{0}' was not installed by using Install-Module, so it cannot be updated.
        ScriptNotInstalledUsingPowerShellGet=Script '{0}' was not installed by using Install-Script, so it cannot be updated.
        DownloadingModuleFromGallery=Downloading module '{0}' with version '{1}' from the repository '{2}'.
        DownloadingScriptFromGallery=Downloading script '{0}' with version '{1}' from the repository '{2}'.
        NoUpdateAvailable=No updates were found for module '{0}'.
        NoScriptUpdateAvailable=No updates were found for module '{0}'.
        FoundModuleUpdate=An update for the module '{0}' was found with version '{1}'.
        FoundScriptUpdate=An update for the script '{0}' was found with version '{1}'.
        InvalidPSModuleDuringUpdate= Module '{0}' was not updated because the module in the repository '{1}' is not a valid Windows PowerShell module.
        ModuleGotUpdated=Module '{0}' has been updated successfully.
        TestingModuleInUse=Testing if the module to update is in use.
        ModuleDestination= The specified module will be installed in '{0}'.
        ScriptDestination= The specified script will be installed in '{0}' and its dependent modules will be installed in '{1}'.
        ModuleIsInUse=Module '{0}' is in currently in use or you don't have the required permissions.
        ModuleInstalledSuccessfully=Module '{0}' was installed successfully to path '{1}'.
        ModuleSavedSuccessfully=Module '{0}' was saved successfully to path '{1}'.
        ScriptInstalledSuccessfully=Script '{0}' was installed successfully to path '{1}'.
        ScriptSavedSuccessfully=Script '{0}' was saved successfully to path '{1}'.
        CheckingForModuleUpdate= Checking for updates for module '{0}'.
        CheckingForScriptUpdate= Checking for updates for script '{0}'.
        ModuleInUseWithProcessDetails=The version '{0}' of module '{1}' is currently in use. Retry the operation after closing the following applications: '{2}'.
        ModuleVersionInUse=The version '{0}' of module '{1}' is currently in use. Retry the operation after closing the applications.
        ModuleNotAvailableLocally=The specified module '{0}' was not published because no module with that name was found in any module directory.
        InvalidModulePathToPublish=The specified module with path '{0}' was not published because no valid module was found with that path.
        ModuleWithRequiredVersionNotAvailableLocally= The specified module '{0}' with version '{1}' was not published because no module with that name and version was found in any module directory.        
        AmbiguousModuleName=Modules with the name '{0}' are available under multiple paths. Add the -RequiredVersion parameter or the -Path parameter to specify the module to publish.
        AmbiguousModulePath=Multiple versions are available under the specified module path '{0}'. Specify the full path to the module to be published.
        PublishModuleLocation=Module '{0}' was found in '{1}'.
        InvalidModuleToPublish=Module '{0}' cannot be published because it does not have a module manifest file. Run New-ModuleManifest -Path <PathName> to create a module manifest with metadata before publishing.         
        MissingRequiredManifestKeys=Module '{0}' cannot be published because it is missing required metadata. Verify that the module manifest specifies Description and Author.
        ModuleVersionShouldBeGreaterThanGalleryVersion=Module '{0}' with version '{1}' cannot be published. The version must exceed the current version '{2}' that exists in the repository '{3}', or you must specify -Force.
        ModuleVersionIsAlreadyAvailableInTheGallery=The module '{0}' with version '{1}' cannot be published as the current version '{2}' is already available in the repository '{3}'.
        CouldNotInstallNuGetProvider=NuGet provider is required to interact with NuGet-based repositories. Please ensure that '{0}' or newer version of NuGet provider is installed.
        CouldNotInstallNuGetExe=NuGet.exe is required to interact with NuGet-based repositories. Please ensure that NuGet.exe is available under one of the paths specified in PATH environment variable value.
        CouldNotInstallNuGetBinaries2=PowerShellGet requires NuGet.exe and NuGet provider version '{0}' or newer to interact with the NuGet-based repositories. Please ensure that '{0}' or newer version of NuGet provider is installed and NuGet.exe is available under one of the paths specified in PATH environment variable value.        
        InstallNuGetProviderShouldContinueQuery=PowerShellGet requires NuGet provider version '{0}' or newer to interact with NuGet-based repositories. The NuGet provider must be available in '{1}' or '{2}'. You can also install the NuGet provider by running 'Install-PackageProvider -Name NuGet -MinimumVersion {0} -Force'. Do you want PowerShellGet to install and import the NuGet provider now?
        InstallNuGetBinariesShouldContinueQuery2=PowerShellGet requires NuGet.exe and NuGet provider version '{0}' or newer to interact with the NuGet-based repositories. The NuGet provider must be available in '{1}' or '{2}'. You can also install the NuGet provider by running 'Install-PackageProvider -Name NuGet -MinimumVersion {0} -Force'. NuGet.exe must be available in '{3}' or '{4}, or under one of the paths specified in PATH environment variable value. NuGet.exe can be downloaded from https://nuget.org/nuget.exe. Do you want PowerShellGet to install both NuGet.exe and NuGet provider now?
        InstallNuGetExeShouldContinueQuery=PowerShellGet requires NuGet.exe to publish an item to the NuGet-based repositories. NuGet.exe must be available in '{0}' or '{1}, or under one of the paths specified in PATH environment variable value. NuGet.exe can be downloaded from https://nuget.org/nuget.exe. Do you want PowerShellGet to install NuGet.exe now?
        InstallNuGetBinariesShouldContinueCaption2=NuGet.exe and NuGet provider are required to continue
        InstallNuGetProviderShouldContinueCaption=NuGet provider is required to continue
        InstallNuGetExeShouldContinueCaption=NuGet.exe is required to continue        
        DownloadingNugetExe=Installing NuGet.exe.
        DownloadingNugetProvider=Installing NuGet provider.        
        ModuleNotFound=Module '{0}' was not found.
        NoMatchFound=No match was found for the specified search criteria and module names '{0}'.
        NoMatchFoundForScriptName=No match was found for the specified search criteria and script names '{0}'.
        FailedToCreateCompressedModule=Failed to generate the compressed file for module '{0}'.
        FailedToPublish=Failed to publish module '{0}': '{1}'.
        PublishedSuccessfully=Successfully published module '{0}' to the module publish location '{1}'. Please allow few minutes for '{2}' to show up in the search results.
        InvalidWebUri=The specified Uri '{0}' for parameter '{1}' is an invalid Web Uri. Please ensure that it meets the Web Uri requirements.
        RepositoryAlreadyRegistered=The repository could not be registered because there exists a registered repository with Name '{0}' and SourceLocation '{1}'. To register another repository with Name '{2}', please unregister the existing repository using the Unregister-PSRepository cmdlet.
        RepositoryToBeUnregisteredNotFound=The repository '{0}' was not removed because no repository was found with that name. Please run Get-PSRepository and ensure that a repository of that name is present.
        RepositoryCannotBeUnregistered=The specified repository '{0}' cannot be unregistered.
        RepositoryNotFound=No repository with the name '{0}' was found.
        PSGalleryNotFound=Unable to find repository '{0}'. Use Get-PSRepository to see all available repositories. Try again after specifying a valid repository name. You can use 'Register-PSRepository -Default' to register the PSGallery repository.
        ParameterIsNotAllowedWithPSGallery=The PSGallery repository has pre-defined locations. The '{0}' parameter is not allowed, try again after removing the '{0}' parameter.
        UseDefaultParameterSetOnRegisterPSRepository=Use 'Register-PSRepository -Default' to register the PSGallery repository.
        RepositoryNameContainsWildCards=The repository name '{0}' should not have wildcards, correct it and try again.
        InvalidRepository=The specified repository '{0}' is not a valid registered repository name. Please ensure that '{1}' is a registered repository.
        RepositoryRegistered=Successfully registered the repository '{0}' with source location '{1}'.
        RepositoryUnregistered=Successfully unregistered the repository '{0}'.
        PSGalleryPublishLocationIsMissing=The specified repository '{0}' does not have a valid PublishLocation. Retry after setting the PublishLocation for repository '{1}' to a valid NuGet publishing endpoint using the Set-PSRepository cmdlet.
        PSRepositoryScriptPublishLocationIsMissing=The specified repository '{0}' does not have a valid ScriptPublishLocation. Retry after setting the ScriptPublishLocation for repository '{1}' to a valid NuGet publishing endpoint using the Set-PSRepository cmdlet.
        ScriptSourceLocationIsMissing=The specified repository '{0}' does not have a valid ScriptSourceLocation. Retry after setting the ScriptSourceLocation for repository '{0}' to a valid NuGet endpoint for scripts using the Set-PSRepository cmdlet.
        PublishModuleSupportsOnlyNuGetBasedPublishLocations=Publish-Module only supports the NuGet-based publish locations. The PublishLocation '{0}' of the repository '{1}' is not a NuGet-based publish location. Retry after setting the PublishLocation for repository '{1}' to a valid NuGet publishing endpoint using the Set-PSRepository cmdlet.        
        PublishScriptSupportsOnlyNuGetBasedPublishLocations=Publish-Script only supports the NuGet-based publish locations. The ScriptPublishLocation '{0}' of the repository '{1}' is not a NuGet-based publish location. Retry after setting the ScriptPublishLocation for repository '{1}' to a valid NuGet publishing endpoint using the Set-PSRepository cmdlet.
        DynamicParameterHelpMessage=The dynamic parameter '{0}' is required for Find-Module and Install-Module when using the PackageManagement provider '{1}' and source location '{2}'. Please enter your value for the '{3}' dynamic parameter:
        ProviderApiDebugMessage=In PowerShellGet Provider - '{0}'.
        ModuleUninstallNotSupported=Module uninstallation is not supported. To remove a module, please delete the module folder.
        FastPackageReference=The FastPackageReference is '{0}'.
        PackageManagementProviderIsNotAvailable=The specified PackageManagement provider '{0}' is not available.
        SpecifiedSourceName=Using the specified source names : '{0}'.
        SpecifiedLocationAndOGP=The specified Location is '{0}' and PackageManagementProvider is '{1}'.
        NoSourceNameIsSpecified=The -Repository parameter was not specified.  PowerShellGet will use all of the registered repositories.
        GettingPackageManagementProviderObject=Getting the provider object for the PackageManagement Provider '{0}'.        
        InvalidInputObjectValue=Invalid value is specified for InputObject parameter.
        SpecifiedInstallationScope=The installation scope is specified to be '{0}'.
        SourceLocationValueForPSGalleryCannotBeChanged=The SourceLocation value for the PSGallery repository can not be changed.
        PublishLocationValueForPSGalleryCannotBeChanged=The PublishLocation value for the PSGallery repository can not be changed.
        SpecifiedProviderName=The specified PackageManagement provider name '{0}'.
        ProviderNameNotSpecified=User did not specify the PackageManagement provider name, trying with the provider name '{0}'.
        SpecifiedProviderNotAvailable=The specified PackageManagement provider '{0}' is not available.        
        SpecifiedProviderDoesnotSupportPSModules=The specified PackageManagement Provider '{0}' does not support PowerShell Modules. PackageManagement Providers must support the 'supports-powershell-modules' feature.
        PollingPackageManagementProvidersForLocation=Polling available PackageManagement Providers to find one that can support the specified source location '{0}'.
        PollingSingleProviderForLocation=Resolving the source location '{0}' with PackageManagement Provider '{1}'.
        FoundProviderForLocation=The PackageManagement provider '{0}' supports the source location '{1}'.
        SpecifiedLocationCannotBeRegistered=The specified location '{0}' cannot be registered.
        RepositoryDetails=Repository details, Name = '{0}', Location = '{1}'; IsTrusted = '{2}'; IsRegistered = '{3}'.
        NotSupportedPowerShellGetFormatVersion=The specified module '{0}' with PowerShellGetFormatVersion '{1}' is not supported by the current version of PowerShellGet. Get the latest version of the PowerShellGet module to install this module, '{2}'.
        NotSupportedPowerShellGetFormatVersionScripts=The specified script '{0}' with PowerShellGetFormatVersion '{1}' is not supported by the current version of PowerShellGet. Get the latest version of the PowerShellGet module to install this script, '{2}'.
        PathNotFound=Cannot find the path '{0}' because it does not exist.
        ModuleIsNotTrusted=Untrusted module '{0}'.        
        ScriptIsNotTrusted=Untrusted script '{0}'.
        SkippedModuleDependency=Because dependent module '{0}' was skipped in the module dependencies list, users might not know how to install it.        
        MissingExternallyManagedModuleDependency=The externally managed, dependent module '{0}' is not installed on this computer. To use the current module '{1}', ensure that its dependent module '{2}' is installed.        
        ExternallyManagedModuleDependencyIsInstalled=The externally managed, dependent module '{0}' is already installed on this computer.        
        ScriptMissingExternallyManagedModuleDependency=The externally managed, dependent module '{0}' is not installed on this computer. To use the current script '{1}', ensure that its dependent module '{2}' is installed.        
        ScriptMissingExternallyManagedScriptDependency=The externally managed, dependent module '{0}' is not installed on this computer. To use the current script '{1}', ensure that its dependent script '{2}' is installed.
        ScriptExternallyManagedScriptDependencyIsInstalled=The externally managed, dependent script '{0}' is already installed on this computer.        
        UnableToResolveModuleDependency=PowerShellGet cannot resolve the module dependency '{0}' of the module '{1}' on the repository '{2}'. Verify that the dependent module '{3}' is available in the repository '{4}'. If this dependent module '{5}' is managed externally, add it to the ExternalModuleDependencies entry in the PSData section of the module manifest.
        FindingModuleDependencies=Finding module dependencies for version '{1}' of the module '{0}' from repository '{2}'.
        InstallingDependencyModule=Installing the dependency module '{0}' with version '{1}' for the module '{2}'.
        InstallingDependencyScript=Installing the dependency script '{0}' with version '{1}' for the script '{2}'.
        SavingDependencyModule=Saving the dependency module '{0}' with version '{1}' for the module '{2}'.
        SavingDependencyScript=Saving the dependency script '{0}' with version '{1}' for the script '{2}'.
        ModuleUninstallationSucceeded=Successfully uninstalled the module '{0}' from module base '{1}'.
        ScriptUninstallationSucceeded=Successfully uninstalled the script '{0}' from script base '{1}'.
        AdminPrivilegesRequiredForUninstall=You cannot uninstall the module '{0}' from '{1}' because Administrator rights are required to uninstall from that folder. Log on to the computer with an account that has Administrator rights, and then try again. You can also try running the Windows PowerShell session with elevated rights (Run as Administrator).
        AdminPrivilegesRequiredForScriptUninstall=You cannot uninstall the script '{0}' from '{1}' because Administrator rights are required to uninstall from that folder. Log on to the computer with an account that has Administrator rights, and then try again. You can also try running the Windows PowerShell session with elevated rights (Run as Administrator).
        ModuleUninstallationNotPossibleAsItIsNotInstalledUsingPowerShellGet=Module '{0}' was not installed on this computer by using either the PowerShellGet cmdlets or the PowerShellGet provider, so it cannot be uninstalled.
        ScriptUninstallationNotPossibleAsItIsNotInstalledUsingPowerShellGet=Script '{0}' was not installed on this computer by using either the PowerShellGet cmdlets or the PowerShellGet provider, so it cannot be uninstalled.
        UnableToUninstallModuleVersion=The module '{0}' of version '{1}' in module base folder '{2}' was installed without side-by-side version support. Some versions are installed in this module base with side-by-side version support. Uninstall other versions of this module before uninstalling the most current version.
        UnableToUninstallAsOtherModulesNeedThisModule=The module '{0}' of version '{1}' in module base folder '{2}' cannot be uninstalled, because one or more other modules '{3}' are dependent on this module. Uninstall the modules that depend on this module before uninstalling module '{4}'.
        UnableToUninstallAsOtherScriptsNeedThisScript=The script '{0}' of version '{1}' in script base folder '{2}' cannot be uninstalled, because one or more other scripts '{3}' are dependent on this script. Uninstall the scripts that depend on this script before uninstalling script '{4}'.
        RepositoryIsNotTrusted=Untrusted repository
        QueryInstallUntrustedPackage=You are installing the modules from an untrusted repository. If you trust this repository, change its InstallationPolicy value by running the Set-PSRepository cmdlet. Are you sure you want to install the modules from '{1}'?
        QueryInstallUntrustedScriptPackage=You are installing the scripts from an untrusted repository. If you trust this repository, change its InstallationPolicy value by running the Set-PSRepository cmdlet. Are you sure you want to install the scripts from '{1}'?
        QuerySaveUntrustedPackage=You are downloading the modules from an untrusted repository. If you trust this repository, change its InstallationPolicy value by running the Set-PSRepository cmdlet. Are you sure you want to download the modules from '{1}'?
        QuerySaveUntrustedScriptPackage=You are downloading the scripts from an untrusted repository. If you trust this repository, change its InstallationPolicy value by running the Set-PSRepository cmdlet. Are you sure you want to download the scripts from '{1}'?
        SourceNotFound=Unable to find repository '{0}'. Use Get-PSRepository to see all available repositories.
        PSGalleryApiV2Deprecated=PowerShell Gallery v2 has been deprecated.  Please run 'Update-Module -Name PowerShellGet' to update to PowerShell Gallery v3.  For more information, please visit our website at 'https://www.powershellgallery.com'.
        PSGalleryApiV2Discontinued=PowerShell Gallery v2 has been discontinued.  Please run 'Update-Module -Name PowerShellGet' to update to PowerShell Gallery v3.  For more information, please visit our website at 'https://www.powershellgallery.com'.
        PowerShellGalleryUnavailable=PowerShell Gallery is currently unavailable.  Please try again later.
        PowerShellGetModuleIsNotInstalledProperly=The PowerShellGet module was not installed properly. Be sure that only one instance or version of the PowerShellGet module is installed in the path '{0}'.
        PowerShelLGetModuleGotUpdated=The PowerShellGet module was updated successfully. Restart the process to use the updated version of the PowerShellGet module.
        TagsShouldBeIncludedInManifestFile=Tags are now supported in the module manifest file (.psd1). Update the module manifest file of module '{0}' in '{1}' with the newest tag changes. You can run Update-ModuleManifest -Tags to update the manifest with tags.
        ReleaseNotesShouldBeIncludedInManifestFile=ReleaseNotes is now supported in the module manifest file (.psd1). Update the module manifest file of module '{0}' in '{1}' with the newest ReleaseNotes changes. You can run Update-ModuleManifest -ReleaseNotes to update the manifest with ReleaseNotes.
        LicenseUriShouldBeIncludedInManifestFile=LicenseUri is now supported in the module manifest file (.psd1). Update the module manifest file of module '{0}' with the newest LicenseUri changes. You can run Update-ModuleManifest -LicenseUri to update the manifest with LicenseUri.
        IconUriShouldBeIncludedInManifestFile=IconUri is now supported in the module manifest file (.psd1). Update the module manifest file of module '{0}' in '{1}' with the newest IconUri changes. You can run Update-ModuleManifest -IconUri to update the manifest with IconUri.
        ProjectUriShouldBeIncludedInManifestFile=ProjectUri is now supported in the module manifest file (.psd1). Update the module manifest file of module '{0}' in '{1}' with the newest ProjectUri changes. You can run Update-ModuleManifest -ProjectUri to update the manifest with ProjectUri.
        ShouldIncludeFunctionsToExport=This module '{0}' has exported functions. As a best practice, include exported functions in the module manifest file(.psd1). You can run Update-ModuleManifest -FunctionsToExport to update the manifest with ExportedFunctions field.
        ShouldIncludeCmdletsToExport=This module '{0}' has exported cmdlets. As a best practice, include exported cmdlets in the module manifest file(.psd1). You can run Update-ModuleManifest -CmdletsToExport to update the manifest with ExportedCmdlets field.
        ShouldIncludeDscResourcesToExport=This module '{0}' has exported DscResources. As a best practice, include exported DSC resources in the module manifest file(.psd1). If your PowerShell version is higher than 5.0, run Update-ModuleManifest -DscResourcesToExport to update the manifest with ExportedDscResources field.
        UpdateModuleManifestPathCannotFound=Cannot load the manifest file '{0}' properly. Please specify the correct manifest path.
        UpdatedModuleManifestNotValid=Cannot update the manifest file '{0}' because the manifest is not valid. Verify that the manifest file is valid, and then try again.'{1}'
        ExportedDscResourcesNotSupportedOnLowerPowerShellVersion=The ExportedDscResources property is not supported in module manifests on PowerShell versions that are older than 5.0. Remove the value for the parameter 'DscResourcesToExport', and then try again.
        CompatiblePSEditionsNotSupportedOnLowerPowerShellVersion=The CompatiblePSEditions property is not supported in module manifests on PowerShell versions that are older than 5.1. Remove the value for the parameter 'CompatiblePSEditions', and then try again.
        ExternalModuleDependenciesNotSpecifiedInRequiredOrNestedModules='{0}' is listed in ExternalModuleDependencies, but it is not found in either the RequiredModules or NestedModules properties. Verify that this module is required for ExternalModuleDependencies, and then add it to NestedModules or RequiredModules.
        TestModuleManifestFail=Cannot update the manifest properly. '{0}'
        PackageManagementProvidersNotInModuleBaseFolder=PackageManagementProvider '{0}' is not found in the module base '{1}'. Verify that the PackageManagementProvider specified is within the module base.
        UpdateManifestContentMessage=Update manifest file with new contents:
        InvalidPackageManagementProviderValue=The PackageManagementProvider value cannot be '{0}'. Valid values for provider names include '{1}', and the default value for this parameter is '{2}'.
        PowerShellGetUpdateIsNotSupportedOnLowerPSVersions=Self update of the PowerShellGet module is supported only in PowerShell 5.0 and newer releases. It is not supported in PowerShell 3.0 or 4.0.
        ScriptVersionShouldBeGreaterThanGalleryVersion=Script '{0}' with version '{1}' cannot be published. The version must exceed the current version '{2}' that exists in the repository '{3}', or you must specify -Force.
        ScriptVersionIsAlreadyAvailableInTheGallery=The script '{0}' with version '{1}' cannot be published as the current version '{2}' is already available in the repository '{3}'.
        ScriptParseError=The specified script file '{0}' has parse errors, try again after fixing the parse errors.
        InvalidScriptToPublish=Script file '{0}' cannot be published because it does not have the required script metadata. Run Update-ScriptFileInfo -Path '{1}' to add the script metadata.
        FailedToCreateCompressedScript=Failed to generate the compressed file for script '{0}'.
        FailedToPublishScript=Failed to publish script '{0}': '{1}'.
        PublishedScriptSuccessfully=Successfully published script '{0}' to the publish location '{1}'. Please allow few minutes for '{2}' to show up in the search results.
        UnableToResolveScriptDependency=PowerShellGet cannot resolve the {0} dependency '{1}' of the script '{2}' on the repository '{3}'. Verify that the dependent {0} '{1}' is available in the repository '{3}'. If this dependent {0} '{1}' is managed externally, add it to the '{4}' entry in the script metadata.
        InvalidVersion=Cannot convert value '{0}' to type 'System.Version'. 
        InvalidGuid=Cannot convert value '{0}' to type 'System.Guid'.
        InvalidParameterValue=The specified value '{0}' for the parameter '{1}' is invalid. Ensure that it does not contain '<#' or '#>'.
        MissingPSScriptInfo=PSScriptInfo is not specified in the script file '{0}'. You can use the Update-ScriptFileInfo with -Force or New-ScriptFileInfo cmdlet to add the PSScriptInfo to the script file.
        MissingRequiredPSScriptInfoProperties=Script '{0}' is missing required metadata properties. Verify that the script file has Version, Guid, Description and Author properties. You can use the Update-ScriptFileInfo or New-ScriptFileInfo cmdlet to add or update the PSScriptInfo to the script file.
        SkippedScriptDependency=Because dependent script '{0}' was skipped in the script dependencies list, users might not know how to install it.
        SourceLocationPathsForModulesAndScriptsShouldBeEqual=SourceLocation '{0}' and ScriptSourceLocation '{1}' should be same for SMB Share or Local directory based repositories.
        SourceLocationUrisForModulesAndScriptsShouldBeDifferent=SourceLocation '{0}' and ScriptSourceLocation '{1}' should not be same for URI based repositories.
        PublishLocationPathsForModulesAndScriptsShouldBeEqual=PublishLocation '{0}' and ScriptPublishLocation '{1}' should be same for SMB Share or Local directory based repositories.
        SpecifiedNameIsAlearyUsed=The specified name '{0}' is already used for a different item on the specified repository '{1}'. Run '{2} -Name {0} -Repository {1}' to check whether the specified name '{0}' is already taken.
        InvalidScriptFilePath=The script file path '{0}' is not valid. The value of the Path argument must resolve to a single file that has a '.ps1' extension. Change the value of the Path argument to point to a valid ps1 file, and then try again.
        NuGetApiKeyIsRequiredForNuGetBasedGalleryService=NuGetApiKey is required for publishing a module or script file to the specified repository '{0}' whose publish location is '{1}'. Try again after specifying a valid value for the NuGetApiKey parameter. To get your API key, view your profile page.
        ScriptFileExist=The specified script file '{0}' already exists.
        PublishPSArtifactUnsupportedOnNano=Publish-{0} is not supported on Nano Server and PowerShellCore.
        InvalidEnvironmentVariableName=The specified environment variable name '{0}' exceeded the allowed limit of '{1}' characters.
        PublishLocation=Publish Location:'{0}'.
        ScriptPATHPromptCaption=PATH Environment Variable Change
        ScriptPATHPromptQuery=Your system has not been configured with a default script installation path yet, which means you can only run a script by specifying the full path to the script file. This action places the script into the folder '{0}', and adds that folder to your PATH environment variable. Do you want to add the script installation path '{0}' to the PATH environment variable?
        AddedScopePathToProcessSpecificPATHVariable=Added scripts installation location '{0}' for '{1}' scope to process specific PATH environment variable.
        AddedScopePathToPATHVariable=Added scripts installation location '{0}' for '{1}' scope to PATH environment variable. 
        FilePathInFileListNotWithinModuleBase=Path '{0}' defined in FileList is not within module base '{1}'. Provide the correct FileList parameters and then try again.
        ManifestFileReadWritePermissionDenied=The current user does not have read-write permissions for the file:'{0}'. Check the file permissions and then try again.
        MissingTheRequiredPathOrPassThruParameter=The Path or PassThru parameter is required for creating the script file info. A new script file will be created with the script file info when the Path parameter is specified. Script file info will be returned if the PassThru parameter is specified. Try again after specifying the required parameter.
        DescriptionParameterIsMissingForAddingTheScriptFileInfo=Description parameter is missing for adding the metadata to the script file. Try again after specifying the description.
        UnableToAddPSScriptInfo=Unable to add PSScriptInfo to the script file '{0}'. You can use the New-ScriptFileInfo cmdlet to add the metadata to the existing script file.
        RegisterVSTSFeedAsNuGetPackageSource=Publishing to a VSTS package management feed '{0}' requires it to be registered as a NuGet package source. Retry after adding this source '{0}' as NuGet package source by following the instructions specified at '{1}'        
        InvalidModuleAuthenticodeSignature=The module '{0}' cannot be installed or updated because the authenticode signature of the file '{1}' is not valid.
        InvalidCatalogSignature=The module '{0}' cannot be installed because the catalog signature in '{1}' does not match the hash generated from the module.
        AuthenticodeIssuerMismatch=Authenticode issuer '{0}' of the new module '{1}' with version '{2}' is not matching with the authenticode issuer '{3}' of the previously-installed module '{4}' with version '{5}'. If you still want to install or update, use -SkipPublisherCheck parameter.
        ModuleCommandAlreadyAvailable=The following commands are already available on this system:'{0}'. This module '{1}' may override the existing commands. If you still want to install this module '{1}', use -AllowClobber parameter.
        CatalogFileFound=Found the catalog file '{0}' in the module '{1}' contents.        
        CatalogFileNotFoundInAvailableModule=Catalog file '{0}' is not found in the contents of the previously-installed module '{1}' with the same name.
        CatalogFileNotFoundInNewModule=Catalog file '{0}' is not found in the contents of the module '{1}' being installed.
        ValidAuthenticodeSignature=Valid authenticode signature found in the catalog file '{0}' for the module '{1}'.
        ValidAuthenticodeSignatureInFile=Valid authenticode signature found in the file '{0}' for the module '{1}'.
        ValidatingCatalogSignature=Validating the '{0}' module files for catalog signing using the catalog file '{1}'.
        AuthenticodeIssuerMatch=Authenticode issuer '{0}' of the new module '{1}' with version '{2}' matches with the authenticode issuer '{3}' of the previously-installed module '{4}' with version '{5}'.
        ValidCatalogSignature=The catalog signature in '{0}' of the module '{1}' is valid and matches with the hash generated from the module contents.
        SkippingPublisherCheck=Skipping the Publisher check for the version '{0}' of module '{1}'.
        SourceModuleDetailsForPublisherValidation=For publisher validation, using the previously-installed module '{0}' with version '{1}' under '{2}' with publisher name '{3}'. Is this module signed by Microsoft: '{4}'.
        NewModuleVersionDetailsForPublisherValidation=For publisher validation, current module '{0}' with version '{1}' with publisher name '{2}'. Is this module signed by Microsoft: '{3}'.
        PublishersMatch=Publisher '{0}' of the new module '{1}' with version '{2}' matches with the publisher '{3}' of the previously-installed module '{4}' with version '{5}'. Both versions are signed with a Microsoft root certificate.        
        PublishersMismatch=A Microsoft-signed module named '{0}' with version '{1}' that was previously installed conflicts with the new module '{2}' from publisher '{3}' with version '{4}'. Installing the new module may result in system instability. If you still want to install or update, use -SkipPublisherCheck parameter.
        ModuleIsNotCatalogSigned=The version '{0}' of the module '{1}' being installed is not catalog signed. Ensure that the version '{0}' of the module '{1}' has the catalog file '{2}' and signed with the same publisher '{3}' as the previously-installed module '{1}' with version '{4}' under the directory '{5}'. If you still want to install or update, use -SkipPublisherCheck parameter.
        SentEnvironmentVariableChangeMessage=Successfully broadcasted the Environment variable changes.
        UnableToSendEnvironmentVariableChangeMessage=Error in broadcasting the Environment variable changes.
        LicenseUriNotSpecified='LicenseUri' is not specified. 'LicenseUri' must be provided when user license acceptance is required.
        LicenseTxtNotFound=License.txt not Found. License.txt must be provided when user license acceptance is required.
        LicenseTxtEmpty=License.txt is empty.
        requireLicenseAcceptanceNotSupported=Require License Acceptance is not supported on Format version '{0}'.
        AcceptanceLicenseQuery=Do you accept the license terms for module '{0}'.
        ForceAcceptLicense=License Acceptance is required for module '{0}'. Please specify '-AcceptLicense' to perform this operation.
        InvalidValueBoolean=The specified value '{0}' for the parameter '{1}' is invalid. It should be $true or $false.
        UserDeclinedLicenseAcceptance=User declined license acceptance.
        AcceptLicense=License Acceptance
        RequiredScriptVersion=REQUIREDSCRIPTS: Required version of script '{0}' is '{1}'.
        RequiredScriptVersoinFormat=<ScriptName>, <ScriptName>:<MinimumVersion>, <ScriptName>:[<RequiredVersion>], <ScriptName>:[<MinimumVersion>,<MaximumVersion>], <ScriptName>:[,<MaximumVersion>]
        FailedToParseRequiredScripts=Cannot parse REQUIREDSCRIPTS '{0}'. Acceptable formats are: '{1}'.
        FailedToParseRequiredScriptsVersion=Version format error: {0}, '{1}'. Acceptable formats are: '{2}'. 
###PSLOC
'@


# SIG # Begin signature block
# MIIarQYJKoZIhvcNAQcCoIIanjCCGpoCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUOFI6oF1fH0Yrz+QME2JT3/Ev
# S8+gghWAMIIEwjCCA6qgAwIBAgITMwAAALwLLhp7irHHkQAAAAAAvDANBgkqhkiG
# 9w0BAQUFADB3MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSEw
# HwYDVQQDExhNaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EwHhcNMTYwOTA3MTc1ODQ3
# WhcNMTgwOTA3MTc1ODQ3WjCBsjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEMMAoGA1UECxMDQU9DMScwJQYDVQQLEx5uQ2lwaGVyIERTRSBFU046
# MTJCNC0yRDVGLTg3RDQxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNl
# cnZpY2UwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCrW5IBRZQaAQPT
# HTCSXDRgGi/lbqVTqt3Mp5XqqbEkIZowQp8M/Gyv+1TmRpbFaQIQ4oQ7AqZRsvd+
# PMGtZjo6vUBRyeLKpnHq1a9XYeiGkoGaJu/98Ued3Z+sFD45bhzi6tLzY6kq98KI
# YqK7XsI76kqVU3oIyiETzzoANwuXUNSnm9lAN3l/G8xgDm/3qBWMSjkBvg2GeZ57
# 3WqYP6fImkO9U0bRtuIr6mybzvXUUO+rg6hhdrEnLGI4QQ7frEWReYeyMlgjC7VR
# aJy2gomkh+sEmxxivphgOuJrtPgUhdIlyTkUTtyudNUd/6gTE4zt9TsmFf5wGCsx
# pbZqKFW3AgMBAAGjggEJMIIBBTAdBgNVHQ4EFgQUyHJk5pJfz0FWFyn1nlRJFHyq
# /vcwHwYDVR0jBBgwFoAUIzT42VJGcArtQPt2+7MrsMM1sw8wVAYDVR0fBE0wSzBJ
# oEegRYZDaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMv
# TWljcm9zb2Z0VGltZVN0YW1wUENBLmNybDBYBggrBgEFBQcBAQRMMEowSAYIKwYB
# BQUHMAKGPGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljcm9z
# b2Z0VGltZVN0YW1wUENBLmNydDATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG
# 9w0BAQUFAAOCAQEAPiS9UtetZjCdEkaanFlC+NU/Ti+PUD6O+P6yCASPI6+qK20t
# B16FXJg7rXRee3c/E2wcyWuxeL/0oLkj4LunxQoDDhoOjM9w9SnrWjki/kbkEdbg
# i1Pl4ebDSu+6Six3fdRrLowgkQwXxkCoUWwyFS9dL5BbC5lSzHlOiXiWVlc94vr3
# 9sMaoqsxl6A6Ud9YvbohYuiKJsdpSrLW97wXO66h+Cx289JckOmomW1Zum3ppfgp
# +5lJJBxySomU08S8G5QOOrvjO4KsQ55eHHVWJXhnGL+zhghaSf5TIQuDdohDOnNb
# +FImqnwn3++hmpbkAVWdFUNDNlJemia/hMH9vzCCBOswggPToAMCAQICEzMAAAF4
# JVq1zSPGX5UAAQAAAXgwDQYJKoZIhvcNAQEFBQAweTELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEjMCEGA1UEAxMaTWljcm9zb2Z0IENvZGUgU2ln
# bmluZyBQQ0EwHhcNMTcwODExMjAxMTE1WhcNMTgwODExMjAxMTE1WjCBgjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEMMAoGA1UECxMDQU9DMR4w
# HAYDVQQDExVNaWNyb3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUA
# A4IBDwAwggEKAoIBAQCZbh1TVaudsrIbXUPPB9c8S+E+dKSbskHKYlG6SGTH8jhT
# hpuvGiAO87F2b9GHVN+DvszaMkGy/xQgHaGEJLfpnb3kpakic7E0bjDHdG4KnHRb
# no/wfUkGLfS79o+cw//RY8Ck6yE+0czDBcxp0Gbw5JyGP+KFqvzRR/3Tv3nt/5x0
# 5ZnEOHYP+eDVikDvn/DH+oxxtiCfX3tkvtm/yX4eOb47YdmYKQjCgz2+Nil/lupY
# vU0QFIjvke3jshqQINDng/vO9ys2qA0ex/q5hlLKQTST99dGoM86Ge6F723ReToq
# KnGLN8kiCG7uNapOAIQrpCHZq96CVumiaA5ZvxU9AgMBAAGjggFgMIIBXDATBgNV
# HSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUjuhtD3FD7tk/RKloJFX05cpgLjcw
# UQYDVR0RBEowSKRGMEQxDDAKBgNVBAsTA0FPQzE0MDIGA1UEBRMrMjI5ODAzKzFh
# YmY5ZTVmLWNlZDAtNDJlNi1hNjVkLWQ5MzUwOTU5ZmUwZTAfBgNVHSMEGDAWgBTL
# EejK0rQWWAHJNy4zFha5TJoKHzBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3Js
# Lm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNDb2RTaWdQQ0FfMDgt
# MzEtMjAxMC5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY0NvZFNpZ1BDQV8wOC0zMS0y
# MDEwLmNydDANBgkqhkiG9w0BAQUFAAOCAQEAYnG/oHG/xgZYR8NAMHZ/vE9GM0e4
# 7YdhuTea2uY7pSGwM707wp8Wan0Fa6evK1PWfcd/XNOh2BpEv5o8RmKDoEsG0ECP
# 13Jug7cklfKreBVHQ+Djg43VVFLZpuo7aOAVK6wjlcnpPUtn+SfH9K0aM2FjDKVJ
# FW6XFKXBat5R+Zp6uOxWTxpSeMTeDC5zF6IY6ogR1uzU+9EQoRlAvkwX6po+exEL
# nMLr4++P+fqOxIU+PODIoB8ijClAqwwKvLlMPa3qlrNHt+LweTMu7lvGC/RA18wU
# zzXAeomuZ03blUw+bkOiVgWOk4S0RN7EnW7zjJV8gd/+G2dbToUi1cB/fTCCBbww
# ggOkoAMCAQICCmEzJhoAAAAAADEwDQYJKoZIhvcNAQEFBQAwXzETMBEGCgmSJomT
# 8ixkARkWA2NvbTEZMBcGCgmSJomT8ixkARkWCW1pY3Jvc29mdDEtMCsGA1UEAxMk
# TWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5MB4XDTEwMDgzMTIy
# MTkzMloXDTIwMDgzMTIyMjkzMloweTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEjMCEGA1UEAxMaTWljcm9zb2Z0IENvZGUgU2lnbmluZyBQQ0Ew
# ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCycllcGTBkvx2aYCAgQpl2
# U2w+G9ZvzMvx6mv+lxYQ4N86dIMaty+gMuz/3sJCTiPVcgDbNVcKicquIEn08Gis
# TUuNpb15S3GbRwfa/SXfnXWIz6pzRH/XgdvzvfI2pMlcRdyvrT3gKGiXGqelcnNW
# 8ReU5P01lHKg1nZfHndFg4U4FtBzWwW6Z1KNpbJpL9oZC/6SdCnidi9U3RQwWfjS
# jWL9y8lfRjFQuScT5EAwz3IpECgixzdOPaAyPZDNoTgGhVxOVoIoKgUyt0vXT2Pn
# 0i1i8UU956wIAPZGoZ7RW4wmU+h6qkryRs83PDietHdcpReejcsRj1Y8wawJXwPT
# AgMBAAGjggFeMIIBWjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTLEejK0rQW
# WAHJNy4zFha5TJoKHzALBgNVHQ8EBAMCAYYwEgYJKwYBBAGCNxUBBAUCAwEAATAj
# BgkrBgEEAYI3FQIEFgQU/dExTtMmipXhmGA7qDFvpjy82C0wGQYJKwYBBAGCNxQC
# BAweCgBTAHUAYgBDAEEwHwYDVR0jBBgwFoAUDqyCYEBWJ5flJRP8KuEKU5VZ5KQw
# UAYDVR0fBEkwRzBFoEOgQYY/aHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9j
# cmwvcHJvZHVjdHMvbWljcm9zb2Z0cm9vdGNlcnQuY3JsMFQGCCsGAQUFBwEBBEgw
# RjBEBggrBgEFBQcwAoY4aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0
# cy9NaWNyb3NvZnRSb290Q2VydC5jcnQwDQYJKoZIhvcNAQEFBQADggIBAFk5Pn8m
# Rq/rb0CxMrVq6w4vbqhJ9+tfde1MOy3XQ60L/svpLTGjI8x8UJiAIV2sPS9MuqKo
# VpzjcLu4tPh5tUly9z7qQX/K4QwXaculnCAt+gtQxFbNLeNK0rxw56gNogOlVuC4
# iktX8pVCnPHz7+7jhh80PLhWmvBTI4UqpIIck+KUBx3y4k74jKHK6BOlkU7IG9KP
# cpUqcW2bGvgc8FPWZ8wi/1wdzaKMvSeyeWNWRKJRzfnpo1hW3ZsCRUQvX/TartSC
# Mm78pJUT5Otp56miLL7IKxAOZY6Z2/Wi+hImCWU4lPF6H0q70eFW6NB4lhhcyTUW
# X92THUmOLb6tNEQc7hAVGgBd3TVbIc6YxwnuhQ6MT20OE049fClInHLR82zKwexw
# o1eSV32UjaAbSANa98+jZwp0pTbtLS8XyOZyNxL0b7E8Z4L5UrKNMxZlHg6K3RDe
# ZPRvzkbU0xfpecQEtNP7LN8fip6sCvsTJ0Ct5PnhqX9GuwdgR2VgQE6wQuxO7bN2
# edgKNAltHIAxH+IOVN3lofvlRxCtZJj/UBYufL8FIXrilUEnacOTj5XJjdibIa4N
# XJzwoq6GaIMMai27dmsAHZat8hZ79haDJLmIz2qoRzEvmtzjcT3XAH5iR9HOiMm4
# GPoOco3Boz2vAkBq/2mbluIQqBC0N1AI1sM9MIIGBzCCA++gAwIBAgIKYRZoNAAA
# AAAAHDANBgkqhkiG9w0BAQUFADBfMRMwEQYKCZImiZPyLGQBGRYDY29tMRkwFwYK
# CZImiZPyLGQBGRYJbWljcm9zb2Z0MS0wKwYDVQQDEyRNaWNyb3NvZnQgUm9vdCBD
# ZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMDcwNDAzMTI1MzA5WhcNMjEwNDAzMTMw
# MzA5WjB3MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSEwHwYD
# VQQDExhNaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EwggEiMA0GCSqGSIb3DQEBAQUA
# A4IBDwAwggEKAoIBAQCfoWyx39tIkip8ay4Z4b3i48WZUSNQrc7dGE4kD+7Rp9FM
# rXQwIBHrB9VUlRVJlBtCkq6YXDAm2gBr6Hu97IkHD/cOBJjwicwfyzMkh53y9Gcc
# LPx754gd6udOo6HBI1PKjfpFzwnQXq/QsEIEovmmbJNn1yjcRlOwhtDlKEYuJ6yG
# T1VSDOQDLPtqkJAwbofzWTCd+n7Wl7PoIZd++NIT8wi3U21StEWQn0gASkdmEScp
# ZqiX5NMGgUqi+YSnEUcUCYKfhO1VeP4Bmh1QCIUAEDBG7bfeI0a7xC1Un68eeEEx
# d8yb3zuDk6FhArUdDbH895uyAc4iS1T/+QXDwiALAgMBAAGjggGrMIIBpzAPBgNV
# HRMBAf8EBTADAQH/MB0GA1UdDgQWBBQjNPjZUkZwCu1A+3b7syuwwzWzDzALBgNV
# HQ8EBAMCAYYwEAYJKwYBBAGCNxUBBAMCAQAwgZgGA1UdIwSBkDCBjYAUDqyCYEBW
# J5flJRP8KuEKU5VZ5KShY6RhMF8xEzARBgoJkiaJk/IsZAEZFgNjb20xGTAXBgoJ
# kiaJk/IsZAEZFgltaWNyb3NvZnQxLTArBgNVBAMTJE1pY3Jvc29mdCBSb290IENl
# cnRpZmljYXRlIEF1dGhvcml0eYIQea0WoUqgpa1Mc1j0BxMuZTBQBgNVHR8ESTBH
# MEWgQ6BBhj9odHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0
# cy9taWNyb3NvZnRyb290Y2VydC5jcmwwVAYIKwYBBQUHAQEESDBGMEQGCCsGAQUF
# BzAChjhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY3Jvc29m
# dFJvb3RDZXJ0LmNydDATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG9w0BAQUF
# AAOCAgEAEJeKw1wDRDbd6bStd9vOeVFNAbEudHFbbQwTq86+e4+4LtQSooxtYrhX
# AstOIBNQmd16QOJXu69YmhzhHQGGrLt48ovQ7DsB7uK+jwoFyI1I4vBTFd1Pq5Lk
# 541q1YDB5pTyBi+FA+mRKiQicPv2/OR4mS4N9wficLwYTp2OawpylbihOZxnLcVR
# DupiXD8WmIsgP+IHGjL5zDFKdjE9K3ILyOpwPf+FChPfwgphjvDXuBfrTot/xTUr
# XqO/67x9C0J71FNyIe4wyrt4ZVxbARcKFA7S2hSY9Ty5ZlizLS/n+YWGzFFW6J1w
# lGysOUzU9nm/qhh6YinvopspNAZ3GmLJPR5tH4LwC8csu89Ds+X57H2146SodDW4
# TsVxIxImdgs8UoxxWkZDFLyzs7BNZ8ifQv+AeSGAnhUwZuhCEl4ayJ4iIdBD6Svp
# u/RIzCzU2DKATCYqSCRfWupW76bemZ3KOm+9gSd0BhHudiG/m4LBJ1S2sWo9iaF2
# YbRuoROmv6pH8BJv/YoybLL+31HIjCPJZr2dHYcSZAI9La9Zj7jkIeW1sMpjtHhU
# BdRBLlCslLCleKuzoJZ1GtmShxN1Ii8yqAhuoFuMJb+g74TKIdbrHk/Jmu5J4PcB
# ZW+JC33Iacjmbuqnl84xKf8OxVtc2E0bodj6L54/LlUWa8kTo/0xggSXMIIEkwIB
# ATCBkDB5MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSMwIQYD
# VQQDExpNaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQQITMwAAAXglWrXNI8ZflQAB
# AAABeDAJBgUrDgMCGgUAoIGwMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwG
# CisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBQsAaIb
# jmwm1NWmCxNpn1L9ZFvnrzBQBgorBgEEAYI3AgEMMUIwQKAWgBQAUABvAHcAZQBy
# AFMAaABlAGwAbKEmgCRodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vUG93ZXJTaGVs
# bCAwDQYJKoZIhvcNAQEBBQAEggEAM9M4TUC29Yailq7+Fb9AhvIZj0sEo1tskRPV
# L/sWSVrqJjDXmljfgmoymUxCJo/cScNAu+m0quri6fIzipQWE/IjFSJwYGmHggef
# l9SBhkgQFLWrepB7bDoNDhzZ7WVFyrtzyG28F8mgAb27ZnYkJ1FqI7TDzvlrkdFh
# sDSXgBTiomGr2GbcqLKapGYzMTtuCTQ4T41w10CSAUB+14Qt5DxB4YmlB7lNGBlJ
# AwQGM4mYLxzSfcOx0rG7G60TVnAibboZyHLcwHXHACe/eYuLpLEHA6vDiXC+KRAv
# hTimPkQ33nVf8Z1ANdSIepKux+6PT10c1brcFc39dZZFJXWOLKGCAigwggIkBgkq
# hkiG9w0BCQYxggIVMIICEQIBATCBjjB3MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSEwHwYDVQQDExhNaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EC
# EzMAAAC8Cy4ae4qxx5EAAAAAALwwCQYFKw4DAhoFAKBdMBgGCSqGSIb3DQEJAzEL
# BgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTE3MTAwNjIzNDAzMFowIwYJKoZI
# hvcNAQkEMRYEFG2Cj+zV9GahaSIvHGopTjWcmDh/MA0GCSqGSIb3DQEBBQUABIIB
# AECNF5zVL5JAAdXp4CkRSt6HiMcII/S0jqjX8W6Vd4EeIFy4R1YVXjD0GIcXHVr7
# fIQ1rFbGWLpJwuxUYNTeIdQ17qw84xov+iDPmspUazOPy2ZARCvlxfNMYLWoxOGq
# 6kauHMHijnoqhqUTCb13HJ8Tbeird31yzXzLCPyUYc5AfGsUYXkVP3ZVrKjCKLUS
# lmxuBLpVuV4Siu0szoie85rGPkN6hgzA1lBFIWYSlQgZlI+TTSvPfKUWO+T8u0oq
# LwHN17oWDfts2VONWKlFww4Pm+WeqSA+sRSZL/kvLNFMyQ14FPJz8eHPZKnb74i2
# H/YscCm0ez/XRZxs5QjwUOM=
# SIG # End signature block