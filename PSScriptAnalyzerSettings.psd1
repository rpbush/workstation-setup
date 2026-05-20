@{
    # PSScriptAnalyzer settings for workstation-setup.
    #
    # boot.ps1 is a single-purpose, top-level orchestrator script (not a module),
    # runs in user context, and uses Write-Host extensively for user-visible
    # progress. The exclusions below silence rules that fire on patterns that
    # are intentional in this codebase. See CLAUDE.md for architectural context.

    # Only fail on Error / Warning so info-level findings don't break CI.
    Severity     = @('Error', 'Warning')

    # Run the full default rule set EXCEPT the rules below.
    ExcludeRules = @(
        # Write-Host is the primary user-visible output channel here.
        'PSAvoidUsingWriteHost',

        # boot.ps1 is a script, not a module; functions aren't cmdlets.
        'PSUseShouldProcessForStateChangingFunctions',

        # $script:-scoped variables are used heavily for cross-section state
        # (InstalledItems, AlreadySetItems, SectionResults, etc.). This rule
        # flags them as global-like.
        'PSAvoidGlobalVars',

        # Many helpers (Test-WindowsFeatureInstalled, Test-OfficeInstalled,
        # Ensure-WinGetConfigurationEnabled, ...) intentionally use plural /
        # compound nouns; renaming them is out of scope.
        'PSUseSingularNouns'
    )
}
