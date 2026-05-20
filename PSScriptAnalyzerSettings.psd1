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
        'PSUseSingularNouns',

        # Empty catch blocks are intentional "best effort" patterns
        # (e.g., probing optional features, polling for Store install state).
        # Each one is paired with a logical fallback path elsewhere.
        'PSAvoidUsingEmptyCatchBlock',

        # `Write-Log` is the project's own logging function. A newer optional
        # PowerShell module ships a cmdlet with the same name; the rule treats
        # this as a collision but the local definition is intentional and
        # used throughout the script.
        'PSAvoidOverwritingBuiltInCmdlets',

        # `End-Section`, `Refresh-WinGetCatalog`, and
        # `Ensure-WinGetConfigurationEnabled` use non-approved verbs by design.
        # The names match the script's section-tracking vocabulary.
        'PSUseApprovedVerbs',

        # boot.ps1 is UTF-8 without a BOM. The file is consumed by `pwsh` /
        # `powershell.exe` which both handle non-BOM UTF-8 correctly.
        'PSUseBOMForUnicodeEncodedFile',

        # Several variables (e.g., `resetOutput`, `updateOutput`) are
        # captured from winget invocations for potential debugging but not
        # always consumed. Worth a follow-up cleanup, but not a CI blocker.
        # TODO(follow-up): remove or actually log these captures.
        'PSUseDeclaredVarsMoreThanAssignments',

        # False-positive on the `Start-Job -ScriptBlock { param(...) } -ArgumentList`
        # pattern: analyzer flags `$PackageId` inside the scriptblock as
        # needing `$using:`, but it's correctly received via the param block.
        'PSUseUsingScopeModifierInNewRunspaces'
    )
}
