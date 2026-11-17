# Run the same verified release installer as install.ps1, in uninstall mode.
& {
    $installer = Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/avazar/zaslon/dev/install.ps1' -TimeoutSec 30 -ErrorAction Stop
    & ([scriptblock]::Create($installer)) -Uninstall
}
