WINDOWS\system32> medusa install --all --debug  
  
╔════════════════════════════════════════════════════════════════════╗  
║                                                                    ║  
║          ![🐍](https://fonts.gstatic.com/s/e/notoemoji/16.0/1f40d/32.png)![🐍](https://fonts.gstatic.com/s/e/notoemoji/16.0/1f40d/32.png)![🐍](https://fonts.gstatic.com/s/e/notoemoji/16.0/1f40d/32.png) MEDUSA v2025.2.0.0 - Security Guardian ![🐍](https://fonts.gstatic.com/s/e/notoemoji/16.0/1f40d/32.png)![🐍](https://fonts.gstatic.com/s/e/notoemoji/16.0/1f40d/32.png)![🐍](https://fonts.gstatic.com/s/e/notoemoji/16.0/1f40d/32.png)           ║  
║                                                                    ║  
║         Universal Scanner with 43+ Specialized Analyzers          ║  
║           One look from Medusa stops vulnerabilities dead          ║  
║                                                                    ║  
╚════════════════════════════════════════════════════════════════════╝  
  
  
![📦](https://fonts.gstatic.com/s/e/notoemoji/16.0/1f4e6/32.png) Linter Installation  
  
Found 39 missing tools:  
  • shellcheck  
  • hadolint  
  • docker-compose  
  • markdownlint-cli  
  • eslint  
  • tflint  
  • golangci-lint  
  • rubocop  
  • phpstan  
  • cargo-clippy  
  • sqlfluff  
  • stylelint  
  • htmlhint  
  • ktlint  
  • swiftlint  
  • cppcheck  
  • checkstyle  
  • typescript  
  • scalastyle  
  • perlcritic  
  • Rscript  
  • ansible-lint  
  • kube-linter  
  • taplo  
  • xmllint                                                                                                                                                    • buf                                                                                                                                                        • graphql-schema-linter                                                                                                                                      • solhint                                                                                                                                                    • luacheck                                                                                                                                                   • mix  
  • hlint  
  • clj-kondo  
  • dart  
  • codenarc  
  • vim-vint  
  • cmakelang  
  • checkmake  
  • gixy  
  • zig  
  
Install all 39 missing tools? [Y/n/a]: a  
Auto-yes enabled for all remaining prompts  
  
![💡](https://fonts.gstatic.com/s/e/notoemoji/16.0/1f4a1/32.png) 14 tools can be installed via Chocolatey:  
  • shellcheck  
  • hadolint  
  • markdownlint-cli  
  • tflint  
  • golangci-lint  
  • ... and 9 more  
  
Installing Chocolatey...  
Debug mode enabled - showing full output  
[DEBUG] Running command: powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('[https://community.chocolatey.org/install.ps1'](https://community.chocolatey.org/install.ps1')))  
[DEBUG] This will download and run the Chocolatey install script...  
[DEBUG] PowerShell output below:  
------------------------------------------------------------  
Forcing web requests to allow TLS v1.2 (Required for requests to Chocolatey.org)  
Getting latest version of the Chocolatey package for download.  
Not using proxy.  
Getting Chocolatey from [https://community.chocolatey.org/api/v2/package/chocolatey/2.5.1](https://community.chocolatey.org/api/v2/package/chocolatey/2.5.1).  
Downloading [https://community.chocolatey.org/api/v2/package/chocolatey/2.5.1](https://community.chocolatey.org/api/v2/package/chocolatey/2.5.1) to C:\Users\rossc\AppData\Local\Temp\chocolatey\chocoInstall\chocolatey.zip  
Not using proxy.  
Extracting C:\Users\rossc\AppData\Local\Temp\chocolatey\chocoInstall\chocolatey.zip to C:\Users\rossc\AppData\Local\Temp\chocolatey\chocoInstall  
Installing Chocolatey on the local machine  
Creating ChocolateyInstall as an environment variable (targeting 'Machine')  
  Setting ChocolateyInstall to 'C:\ProgramData\chocolatey'  
WARNING: It's very likely you will need to close and reopen your shell  
  before you can use choco.  
Restricting write permissions to Administrators  
We are setting up the Chocolatey package repository.  
The packages themselves go to 'C:\ProgramData\chocolatey\lib'  
  (i.e. C:\ProgramData\chocolatey\lib\yourPackageName).  
A shim file for the command line goes to 'C:\ProgramData\chocolatey\bin'  
  and points to an executable in 'C:\ProgramData\chocolatey\lib\yourPackageName'.  
  
Creating Chocolatey CLI folders if they do not already exist.  
  
chocolatey.nupkg file not installed in lib.  
 Attempting to locate it from bootstrapper.  
PATH environment variable does not have C:\ProgramData\chocolatey\bin in it. Adding...  
WARNING: Not setting tab completion: Profile file does not exist at 'C:\Users\rossc\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1'.  
Chocolatey CLI (choco.exe) is now ready.  
You can call choco from anywhere, command line or PowerShell by typing choco.  
Run choco /? for a list of functions.  
You may need to shut down and restart PowerShell and/or consoles  
 first prior to using choco.  
Ensuring Chocolatey commands are on the path  
Ensuring chocolatey.nupkg is in the lib folder  
------------------------------------------------------------  
[DEBUG] Command exit code: 0  
[DEBUG] Waiting 3 seconds for installation to finalize...  
[DEBUG] Refreshing Windows PATH from registry...  
[DEBUG] Checking if 'choco' is in PATH...  
[DEBUG] shutil.which('choco') returned: C:\ProgramData\chocolatey\bin\choco.EXE  
[DEBUG] Final result: chocolatey INSTALLED  
![✅](https://fonts.gstatic.com/s/e/notoemoji/16.0/2705/32.png) Chocolatey installed successfully!  
PATH refreshed - chocolatey is now available  
  
Runtime Dependencies Detected:  
  • Node.js needed for 8 tools: markdownlint-cli, eslint, stylelint...  
  • PHP needed for 1 tool: phpstan  
  • Go needed for 1 tool: checkmake  
  • Java needed for 4 tools: ktlint, checkstyle, scalastyle... (not auto-installed for security)  
  
  
Installing Node.js via winget...  
![✅](https://fonts.gstatic.com/s/e/notoemoji/16.0/2705/32.png) Node.js installed successfully  
✓ npm is now available  
  
  
Installing PHP via winget...  
![❌](https://fonts.gstatic.com/s/e/notoemoji/16.0/274c/32.png) Failed to install PHP  
  
  
Installing Go via winget...  
![❌](https://fonts.gstatic.com/s/e/notoemoji/16.0/274c/32.png) Failed to install Go  
  
![⚠️](https://fonts.gstatic.com/s/e/notoemoji/16.0/26a0_fe0f/32.png)  Java runtime required for 4 tools  
   We don't auto-install Java due to security concerns  
   Tools: ktlint, checkstyle, scalastyle, codenarc  
  
Installing Tools:  
Installing shellcheck...  
[DEBUG] Tool: shellcheck  
[DEBUG] Primary PM: winget  
[DEBUG] Installer: WingetInstaller  
[DEBUG] PM package: koalaman.shellcheck  
[DEBUG] Choco package: shellcheck  
[DEBUG] NPM package: None  
[DEBUG] PIP package: None  
  → Installing shellcheck via winget: koalaman.shellcheck  
  ![✅](https://fonts.gstatic.com/s/e/notoemoji/16.0/2705/32.png) Installed successfully  
  
Installing hadolint...  
[DEBUG] Tool: hadolint  
[DEBUG] Primary PM: winget  
[DEBUG] Installer: WingetInstaller  
[DEBUG] PM package: hadolint.hadolint  
[DEBUG] Choco package: hadolint  
[DEBUG] NPM package: None  
[DEBUG] PIP package: None  
  → Installing hadolint via winget: hadolint.hadolint  
  ![✅](https://fonts.gstatic.com/s/e/notoemoji/16.0/2705/32.png) Installed successfully  
  
Installing docker-compose...  
[DEBUG] Tool: docker-compose  
[DEBUG] Primary PM: winget  
[DEBUG] Installer: WingetInstaller  
[DEBUG] PM package: Docker.DockerCompose  
[DEBUG] Choco package: None  
[DEBUG] NPM package: None  
[DEBUG] PIP package: None  
  → Installing docker-compose via winget: Docker.DockerCompose  
  ![✅](https://fonts.gstatic.com/s/e/notoemoji/16.0/2705/32.png) Installed successfully  
  
Installing markdownlint-cli...  
[DEBUG] Tool: markdownlint-cli  
[DEBUG] Primary PM: winget  
[DEBUG] Installer: WingetInstaller  
[DEBUG] PM package: None  
[DEBUG] Choco package: markdownlint-cli  
[DEBUG] NPM package: markdownlint-cli  
[DEBUG] PIP package: None  
  → Installing markdownlint-cli via choco: markdownlint-cli  
[DEBUG] Running: choco install markdownlint-cli -y  
[DEBUG] Chocolatey output:  
------------------------------------------------------------  
Chocolatey v2.5.1  
Installing the following packages:  
markdownlint-cli  
By installing, you accept licenses for the packages.  
Downloading package from source '[https://community.chocolatey.org/api/v2/](https://community.chocolatey.org/api/v2/)'  
Progress: Downloading chocolatey-compatibility.extension 1.0.0... 100%  
  
chocolatey-compatibility.extension v1.0.0 [Approved]  
chocolatey-compatibility.extension package files install completed. Performing other installation steps.  
 Installed/updated chocolatey-compatibility extensions.  
 The install of chocolatey-compatibility.extension was successful.  
  Deployed to 'C:\ProgramData\chocolatey\extensions\chocolatey-compatibility'  
Downloading package from source '[https://community.chocolatey.org/api/v2/](https://community.chocolatey.org/api/v2/)'  
Progress: Downloading chocolatey-core.extension 1.4.0... 100%  
  
chocolatey-core.extension v1.4.0 [Approved]  
chocolatey-core.extension package files install completed. Performing other installation steps.  
 Installed/updated chocolatey-core extensions.  
 The install of chocolatey-core.extension was successful.  
  Deployed to 'C:\ProgramData\chocolatey\extensions\chocolatey-core'  
Downloading package from source '[https://community.chocolatey.org/api/v2/](https://community.chocolatey.org/api/v2/)'  
Progress: Downloading chocolatey-npm.extension 1.1.0... 100%  
  
chocolatey-npm.extension v1.1.0 [Approved]  
chocolatey-npm.extension package files install completed. Performing other installation steps.  
 Installed/updated chocolatey-npm extensions.  
 The install of chocolatey-npm.extension was successful.  
  Deployed to 'C:\ProgramData\chocolatey\extensions\chocolatey-npm'  
Downloading package from source '[https://community.chocolatey.org/api/v2/](https://community.chocolatey.org/api/v2/)'  
Progress: Downloading markdownlint-cli 0.46.0... 100%  
  
markdownlint-cli v0.46.0 [Approved]  
markdownlint-cli package files install completed. Performing other installation steps.  
  
added 70 packages in 11s  
  
44 packages are looking for funding  
  run `npm fund` for details  
npm notice  
npm notice New patch version of npm available! 11.6.2 -> 11.6.3  
npm notice Changelog: [https://github.com/npm/cli/releases/tag/v11.6.3](https://github.com/npm/cli/releases/tag/v11.6.3)  
npm notice To update run: npm install -g npm@11.6.3  
npm notice  
Only an exit code of non-zero will fail the package by default. Set  
 `--failonstderr` if you want error messages to also fail a script. See  
 `choco --help` for details.  
 The install of markdownlint-cli was successful.  
  Software install location not explicitly set, it could be in package or  
  default install location of installer.  
  
Chocolatey installed 4/4 packages.  
 See the log for details (C:\ProgramData\chocolatey\logs\chocolatey.log).  
  
Enjoy using Chocolatey? Explore more amazing features to take your  
experience to the next level at  
 [https://chocolatey.org/compare](https://chocolatey.org/compare)  
------------------------------------------------------------  
[DEBUG] Exit code: 0  
  ![✅](https://fonts.gstatic.com/s/e/notoemoji/16.0/2705/32.png) Installed successfully  
  
Installing eslint...  
[DEBUG] Tool: eslint  
[DEBUG] Primary PM: winget  
[DEBUG] Installer: WingetInstaller  
[DEBUG] PM package: None  
[DEBUG] Choco package: None  
[DEBUG] NPM package: eslint  
[DEBUG] PIP package: None  
  → Installing eslint via npm: eslint  
  ![✅](https://fonts.gstatic.com/s/e/notoemoji/16.0/2705/32.png) Installed successfully  
  
Installing tflint...  
[DEBUG] Tool: tflint  
[DEBUG] Primary PM: winget  
[DEBUG] Installer: WingetInstaller  
[DEBUG] PM package: TerraformLinters.tflint  
[DEBUG] Choco package: tflint  
[DEBUG] NPM package: None  
[DEBUG] PIP package: None  
  → Installing tflint via winget: TerraformLinters.tflint  
  ![✅](https://fonts.gstatic.com/s/e/notoemoji/16.0/2705/32.png) Installed successfully  
  
Installing golangci-lint...  
[DEBUG] Tool: golangci-lint  
[DEBUG] Primary PM: winget  
[DEBUG] Installer: WingetInstaller  
[DEBUG] PM package: GolangCI.golangci-lint  
[DEBUG] Choco package: golangci-lint  
[DEBUG] NPM package: None                                                                                                                                    [DEBUG] PIP package: None                                                                                                                                      → Installing golangci-lint via winget: GolangCI.golangci-lint                                                                                                ![✅](https://fonts.gstatic.com/s/e/notoemoji/16.0/2705/32.png)![✅](https://fonts.gstatic.com/s/e/notoemoji/16.0/2705/32.png) Installed successfully                                                                                                                                    
Installing rubocop...  
[DEBUG] Tool: rubocop  
[DEBUG] Primary PM: winget  
[DEBUG] Installer: WingetInstaller  
[DEBUG] PM package: RubyInstallerTeam.RubyWithDevKit.3.4  
[DEBUG] Choco package: None  
[DEBUG] NPM package: None  
[DEBUG] PIP package: None  
  → Installing rubocop via winget: RubyInstallerTeam.RubyWithDevKit.3.4  
  ![✅](https://fonts.gstatic.com/s/e/notoemoji/16.0/2705/32.png) Ruby installed successfully  
  → Refreshing PATH to find gem...  
[DEBUG] PATH refreshed from registry  
  → Found gem: C:\Ruby34-x64\bin\gem.cmd  
  → Installing rubocop via gem...  
  ![✅](https://fonts.gstatic.com/s/e/notoemoji/16.0/2705/32.png) rubocop installed via gem  
  
Installing phpstan...  
[DEBUG] Tool: phpstan  
[DEBUG] Primary PM: winget  
[DEBUG] Installer: WingetInstaller  
[DEBUG] PM package: None  
[DEBUG] Choco package: None  
[DEBUG] NPM package: None  
[DEBUG] PIP package: None  
  → Using custom Windows installer...  
[DEBUG] Running PowerShell installer: install-phpstan.ps1  
[DEBUG] Script written to: C:\Users\rossc\AppData\Local\Temp\tmpp_z49ffu.ps1  
[DEBUG] Using PowerShell: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe  
[DEBUG] Running: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Users\rossc\AppData\Local\Temp\tmpp_z49ffu.ps1 -Debug  
[2025-11-23 16:32:23] [INFO] Starting phpstan installation...  
[2025-11-23 16:32:23] [INFO] Fetching release information for version 2.0.4...  
[2025-11-23 16:32:24] [INFO] Installing version: 2.0.4  
[2025-11-23 16:32:24] [INFO] Found asset: phpstan.phar  
[2025-11-23 16:32:24] [INFO] Creating install directory: C:\Users\rossc\AppData\Local\phpstan  
[2025-11-23 16:32:24] [INFO] Downloading from: [https://github.com/phpstan/phpstan/releases/download/2.0.4/phpstan.phar](https://github.com/phpstan/phpstan/releases/download/2.0.4/phpstan.phar)  
Downloading phpstan 2.0.4...  
[2025-11-23 16:32:52] [INFO] Download complete: C:\Users\rossc\AppData\Local\phpstan\phpstan.phar  
[2025-11-23 16:32:52] [INFO] Created wrapper script: C:\Users\rossc\AppData\Local\phpstan\phpstan.bat  
  
WARNING: PHP not found in PATH  
   phpstan requires PHP to run  
   Install PHP from: [https://windows.php.net/download/](https://windows.php.net/download/)  
  
SUCCESS: phpstan installed successfully!  
   Location: C:\Users\rossc\AppData\Local\phpstan\phpstan.phar  
   Wrapper: C:\Users\rossc\AppData\Local\phpstan\phpstan.bat  
  
NOTE: C:\Users\rossc\AppData\Local\phpstan is not in your PATH  
   Add to PATH to use 'phpstan' command globally  
  
   To add to PATH (run as administrator):  
   [Environment]::SetEnvironmentVariable('Path', $env:Path + ';C:\Users\rossc\AppData\Local\phpstan', 'Machine')  
  
   Testing installation...  
[2025-11-23 16:32:53] [INFO] Version check failed (PHP may not be available)  
[DEBUG] Successfully installed phpstan via PowerShell script  
  ![✅](https://fonts.gstatic.com/s/e/notoemoji/16.0/2705/32.png) Installed successfully  
  
Installing cargo-clippy...  
[DEBUG] Tool: cargo-clippy  
[DEBUG] Primary PM: winget  
[DEBUG] Installer: WingetInstaller  
[DEBUG] PM package: Rustlang.Rustup  
[DEBUG] Choco package: rustup  
[DEBUG] NPM package: None  
[DEBUG] PIP package: None  
  → Installing cargo-clippy via winget: Rustlang.Rustup  
  ![⚠️](https://fonts.gstatic.com/s/e/notoemoji/16.0/26a0_fe0f/32.png) winget failed, trying choco fallback...  
  → Installing cargo-clippy via choco: rustup  
[DEBUG] Running: choco install rustup -y  
[DEBUG] Chocolatey output:  
------------------------------------------------------------  
Chocolatey v2.5.1  
Installing the following packages:  
rustup  
By installing, you accept licenses for the packages.  
rustup not installed. The package was not found with the source(s) listed.  
 Source(s): '[https://community.chocolatey.org/api/v2/](https://community.chocolatey.org/api/v2/)'  
 NOTE: When you specify explicit sources, it overrides default sources.  
If the package version is a prerelease and you didn't specify `--pre`,  
 the package may not be found.  
Please see [https://docs.chocolatey.org/en-us/troubleshooting](https://docs.chocolatey.org/en-us/troubleshooting) for more  
 assistance.  
  
Chocolatey installed 0/1 packages. 1 packages failed.  
 See the log for details (C:\ProgramData\chocolatey\logs\chocolatey.log).  
  
Failures  
 - rustup - rustup not installed. The package was not found with the source(s) listed.  
 Source(s): '[https://community.chocolatey.org/api/v2/](https://community.chocolatey.org/api/v2/)'  
 NOTE: When you specify explicit sources, it overrides default sources.  
If the package version is a prerelease and you didn't specify `--pre`,  
 the package may not be found.  
Please see [https://docs.chocolatey.org/en-us/troubleshooting](https://docs.chocolatey.org/en-us/troubleshooting) for more  
 assistance.  
  
Enjoy using Chocolatey? Explore more amazing features to take your  
experience to the next level at  
 [https://chocolatey.org/compare](https://chocolatey.org/compare)  
------------------------------------------------------------  
[DEBUG] Exit code: 1  
  ![❌](https://fonts.gstatic.com/s/e/notoemoji/16.0/274c/32.png) Installation failed  
  
Installing sqlfluff...  
[DEBUG] Tool: sqlfluff  
[DEBUG] Primary PM: winget  
[DEBUG] Installer: WingetInstaller  
[DEBUG] PM package: None  
[DEBUG] Choco package: None  
[DEBUG] NPM package: None  
[DEBUG] PIP package: sqlfluff  
  → Installing sqlfluff via pip: sqlfluff  
  ![✅](https://fonts.gstatic.com/s/e/notoemoji/16.0/2705/32.png) Installed successfully  
  
Installing stylelint...  
[DEBUG] Tool: stylelint                                                                                                                                      [DEBUG] Primary PM: winget                                                                                                                                   [DEBUG] Installer: WingetInstaller                                                                                                                           [DEBUG] PM package: None                                                                                                                                     [DEBUG] Choco package: None  
[DEBUG] NPM package: stylelint  
[DEBUG] PIP package: None  
  → Installing stylelint via npm: stylelint  
  ![✅](https://fonts.gstatic.com/s/e/notoemoji/16.0/2705/32.png) Installed successfully  
  
Installing htmlhint...  
[DEBUG] Tool: htmlhint  
[DEBUG] Primary PM: winget  
[DEBUG] Installer: WingetInstaller  
[DEBUG] PM package: None  
[DEBUG] Choco package: None  
[DEBUG] NPM package: htmlhint  
[DEBUG] PIP package: None  
  → Installing htmlhint via npm: htmlhint  
  ![✅](https://fonts.gstatic.com/s/e/notoemoji/16.0/2705/32.png) Installed successfully  
  
Installing ktlint...  
[DEBUG] Tool: ktlint  
[DEBUG] Primary PM: winget  
[DEBUG] Installer: WingetInstaller  
[DEBUG] PM package: None  
[DEBUG] Choco package: None  
[DEBUG] NPM package: None  
[DEBUG] PIP package: None  
  → Using custom Windows installer...  
[DEBUG] Running PowerShell installer: install-ktlint.ps1  
[DEBUG] Script written to: C:\Users\rossc\AppData\Local\Temp\tmp6a7k4tes.ps1  
[DEBUG] Using PowerShell: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe  
[DEBUG] Running: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Users\rossc\AppData\Local\Temp\tmp6a7k4tes.ps1 -Debug  
[2025-11-23 16:33:50] [INFO] Starting ktlint installation...  
[2025-11-23 16:33:50] [INFO] Fetching release information for version 1.5.0...  
[2025-11-23 16:33:51] [INFO] Installing version: 1.5.0  
[2025-11-23 16:33:51] [INFO] Found asset: ktlint  
[2025-11-23 16:33:51] [INFO] Creating install directory: C:\Users\rossc\AppData\Local\ktlint  
[2025-11-23 16:33:51] [INFO] Downloading from: [https://github.com/pinterest/ktlint/releases/download/1.5.0/ktlint](https://github.com/pinterest/ktlint/releases/download/1.5.0/ktlint)  
Downloading ktlint 1.5.0...  
[2025-11-23 16:35:10] [INFO] Download complete: C:\Users\rossc\AppData\Local\ktlint\ktlint.jar  
[2025-11-23 16:35:10] [INFO] Created wrapper script: C:\Users\rossc\AppData\Local\ktlint\ktlint.bat  
  
WARNING: Java not found in PATH  
   ktlint requires Java to run  
   Install Java from: [https://adoptium.net/](https://adoptium.net/)  
  
SUCCESS: ktlint installed successfully!  
   Location: C:\Users\rossc\AppData\Local\ktlint\ktlint.jar  
   Wrapper: C:\Users\rossc\AppData\Local\ktlint\ktlint.bat  
  
NOTE: C:\Users\rossc\AppData\Local\ktlint is not in your PATH  
   Add to PATH to use 'ktlint' command globally  
  
   To add to PATH (run as administrator):  
   [Environment]::SetEnvironmentVariable('Path', $env:Path + ';C:\Users\rossc\AppData\Local\ktlint', 'Machine')  
  
   Testing installation...  
[2025-11-23 16:35:10] [INFO] Version check failed (Java may not be available)  
[DEBUG] Successfully installed ktlint via PowerShell script  
  ![✅](https://fonts.gstatic.com/s/e/notoemoji/16.0/2705/32.png) Installed successfully  
  
Installing swiftlint...  
[DEBUG] Tool: swiftlint  
[DEBUG] Primary PM: winget  
[DEBUG] Installer: WingetInstaller  
[DEBUG] PM package: None  
[DEBUG] Choco package: None  
[DEBUG] NPM package: None  
[DEBUG] PIP package: None  
  ⊘ No installer available for this platform  
  
Installing cppcheck...  
[DEBUG] Tool: cppcheck  
[DEBUG] Primary PM: winget  
[DEBUG] Installer: WingetInstaller  
[DEBUG] PM package: Cppcheck.Cppcheck  
[DEBUG] Choco package: cppcheck  
[DEBUG] NPM package: None  
[DEBUG] PIP package: None  
  → Installing cppcheck via winget: Cppcheck.Cppcheck  
  ![⚠️](https://fonts.gstatic.com/s/e/notoemoji/16.0/26a0_fe0f/32.png) winget failed, trying choco fallback...  
  → Installing cppcheck via choco: cppcheck  
[DEBUG] Running: choco install cppcheck -y  
[DEBUG] Chocolatey output:  
------------------------------------------------------------  
Chocolatey v2.5.1  
Installing the following packages:  
cppcheck  
By installing, you accept licenses for the packages.  
Downloading package from source '[https://community.chocolatey.org/api/v2/](https://community.chocolatey.org/api/v2/)'  
Progress: Downloading chocolatey-windowsupdate.extension 1.0.5... 100%  
  
chocolatey-windowsupdate.extension v1.0.5 [Approved]  
chocolatey-windowsupdate.extension package files install completed. Performing other installation steps.  
 Installed/updated chocolatey-windowsupdate extensions.  
 The install of chocolatey-windowsupdate.extension was successful.  
  Deployed to 'C:\ProgramData\chocolatey\extensions\chocolatey-windowsupdate'  
Downloading package from source '[https://community.chocolatey.org/api/v2/](https://community.chocolatey.org/api/v2/)'  
Progress: Downloading KB2919442 1.0.20160915... 100%  
  
KB2919442 v1.0.20160915 [Approved]  
KB2919442 package files install completed. Performing other installation steps.  
Skipping installation because this hotfix only applies to Windows 8.1 and Windows Server 2012 R2.  
 The install of KB2919442 was successful.  
  Software install location not explicitly set, it could be in package or  
  default install location of installer.  
Downloading package from source '[https://community.chocolatey.org/api/v2/](https://community.chocolatey.org/api/v2/)'  
Progress: Downloading KB2919355 1.0.20160915... 100%  
  
KB2919355 v1.0.20160915 [Approved]  
KB2919355 package files install completed. Performing other installation steps.  
Skipping installation because this hotfix only applies to Windows 8.1 and Windows Server 2012 R2.  
 The install of KB2919355 was successful.  
  Software install location not explicitly set, it could be in package or  
  default install location of installer.  
Downloading package from source '[https://community.chocolatey.org/api/v2/](https://community.chocolatey.org/api/v2/)'  
Progress: Downloading KB2999226 1.0.20181019... 100%  
  
KB2999226 v1.0.20181019 [Approved]  
KB2999226 package files install completed. Performing other installation steps.  
Skipping installation because update KB2999226 does not apply to this operating system (Microsoft Windows 11 Home).  
 The install of KB2999226 was successful.  
  Software install location not explicitly set, it could be in package or  
  default install location of installer.  
Downloading package from source '[https://community.chocolatey.org/api/v2/](https://community.chocolatey.org/api/v2/)'  
Progress: Downloading KB3035131 1.0.3... 100%  
  
KB3035131 v1.0.3 [Approved]  
KB3035131 package files install completed. Performing other installation steps.  
Skipping installation because update KB3035131 does not apply to this operating system (Microsoft Windows 11 Home).  
 The install of KB3035131 was successful.  
  Software install location not explicitly set, it could be in package or  
  default install location of installer.  
Downloading package from source '[https://community.chocolatey.org/api/v2/](https://community.chocolatey.org/api/v2/)'  
Progress: Downloading KB3033929 1.0.5... 100%  
  
KB3033929 v1.0.5 [Approved]  
KB3033929 package files install completed. Performing other installation steps.  
Skipping installation because update KB3033929 does not apply to this operating system (Microsoft Windows 11 Home).  
 The install of KB3033929 was successful.  
  Software install location not explicitly set, it could be in package or  
  default install location of installer.  
Downloading package from source '[https://community.chocolatey.org/api/v2/](https://community.chocolatey.org/api/v2/)'  
Progress: Downloading vcredist140 14.44.35211... 100%  
  
vcredist140 v14.44.35211 [Approved] - Possibly broken  
vcredist140 package files install completed. Performing other installation steps.  
Runtime for architecture x86 version 14.44.35211 is already installed.  
Runtime for architecture x64 version 14.44.35211 is already installed.  
 The install of vcredist140 was successful.  
  Software install location not explicitly set, it could be in package or  
  default install location of installer.  
Downloading package from source '[https://community.chocolatey.org/api/v2/](https://community.chocolatey.org/api/v2/)'  
Progress: Downloading cppcheck 2.16.0... 100%  
  
cppcheck v2.16.0 [Approved] - Likely broken for FOSS users (due to download location changes)  
cppcheck package files install completed. Performing other installation steps.  
Downloading cppcheck 64 bit  
  from '[https://github.com/danmar/cppcheck/releases/download/2.16.0/cppcheck-2.16.0-x64-Setup.msi](https://github.com/danmar/cppcheck/releases/download/2.16.0/cppcheck-2.16.0-x64-Setup.msi)'  
Progress: 100% - Completed download of C:\Users\rossc\AppData\Local\Temp\chocolatey\cppcheck\2.16.0\cppcheck-2.16.0-x64-Setup.msi (19.68 MB).  
Download of cppcheck-2.16.0-x64-Setup.msi (19.68 MB) completed.  
Hashes match.  
Installing cppcheck...  
cppcheck has been installed.  
PATH environment variable does not have C:\Program Files\Cppcheck in it. Adding...  
  cppcheck may be able to be automatically uninstalled.  
Environment Vars (like PATH) have changed. Close/reopen your shell to                                                                                         see the changes (or in powershell/cmd.exe just type `refreshenv`).                                                                                           The install of cppcheck was successful.                                                                                                                       Software installed as 'MSI', install location is likely default.                                                                                            
Chocolatey installed 8/8 packages.  
 See the log for details (C:\ProgramData\chocolatey\logs\chocolatey.log).  
  
Installed:  
 - chocolatey-windowsupdate.extension v1.0.5  
 - cppcheck v2.16.0  
 - KB2919355 v1.0.20160915  
 - KB2919442 v1.0.20160915  
 - KB2999226 v1.0.20181019  
 - KB3033929 v1.0.5  
 - KB3035131 v1.0.3  
 - vcredist140 v14.44.35211  
------------------------------------------------------------  
[DEBUG] Exit code: 0  
  ![✅](https://fonts.gstatic.com/s/e/notoemoji/16.0/2705/32.png) Installed successfully  
  
Installing checkstyle...  
[DEBUG] Tool: checkstyle  
[DEBUG] Primary PM: winget  
[DEBUG] Installer: WingetInstaller  
[DEBUG] PM package: None  
[DEBUG] Choco package: None  
[DEBUG] NPM package: None  
[DEBUG] PIP package: None  
  → Using custom Windows installer...  
[DEBUG] Running PowerShell installer: install-checkstyle.ps1  
[DEBUG] Script written to: C:\Users\rossc\AppData\Local\Temp\tmp6tudxsgx.ps1  
[DEBUG] Using PowerShell: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe  
[DEBUG] Running: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Users\rossc\AppData\Local\Temp\tmp6tudxsgx.ps1 -Debug  
[2025-11-23 16:35:45] [INFO] Starting checkstyle installation...  
[2025-11-23 16:35:45] [INFO] Fetching release information for version checkstyle-12.1.2...  
[2025-11-23 16:35:45] [INFO] Installing version: checkstyle-12.1.2  
[2025-11-23 16:35:46] [INFO] Found asset: checkstyle-12.1.2-all.jar  
[2025-11-23 16:35:46] [INFO] Creating install directory: C:\Users\rossc\AppData\Local\checkstyle  
[2025-11-23 16:35:46] [INFO] Downloading from: [https://github.com/checkstyle/checkstyle/releases/download/checkstyle-12.1.2/checkstyle-12.1.2-all.jar](https://github.com/checkstyle/checkstyle/releases/download/checkstyle-12.1.2/checkstyle-12.1.2-all.jar)  
Downloading checkstyle checkstyle-12.1.2...  
[2025-11-23 16:36:06] [INFO] Download complete: C:\Users\rossc\AppData\Local\checkstyle\checkstyle.jar  
[2025-11-23 16:36:06] [INFO] Created wrapper script: C:\Users\rossc\AppData\Local\checkstyle\checkstyle.bat  
  
WARNING: Java not found in PATH  
   checkstyle requires Java to run  
   Install Java from: [https://adoptium.net/](https://adoptium.net/)  
  
SUCCESS: checkstyle installed successfully!  
   Location: C:\Users\rossc\AppData\Local\checkstyle\checkstyle.jar  
   Wrapper: C:\Users\rossc\AppData\Local\checkstyle\checkstyle.bat  
  
NOTE: C:\Users\rossc\AppData\Local\checkstyle is not in your PATH  
   Add to PATH to use 'checkstyle' command globally  
  
   To add to PATH (run as administrator):  
   [Environment]::SetEnvironmentVariable('Path', $env:Path + ';C:\Users\rossc\AppData\Local\checkstyle', 'Machine')  
  
   Testing installation...  
[2025-11-23 16:36:06] [INFO] Version check failed (Java may not be available)  
[DEBUG] Successfully installed checkstyle via PowerShell script  
  ![✅](https://fonts.gstatic.com/s/e/notoemoji/16.0/2705/32.png) Installed successfully  
  
Installing typescript...  
[DEBUG] Tool: typescript  
[DEBUG] Primary PM: winget  
[DEBUG] Installer: WingetInstaller  
[DEBUG] PM package: None  
[DEBUG] Choco package: None  
[DEBUG] NPM package: typescript  
[DEBUG] PIP package: None  
  → Installing typescript via npm: typescript  
  ![✅](https://fonts.gstatic.com/s/e/notoemoji/16.0/2705/32.png) Installed successfully  
  
Installing scalastyle...  
[DEBUG] Tool: scalastyle  
[DEBUG] Primary PM: winget  
[DEBUG] Installer: WingetInstaller  
[DEBUG] PM package: None  
[DEBUG] Choco package: scala  
[DEBUG] NPM package: None  
[DEBUG] PIP package: None  
  → Installing scalastyle via choco: scala  
[DEBUG] Running: choco install scala -y  
[DEBUG] Chocolatey output:  
------------------------------------------------------------  
Chocolatey v2.5.1  
Installing the following packages:  
scala  
By installing, you accept licenses for the packages.  
Downloading package from source '[https://community.chocolatey.org/api/v2/](https://community.chocolatey.org/api/v2/)'  
Progress: Downloading scala 3.7.4... 100%  
  
scala v3.7.4 [Approved]  
scala package files install completed. Performing other installation steps.  
Downloading scala 64 bit  
  from '[https://github.com/scala/scala3/releases/download/3.7.4/scala3-3.7.4-x86_64-pc-win32.zip](https://github.com/scala/scala3/releases/download/3.7.4/scala3-3.7.4-x86_64-pc-win32.zip)'  
Progress: 100% - Completed download of C:\Users\rossc\AppData\Local\Temp\chocolatey\scala\3.7.4\scala3-3.7.4-x86_64-pc-win32.zip (74.07 MB).  
Download of scala3-3.7.4-x86_64-pc-win32.zip (74.07 MB) completed.  
Hashes match.  
Extracting C:\Users\rossc\AppData\Local\Temp\chocolatey\scala\3.7.4\scala3-3.7.4-x86_64-pc-win32.zip to C:\ProgramData\chocolatey\lib\scala\tools\scala\3.7.4...  
C:\ProgramData\chocolatey\lib\scala\tools\scala\3.7.4  
Creating shims for .bat file from C:\ProgramData\chocolatey\lib\scala\tools\scala\3.7.4\scala3-3.7.4-x86_64-pc-win32\bin  
Creating shim for C:\ProgramData\chocolatey\lib\scala\tools\scala\3.7.4\scala3-3.7.4-x86_64-pc-win32\bin\scala.bat...  
Added C:\ProgramData\chocolatey\bin\scala.exe shim pointed to '..\lib\scala\tools\scala\3.7.4\scala3-3.7.4-x86_64-pc-win32\bin\scala.bat'.  
Creating shim for C:\ProgramData\chocolatey\lib\scala\tools\scala\3.7.4\scala3-3.7.4-x86_64-pc-win32\bin\scalac.bat...  
Added C:\ProgramData\chocolatey\bin\scalac.exe shim pointed to '..\lib\scala\tools\scala\3.7.4\scala3-3.7.4-x86_64-pc-win32\bin\scalac.bat'.  
Creating shim for C:\ProgramData\chocolatey\lib\scala\tools\scala\3.7.4\scala3-3.7.4-x86_64-pc-win32\bin\scaladoc.bat...  
Added C:\ProgramData\chocolatey\bin\scaladoc.exe shim pointed to '..\lib\scala\tools\scala\3.7.4\scala3-3.7.4-x86_64-pc-win32\bin\scaladoc.bat'.  
 ShimGen has successfully created a shim for scala-cli.exe  
 The install of scala was successful.  
  Deployed to 'C:\ProgramData\chocolatey\lib\scala\tools\scala\3.7.4'  
  
Chocolatey installed 1/1 packages.  
 See the log for details (C:\ProgramData\chocolatey\logs\chocolatey.log).  
------------------------------------------------------------  
[DEBUG] Exit code: 0  
  ![✅](https://fonts.gstatic.com/s/e/notoemoji/16.0/2705/32.png) Installed successfully  
  
Installing perlcritic...  
[DEBUG] Tool: perlcritic  
[DEBUG] Primary PM: winget  
[DEBUG] Installer: WingetInstaller  
[DEBUG] PM package: None  
[DEBUG] Choco package: strawberryperl  
[DEBUG] NPM package: None  
[DEBUG] PIP package: None  
  → Installing perlcritic via choco: strawberryperl  
[DEBUG] Running: choco install strawberryperl -y  
[DEBUG] Chocolatey output:  
------------------------------------------------------------  
Chocolatey v2.5.1  
Installing the following packages:  
strawberryperl  
By installing, you accept licenses for the packages.  
Downloading package from source '[https://community.chocolatey.org/api/v2/](https://community.chocolatey.org/api/v2/)'  
Progress: Downloading StrawberryPerl 5.42.0.1... 100%  
  
strawberryperl v5.42.0.1 [Approved]  
strawberryperl package files install completed. Performing other installation steps.  
Downloading strawberryperl 64 bit  
  from '[https://github.com/StrawberryPerl/Perl-Dist-Strawberry/releases/download/SP_54201_64bit/strawberry-perl-5.42.0.1-64bit.msi](https://github.com/StrawberryPerl/Perl-Dist-Strawberry/releases/download/SP_54201_64bit/strawberry-perl-5.42.0.1-64bit.msi)'  
Progress: 100% - Completed download of C:\Users\rossc\AppData\Local\Temp\chocolatey\StrawberryPerl\5.42.0.1\strawberry-perl-5.42.0.1-64bit.msi (198.4 MB).  
Download of strawberry-perl-5.42.0.1-64bit.msi (198.4 MB) completed.  
Hashes match.  
Installing strawberryperl...  
strawberryperl has been installed.  
  strawberryperl may be able to be automatically uninstalled.  
Environment Vars (like PATH) have changed. Close/reopen your shell to  
 see the changes (or in powershell/cmd.exe just type `refreshenv`).  
 The install of strawberryperl was successful.  
  Deployed to 'C:\Strawberry\'  
  
Chocolatey installed 1/1 packages.  
 See the log for details (C:\ProgramData\chocolatey\logs\chocolatey.log).  
  
Did you know the proceeds of Pro (and some proceeds from other  
 licensed editions) go into bettering the community infrastructure?  
 Your support ensures an active community, keeps Chocolatey tip-top,  
 plus it nets you some awesome features!  
 [https://chocolatey.org/compare](https://chocolatey.org/compare)  
------------------------------------------------------------  
[DEBUG] Exit code: 0  
  ![✅](https://fonts.gstatic.com/s/e/notoemoji/16.0/2705/32.png) Installed successfully  
  
Installing Rscript...  
[DEBUG] Tool: Rscript  
[DEBUG] Primary PM: winget  
[DEBUG] Installer: WingetInstaller  
[DEBUG] PM package: RProject.R  
[DEBUG] Choco package: None  
[DEBUG] NPM package: None  
[DEBUG] PIP package: None  
  → Installing Rscript via winget: RProject.R  
  ![✅](https://fonts.gstatic.com/s/e/notoemoji/16.0/2705/32.png) Installed successfully  
  
Installing ansible-lint...  
[DEBUG] Tool: ansible-lint                                                                                                                                   [DEBUG] Primary PM: winget                                                                                                                                   [DEBUG] Installer: WingetInstaller                                                                                                                           [DEBUG] PM package: None                                                                                                                                     [DEBUG] Choco package: None                                                                                                                                  [DEBUG] NPM package: None                                                                                                                                    [DEBUG] PIP package: ansible-lint                                                                                                                              → Installing ansible-lint via pip: ansible-lint  
  ![✅](https://fonts.gstatic.com/s/e/notoemoji/16.0/2705/32.png) Installed successfully  
  
Installing kube-linter...  
[DEBUG] Tool: kube-linter  
[DEBUG] Primary PM: winget  
[DEBUG] Installer: WingetInstaller  
[DEBUG] PM package: stackrox.kube-linter  
[DEBUG] Choco package: None  
[DEBUG] NPM package: None  
[DEBUG] PIP package: None  
  → Installing kube-linter via winget: stackrox.kube-linter  
  ![✅](https://fonts.gstatic.com/s/e/notoemoji/16.0/2705/32.png) Installed successfully  
  
Installing taplo...  
[DEBUG] Tool: taplo  
[DEBUG] Primary PM: winget  
[DEBUG] Installer: WingetInstaller  
[DEBUG] PM package: None  
[DEBUG] Choco package: None  
[DEBUG] NPM package: None  
[DEBUG] PIP package: None  
  → Using custom Windows installer...  
[DEBUG] Running PowerShell installer: install-taplo.ps1  
[DEBUG] Script written to: C:\Users\rossc\AppData\Local\Temp\tmp23_cwzn7.ps1  
[DEBUG] Using PowerShell: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe  
[DEBUG] Running: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Users\rossc\AppData\Local\Temp\tmp23_cwzn7.ps1 -Debug  
[2025-11-23 16:39:58] [INFO] Starting taplo installation...  
[2025-11-23 16:39:58] [INFO] Fetching release information for version 0.9.3...  
[2025-11-23 16:39:59] [INFO] Installing version: 0.9.3  
[2025-11-23 16:39:59] [INFO] Found asset: taplo-full-windows-x86_64.zip  
[2025-11-23 16:39:59] [INFO] Creating install directory: C:\Users\rossc\AppData\Local\taplo  
[2025-11-23 16:39:59] [INFO] Downloading from: [https://github.com/tamasfe/taplo/releases/download/0.9.3/taplo-full-windows-x86_64.zip](https://github.com/tamasfe/taplo/releases/download/0.9.3/taplo-full-windows-x86_64.zip)  
Downloading taplo 0.9.3...  
[2025-11-23 16:40:25] [INFO] Download complete: C:\Users\rossc\AppData\Local\Temp\taplo-0.9.3.zip  
[2025-11-23 16:40:25] [INFO] Extracting to: C:\Users\rossc\AppData\Local\taplo  
[2025-11-23 16:40:26] [INFO] Extraction complete  
[2025-11-23 16:40:26] [INFO] Cleaned up temporary ZIP file  
[2025-11-23 16:40:26] [INFO] Found executable: C:\Users\rossc\AppData\Local\taplo\taplo.exe  
  
SUCCESS: taplo installed successfully!  
   Location: C:\Users\rossc\AppData\Local\taplo\taplo.exe  
  
NOTE: C:\Users\rossc\AppData\Local\taplo is not in your PATH  
   Add to PATH to use 'taplo' command globally  
  
   To add to PATH (run as administrator):  
   [Environment]::SetEnvironmentVariable('Path', $env:Path + ';C:\Users\rossc\AppData\Local\taplo', 'Machine')  
  
   Testing installation...  
   Version: taplo 0.9.3  
[DEBUG] Successfully installed taplo via PowerShell script  
  ![✅](https://fonts.gstatic.com/s/e/notoemoji/16.0/2705/32.png) Installed successfully  
  
Installing xmllint...  
[DEBUG] Tool: xmllint  
[DEBUG] Primary PM: winget  
[DEBUG] Installer: WingetInstaller  
[DEBUG] PM package: None  
[DEBUG] Choco package: xsltproc  
[DEBUG] NPM package: None  
[DEBUG] PIP package: None  
  → Installing xmllint via choco: xsltproc  
[DEBUG] Running: choco install xsltproc -y  
[DEBUG] Chocolatey output:  
------------------------------------------------------------  
Chocolatey v2.5.1  
Installing the following packages:  
xsltproc  
By installing, you accept licenses for the packages.  
Downloading package from source '[https://community.chocolatey.org/api/v2/](https://community.chocolatey.org/api/v2/)'  
Progress: Downloading xsltproc 1.1.28.0... 100%  
  
xsltproc v1.1.28 [Approved]  
xsltproc package files install completed. Performing other installation steps.  
Downloading xsltproc-mingwrt 64 bit  
  from '[http://xmlsoft.org/sources/win32/64bit/mingwrt-5.2.0-win32-x86_64.7z](http://xmlsoft.org/sources/win32/64bit/mingwrt-5.2.0-win32-x86_64.7z)'  
Progress: 100% - Completed download of C:\Users\rossc\AppData\Local\Temp\chocolatey\xsltproc\1.1.28\mingwrt-5.2.0-win32-x86_64.7z (91.28 KB).  
Download of mingwrt-5.2.0-win32-x86_64.7z (91.28 KB) completed.  
Hashes match.  
Extracting C:\Users\rossc\AppData\Local\Temp\chocolatey\xsltproc\1.1.28\mingwrt-5.2.0-win32-x86_64.7z to C:\ProgramData\chocolatey\lib\xsltproc\tools\..\dist...  
C:\ProgramData\chocolatey\lib\xsltproc\tools\..\dist  
Downloading xsltproc-iconv 64 bit  
  from '[http://xmlsoft.org/sources/win32/64bit/iconv-1.14-win32-x86_64.7z](http://xmlsoft.org/sources/win32/64bit/iconv-1.14-win32-x86_64.7z)'  
Progress: 100% - Completed download of C:\Users\rossc\AppData\Local\Temp\chocolatey\xsltproc\1.1.28\iconv-1.14-win32-x86_64.7z (701.95 KB).  
Download of iconv-1.14-win32-x86_64.7z (701.95 KB) completed.  
Hashes match.  
Extracting C:\Users\rossc\AppData\Local\Temp\chocolatey\xsltproc\1.1.28\iconv-1.14-win32-x86_64.7z to C:\ProgramData\chocolatey\lib\xsltproc\tools\..\dist...  
C:\ProgramData\chocolatey\lib\xsltproc\tools\..\dist  
Downloading xsltproc-zlib 64 bit  
  from '[http://xmlsoft.org/sources/win32/64bit/zlib-1.2.8-win32-x86_64.7z](http://xmlsoft.org/sources/win32/64bit/zlib-1.2.8-win32-x86_64.7z)'  
Progress: 100% - Completed download of C:\Users\rossc\AppData\Local\Temp\chocolatey\xsltproc\1.1.28\zlib-1.2.8-win32-x86_64.7z (121.56 KB).  
Download of zlib-1.2.8-win32-x86_64.7z (121.56 KB) completed.  
Hashes match.  
Extracting C:\Users\rossc\AppData\Local\Temp\chocolatey\xsltproc\1.1.28\zlib-1.2.8-win32-x86_64.7z to C:\ProgramData\chocolatey\lib\xsltproc\tools\..\dist...  
C:\ProgramData\chocolatey\lib\xsltproc\tools\..\dist  
Downloading xsltproc-libxml 64 bit  
  from '[http://xmlsoft.org/sources/win32/64bit/libxml2-2.9.3-win32-x86_64.7z](http://xmlsoft.org/sources/win32/64bit/libxml2-2.9.3-win32-x86_64.7z)'  
Progress: 100% - Completed download of C:\Users\rossc\AppData\Local\Temp\chocolatey\xsltproc\1.1.28\libxml2-2.9.3-win32-x86_64.7z (3.54 MB).  
Download of libxml2-2.9.3-win32-x86_64.7z (3.54 MB) completed.  
Hashes match.  
Extracting C:\Users\rossc\AppData\Local\Temp\chocolatey\xsltproc\1.1.28\libxml2-2.9.3-win32-x86_64.7z to C:\ProgramData\chocolatey\lib\xsltproc\tools\..\dist...  
C:\ProgramData\chocolatey\lib\xsltproc\tools\..\dist  
Downloading xsltproc-libxslt 64 bit  
  from '[http://xmlsoft.org/sources/win32/64bit/libxslt-1.1.28-win32-x86_64.7z](http://xmlsoft.org/sources/win32/64bit/libxslt-1.1.28-win32-x86_64.7z)'  
Progress: 100% - Completed download of C:\Users\rossc\AppData\Local\Temp\chocolatey\xsltproc\1.1.28\libxslt-1.1.28-win32-x86_64.7z (1.02 MB).  
Download of libxslt-1.1.28-win32-x86_64.7z (1.02 MB) completed.  
Hashes match.  
Extracting C:\Users\rossc\AppData\Local\Temp\chocolatey\xsltproc\1.1.28\libxslt-1.1.28-win32-x86_64.7z to C:\ProgramData\chocolatey\lib\xsltproc\tools\..\dist...  
C:\ProgramData\chocolatey\lib\xsltproc\tools\..\dist  
Added C:\ProgramData\chocolatey\bin\xsltproc.exe shim pointed to '..\lib\xsltproc\tools\xsltproc.bat'.  
 ShimGen has successfully created a shim for iconv.exe  
 ShimGen has successfully created a shim for xmlcatalog.exe  
 ShimGen has successfully created a shim for xmllint.exe  
 The install of xsltproc was successful.  
  Deployed to 'C:\ProgramData\chocolatey\lib\xsltproc\tools\..\dist'  
  
Chocolatey installed 1/1 packages.  
 See the log for details (C:\ProgramData\chocolatey\logs\chocolatey.log).  
------------------------------------------------------------  
[DEBUG] Exit code: 0  
  ![✅](https://fonts.gstatic.com/s/e/notoemoji/16.0/2705/32.png) Installed successfully  
  
Installing buf...  
[DEBUG] Tool: buf  
[DEBUG] Primary PM: winget  
[DEBUG] Installer: WingetInstaller  
[DEBUG] PM package: None  
[DEBUG] Choco package: None  
[DEBUG] NPM package: @bufbuild/buf  
[DEBUG] PIP package: None  
  → Installing buf via npm: @bufbuild/buf  
  ![✅](https://fonts.gstatic.com/s/e/notoemoji/16.0/2705/32.png) Installed successfully  
  
Installing graphql-schema-linter...  
[DEBUG] Tool: graphql-schema-linter  
[DEBUG] Primary PM: winget  
[DEBUG] Installer: WingetInstaller  
[DEBUG] PM package: None  
[DEBUG] Choco package: None  
[DEBUG] NPM package: graphql-schema-linter  
[DEBUG] PIP package: None  
  → Installing graphql-schema-linter via npm: graphql-schema-linter  
  ![✅](https://fonts.gstatic.com/s/e/notoemoji/16.0/2705/32.png) Installed successfully  
  
Installing solhint...  
[DEBUG] Tool: solhint  
[DEBUG] Primary PM: winget  
[DEBUG] Installer: WingetInstaller  
[DEBUG] PM package: None  
[DEBUG] Choco package: None  
[DEBUG] NPM package: solhint  
[DEBUG] PIP package: None  
  → Installing solhint via npm: solhint  
  ![✅](https://fonts.gstatic.com/s/e/notoemoji/16.0/2705/32.png) Installed successfully  
  
Installing luacheck...  
[DEBUG] Tool: luacheck  
[DEBUG] Primary PM: winget  
[DEBUG] Installer: WingetInstaller  
[DEBUG] PM package: None  
[DEBUG] Choco package: lua  
[DEBUG] NPM package: None  
[DEBUG] PIP package: None  
  → Installing luacheck via choco: lua  
[DEBUG] Running: choco install lua -y  
[DEBUG] Chocolatey output:  
------------------------------------------------------------  
Chocolatey v2.5.1  
Installing the following packages:  
lua  
By installing, you accept licenses for the packages.  
Downloading package from source '[https://community.chocolatey.org/api/v2/](https://community.chocolatey.org/api/v2/)'  
Progress: Downloading vcredist2005 8.0.50727.619501... 100%  
  
vcredist2005 v8.0.50727.619501 [Approved]  
vcredist2005 package files install completed. Performing other installation steps.  
Downloading vcredist2005 64 bit  
  from '[https://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x64.EXE](https://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x64.EXE)'  
Progress: 100% - Completed download of C:\Users\rossc\AppData\Local\Temp\chocolatey\vcredist2005\8.0.50727.619501\vcredist_x64.EXE (3.03 MB).  
Download of vcredist_x64.EXE (3.03 MB) completed.  
Hashes match.  
Installing vcredist2005...  
vcredist2005 has been installed.  
Downloading vcredist2005 32 bit  
  from '[https://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x86.EXE](https://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x86.EXE)'  
Progress: 100% - Completed download of C:\Users\rossc\AppData\Local\Temp\chocolatey\vcredist2005\8.0.50727.619501\vcredist_x86.EXE (2.58 MB).  
Download of vcredist_x86.EXE (2.58 MB) completed.  
Hashes match.  
Installing vcredist2005...  
vcredist2005 has been installed.  
  vcredist2005 may be able to be automatically uninstalled.  
 The install of vcredist2005 was successful.  
  Software installed as 'exe', install location is likely default.  
Downloading package from source '[https://community.chocolatey.org/api/v2/](https://community.chocolatey.org/api/v2/)'  
Progress: Downloading Lua 5.1.5.52... 100%  
  
lua v5.1.5.52 [Approved]  
lua package files install completed. Performing other installation steps.  
Downloading lua  
  from '[https://github.com/rjpcomputing/luaforwindows/releases/download/v5.1.5-52/LuaForWindows_v5.1.5-52.exe](https://github.com/rjpcomputing/luaforwindows/releases/download/v5.1.5-52/LuaForWindows_v5.1.5-52.exe)'  
Progress: 100% - Completed download of C:\Users\rossc\AppData\Local\Temp\chocolatey\Lua\5.1.5.52\LuaForWindows_v5.1.5-52.exe (27.8 MB).  
Download of LuaForWindows_v5.1.5-52.exe (27.8 MB) completed.  
Hashes match.  
Installing lua...  
lua has been installed.  
  lua can be automatically uninstalled.  
Environment Vars (like PATH) have changed. Close/reopen your shell to  
 see the changes (or in powershell/cmd.exe just type `refreshenv`).  
 The install of lua was successful.  
  Deployed to 'C:\Program Files (x86)\Lua\5.1\'  
  
Chocolatey installed 2/2 packages.  
 See the log for details (C:\ProgramData\chocolatey\logs\chocolatey.log).  
------------------------------------------------------------  
[DEBUG] Exit code: 0  
  ![✅](https://fonts.gstatic.com/s/e/notoemoji/16.0/2705/32.png) Installed successfully  
  
Installing mix...  
[DEBUG] Tool: mix  
[DEBUG] Primary PM: winget  
[DEBUG] Installer: WingetInstaller  
[DEBUG] PM package: None  
[DEBUG] Choco package: elixir  
[DEBUG] NPM package: None  
[DEBUG] PIP package: None  
  → Installing mix via choco: elixir  
[DEBUG] Running: choco install elixir -y  
[DEBUG] Chocolatey output:  
------------------------------------------------------------  
Chocolatey v2.5.1  
Installing the following packages:  
elixir  
By installing, you accept licenses for the packages.  
Downloading package from source '[https://community.chocolatey.org/api/v2/](https://community.chocolatey.org/api/v2/)'  
Progress: Downloading erlang 28.1.1... 100%  
  
erlang v28.1.1 [Approved]  
erlang package files install completed. Performing other installation steps.  
Downloading erlang 64 bit  
  from '[https://github.com/erlang/otp/releases/download/OTP-28.1.1/otp_win64_28.1.1.exe](https://github.com/erlang/otp/releases/download/OTP-28.1.1/otp_win64_28.1.1.exe)'  
Progress: 100% - Completed download of C:\Users\rossc\AppData\Local\Temp\chocolatey\erlang\28.1.1\otp_win64_28.1.1.exe (141.44 MB).  
Download of otp_win64_28.1.1.exe (141.44 MB) completed.  
Hashes match.  
Installing erlang...  
erlang has been installed.  
Added C:\ProgramData\chocolatey\bin\ct_run.exe shim pointed to 'c:\program files\erlang otp\erts-16.1.1\bin\ct_run.exe'.  
Added C:\ProgramData\chocolatey\bin\erl.exe shim pointed to 'c:\program files\erlang otp\erts-16.1.1\bin\erl.exe'.  
Added C:\ProgramData\chocolatey\bin\werl.exe shim pointed to 'c:\program files\erlang otp\erts-16.1.1\bin\werl.exe'.  
Added C:\ProgramData\chocolatey\bin\erlc.exe shim pointed to 'c:\program files\erlang otp\erts-16.1.1\bin\erlc.exe'.  
Added C:\ProgramData\chocolatey\bin\escript.exe shim pointed to 'c:\program files\erlang otp\erts-16.1.1\bin\escript.exe'.  
Added C:\ProgramData\chocolatey\bin\dialyzer.exe shim pointed to 'c:\program files\erlang otp\erts-16.1.1\bin\dialyzer.exe'.  
Added C:\ProgramData\chocolatey\bin\typer.exe shim pointed to 'c:\program files\erlang otp\erts-16.1.1\bin\typer.exe'.  
  erlang may be able to be automatically uninstalled.  
 The install of erlang was successful.  
  Software installed as 'exe', install location is likely default.  
Downloading package from source '[https://community.chocolatey.org/api/v2/](https://community.chocolatey.org/api/v2/)'  
Progress: Downloading Elixir 1.19.3... 100%  
  
elixir v1.19.3 [Approved]  
elixir package files install completed. Performing other installation steps.  
Downloading elixir  
  from '[https://github.com/elixir-lang/elixir/releases/download/v1.19.3/elixir-otp-28.zip](https://github.com/elixir-lang/elixir/releases/download/v1.19.3/elixir-otp-28.zip)'  
Progress: 100% - Completed download of C:\Users\rossc\AppData\Local\Temp\chocolatey\Elixir\1.19.3\elixir-otp-28.zip (7.86 MB).  
Download of elixir-otp-28.zip (7.86 MB) completed.  
Hashes match.  
Extracting C:\Users\rossc\AppData\Local\Temp\chocolatey\Elixir\1.19.3\elixir-otp-28.zip to C:\ProgramData\chocolatey\lib\Elixir\tools...  
C:\ProgramData\chocolatey\lib\Elixir\tools  
------------------------------------------------------------------------  
NOTE:  
  
The Elixir commands have been installed to:  
  
C:\ProgramData\chocolatey\lib\Elixir\tools\bin  
  
Please add this directory to your PATH,  
then your shell session to access these commands:  
  
elixir  
elixirc  
mix  
iex  
------------------------------------------------------------------------  
 The install of elixir was successful.  
  Deployed to 'C:\ProgramData\chocolatey\lib\Elixir\tools'  
  
Chocolatey installed 2/2 packages.  
 See the log for details (C:\ProgramData\chocolatey\logs\chocolatey.log).  
------------------------------------------------------------  
[DEBUG] Exit code: 0  
  ![✅](https://fonts.gstatic.com/s/e/notoemoji/16.0/2705/32.png) Installed successfully  
  
Installing hlint...  
[DEBUG] Tool: hlint  
[DEBUG] Primary PM: winget  
[DEBUG] Installer: WingetInstaller  
[DEBUG] PM package: None  
[DEBUG] Choco package: ghc  
[DEBUG] NPM package: None  
[DEBUG] PIP package: None  
  → Installing hlint via choco: ghc  
[DEBUG] Running: choco install ghc -y  
[DEBUG] Chocolatey output:  
------------------------------------------------------------  
Chocolatey v2.5.1  
Installing the following packages:  
ghc  
By installing, you accept licenses for the packages.  
Downloading package from source '[https://community.chocolatey.org/api/v2/](https://community.chocolatey.org/api/v2/)'  
Progress: Downloading cabal 3.10.2.0... 100%  
  
cabal v3.10.2 [Approved]  
cabal package files install completed. Performing other installation steps.  
Downloading cabal 64 bit  
  from '[https://downloads.haskell.org/cabal/cabal-install-3.10.2.0/cabal-install-3.10.2.0-x86_64-windows.zip](https://downloads.haskell.org/cabal/cabal-install-3.10.2.0/cabal-install-3.10.2.0-x86_64-windows.zip)'  
Progress: 100% - Completed download of C:\Users\rossc\AppData\Local\Temp\chocolatey\cabal\3.10.2\cabal-install-3.10.2.0-x86_64-windows.zip (14.93 MB).  
Download of cabal-install-3.10.2.0-x86_64-windows.zip (14.93 MB) completed.  
Hashes match.  
Extracting C:\Users\rossc\AppData\Local\Temp\chocolatey\cabal\3.10.2\cabal-install-3.10.2.0-x86_64-windows.zip to C:\ProgramData\chocolatey\lib\cabal\tools\cabal-3.10.2.0...  
C:\ProgramData\chocolatey\lib\cabal\tools\cabal-3.10.2.0  
Could not read cabal configuration key 'install-method'.  
Updated cabal configuration.  
PATH environment variable does not have C:\Users\rossc\AppData\Roaming\cabal\bin in it. Adding...  
Finding cabal config file...  
Detected config file: 'C:\Users\rossc\AppData\Roaming\cabal\config'.  
Forcibly correct backwards incompatible cabal configurations.  
Adding C:\ProgramData\chocolatey\bin\mingw64-pkg.bat and pointing it to powershell command C:\ProgramData\chocolatey\lib\cabal\tools\mingw64-pkg.ps1  
Environment Vars (like PATH) have changed. Close/reopen your shell to  
 see the changes (or in powershell/cmd.exe just type `refreshenv`).  
 ShimGen has successfully created a shim for cabal.exe  
 The install of cabal was successful.  
  Deployed to 'C:\ProgramData\chocolatey\lib\cabal\tools\cabal-3.10.2.0'  
Downloading package from source '[https://community.chocolatey.org/api/v2/](https://community.chocolatey.org/api/v2/)'  
Progress: Downloading ghc 9.8.2... 100%  
  
ghc v9.8.2 [Approved] - Possibly broken  
ghc package files install completed. Performing other installation steps.  
Downloading ghc 64 bit  
  from '[https://downloads.haskell.org/~ghc/9.8.2/ghc-9.8.2-x86_64-unknown-mingw32.tar.xz](https://downloads.haskell.org/~ghc/9.8.2/ghc-9.8.2-x86_64-unknown-mingw32.tar.xz)'  
Progress: 100% - Completed download of C:\tools\ghc-9.8.2\tmp\ghcInstall (309.95 MB).  
Download of ghcInstall (309.95 MB) completed.                                                                                                                Hashes match.                                                                                                                                                C:\tools\ghc-9.8.2\tmp\ghcInstall                                                                                                                            Extracting C:\tools\ghc-9.8.2\tmp\ghcInstall to C:\tools...                                                                                                  C:\tools                                                                                                                                                     Extracting C:\tools\ghcInstall~ to C:\tools...                                                                                                               C:\tools                                                                                                                                                     Renamed C:\tools\ghc-9.8.2-x86_64-unknown-mingw32 to C:\tools\ghc-9.8.2                                                                                      PATH environment variable does not have C:\tools\ghc-9.8.2\bin in it. Adding...  
Hiding shims for 'C:\tools'.  
Environment Vars (like PATH) have changed. Close/reopen your shell to  
 see the changes (or in powershell/cmd.exe just type `refreshenv`).  
 The install of ghc was successful.  
  Deployed to 'C:\tools'  
  
Chocolatey installed 2/2 packages.  
 See the log for details (C:\ProgramData\chocolatey\logs\chocolatey.log).  
------------------------------------------------------------  
[DEBUG] Exit code: 0  
  ![✅](https://fonts.gstatic.com/s/e/notoemoji/16.0/2705/32.png) Installed successfully  
  
Installing clj-kondo...  
[DEBUG] Tool: clj-kondo  
[DEBUG] Primary PM: winget  
[DEBUG] Installer: WingetInstaller  
[DEBUG] PM package: None  
[DEBUG] Choco package: None  
[DEBUG] NPM package: None  
[DEBUG] PIP package: None  
  → Using custom Windows installer...  
[DEBUG] Running PowerShell installer: install-clj-kondo.ps1  
[DEBUG] Script written to: C:\Users\rossc\AppData\Local\Temp\tmpw3jh6jvp.ps1  
[DEBUG] Using PowerShell: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe  
[DEBUG] Running: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Users\rossc\AppData\Local\Temp\tmpw3jh6jvp.ps1 -Debug  
[2025-11-23 17:27:49] [INFO] Starting clj-kondo installation...  
[2025-11-23 17:27:49] [INFO] Fetching release information for version v2025.10.23...  
[2025-11-23 17:27:49] [INFO] Installing version: v2025.10.23  
[2025-11-23 17:27:49] [INFO] Found asset: clj-kondo-2025.10.23-windows-amd64.zip  
[2025-11-23 17:27:49] [INFO] Creating install directory: C:\Users\rossc\AppData\Local\clj-kondo  
[2025-11-23 17:27:49] [INFO] Downloading from: [https://github.com/clj-kondo/clj-kondo/releases/download/v2025.10.23/clj-kondo-2025.10.23-windows-amd64.zip](https://github.com/clj-kondo/clj-kondo/releases/download/v2025.10.23/clj-kondo-2025.10.23-windows-amd64.zip)  
Downloading clj-kondo v2025.10.23...  
[2025-11-23 17:28:12] [INFO] Download complete: C:\Users\rossc\AppData\Local\Temp\clj-kondo.zip  
[2025-11-23 17:28:12] [INFO] Extracting to: C:\Users\rossc\AppData\Local\clj-kondo  
Extracting files...  
[2025-11-23 17:28:14] [INFO] Cleanup complete  
  
SUCCESS: clj-kondo installed successfully!  
   Location: C:\Users\rossc\AppData\Local\clj-kondo\clj-kondo.exe  
  
NOTE: C:\Users\rossc\AppData\Local\clj-kondo is not in your PATH  
   Add to PATH to use 'clj-kondo' command globally  
  
   To add to PATH (run as administrator):  
   [Environment]::SetEnvironmentVariable('Path', $env:Path + ';C:\Users\rossc\AppData\Local\clj-kondo', 'Machine')  
  
   Testing installation...  
   Version: clj-kondo v2025.10.23  
[DEBUG] Successfully installed clj-kondo via PowerShell script  
  ![✅](https://fonts.gstatic.com/s/e/notoemoji/16.0/2705/32.png) Installed successfully  
  
Installing dart...  
[DEBUG] Tool: dart  
[DEBUG] Primary PM: winget  
[DEBUG] Installer: WingetInstaller  
[DEBUG] PM package: Google.DartSDK  
[DEBUG] Choco package: None  
[DEBUG] NPM package: None  
[DEBUG] PIP package: None  
  → Installing dart via winget: Google.DartSDK  
  ![✅](https://fonts.gstatic.com/s/e/notoemoji/16.0/2705/32.png) Installed successfully  
  
Installing codenarc...  
[DEBUG] Tool: codenarc  
[DEBUG] Primary PM: winget  
[DEBUG] Installer: WingetInstaller  
[DEBUG] PM package: None  
[DEBUG] Choco package: groovy  
[DEBUG] NPM package: None  
[DEBUG] PIP package: None  
  → Installing codenarc via choco: groovy  
[DEBUG] Running: choco install groovy -y  
[DEBUG] Chocolatey output:  
------------------------------------------------------------  
Chocolatey v2.5.1  
Installing the following packages:  
groovy  
By installing, you accept licenses for the packages.  
Downloading package from source '[https://community.chocolatey.org/api/v2/](https://community.chocolatey.org/api/v2/)'  
Progress: Downloading groovy 3.0.25... 100%  
  
groovy v3.0.25 [Approved] - Likely broken for FOSS users (due to download location changes)  
groovy package files install completed. Performing other installation steps.  
Downloading groovy  
  from '[https://groovy.jfrog.io/artifactory/dist-release-local/groovy-zips/apache-groovy-binary-3.0.25.zip](https://groovy.jfrog.io/artifactory/dist-release-local/groovy-zips/apache-groovy-binary-3.0.25.zip)'  
Progress: 100% - Completed download of C:\Users\rossc\AppData\Local\Temp\chocolatey\groovy\3.0.25\apache-groovy-binary-3.0.25.zip (42.96 MB).  
Download of apache-groovy-binary-3.0.25.zip (42.96 MB) completed.  
Hashes match.  
Extracting C:\Users\rossc\AppData\Local\Temp\chocolatey\groovy\3.0.25\apache-groovy-binary-3.0.25.zip to C:\tools...  
C:\tools  
PATH environment variable does not have %GROOVY_HOME%\bin in it. Adding...  
Environment Vars (like PATH) have changed. Close/reopen your shell to  
 see the changes (or in powershell/cmd.exe just type `refreshenv`).  
 The install of groovy was successful.  
  Deployed to 'C:\tools'  
  
Chocolatey installed 1/1 packages.  
 See the log for details (C:\ProgramData\chocolatey\logs\chocolatey.log).  
  
Enjoy using Chocolatey? Explore more amazing features to take your  
experience to the next level at  
 [https://chocolatey.org/compare](https://chocolatey.org/compare)  
------------------------------------------------------------  
[DEBUG] Exit code: 0  
  ![✅](https://fonts.gstatic.com/s/e/notoemoji/16.0/2705/32.png) Installed successfully  
  
Installing vim-vint...  
[DEBUG] Tool: vim-vint  
[DEBUG] Primary PM: winget  
[DEBUG] Installer: WingetInstaller  
[DEBUG] PM package: None  
[DEBUG] Choco package: None  
[DEBUG] NPM package: None  
[DEBUG] PIP package: vim-vint  
  → Installing vim-vint via pip: vim-vint  
  ![✅](https://fonts.gstatic.com/s/e/notoemoji/16.0/2705/32.png) Installed successfully  
  
Installing cmakelang...  
[DEBUG] Tool: cmakelang  
[DEBUG] Primary PM: winget  
[DEBUG] Installer: WingetInstaller  
[DEBUG] PM package: None  
[DEBUG] Choco package: None  
[DEBUG] NPM package: None  
[DEBUG] PIP package: cmakelang  
  → Installing cmakelang via pip: cmakelang  
  ![✅](https://fonts.gstatic.com/s/e/notoemoji/16.0/2705/32.png) Installed successfully  
  
Installing checkmake...  
[DEBUG] Tool: checkmake  
[DEBUG] Primary PM: winget  
[DEBUG] Installer: WingetInstaller  
[DEBUG] PM package: None  
[DEBUG] Choco package: None  
[DEBUG] NPM package: None  
[DEBUG] PIP package: None  
  → Using custom Windows installer...  
  
![⚠️](https://fonts.gstatic.com/s/e/notoemoji/16.0/26a0_fe0f/32.png)  Unable to automatically install checkmake  
  
Please install manually:  
  Install via package manager or download from official website  
  Note: checkmake requires Go toolchain (go install [github.com/mrtazz/checkmake/cmd/checkmake@latest](http://github.com/mrtazz/checkmake/cmd/checkmake@latest))  
  
After installation, add to PATH and run: medusa install --check  
  ![❌](https://fonts.gstatic.com/s/e/notoemoji/16.0/274c/32.png) Custom installer failed  
  → Looking for go... ✗ Not found  
  ⊘ Review installation guide for manual setup  
  
Installing gixy...  
[DEBUG] Tool: gixy  
[DEBUG] Primary PM: winget  
[DEBUG] Installer: WingetInstaller  
[DEBUG] PM package: None  
[DEBUG] Choco package: None  
[DEBUG] NPM package: None  
[DEBUG] PIP package: gixy  
  → Installing gixy via pip: gixy  
  ![✅](https://fonts.gstatic.com/s/e/notoemoji/16.0/2705/32.png) Installed successfully  
  
Installing zig...  
[DEBUG] Tool: zig  
[DEBUG] Primary PM: winget  
[DEBUG] Installer: WingetInstaller  
[DEBUG] PM package: Zig.Zig  
[DEBUG] Choco package: None  
[DEBUG] NPM package: None  
[DEBUG] PIP package: None  
  → Installing zig via winget: Zig.Zig  
  ![✅](https://fonts.gstatic.com/s/e/notoemoji/16.0/2705/32.png) Installed successfully  
  
  
Installation Summary:  
  ![✅](https://fonts.gstatic.com/s/e/notoemoji/16.0/2705/32.png) Installed: 36  
  ![❌](https://fonts.gstatic.com/s/e/notoemoji/16.0/274c/32.png) Failed: 3  
  
![⚠️](https://fonts.gstatic.com/s/e/notoemoji/16.0/26a0_fe0f/32.png)  Windows PATH Update Required  
   Please restart your terminal for the installed tools to be detected  
   Tools installed via winget/npm may not be in your PATH until you restart  
  
![📄](https://fonts.gstatic.com/s/e/notoemoji/16.0/1f4c4/32.png) Installation guide created: C:\WINDOWS\system32\.medusa\installation-guide.md  
   See this file for manual installation instructions  
  
Run 'medusa config' to see updated scanner status  
PS C:\WINDOWS\system32>