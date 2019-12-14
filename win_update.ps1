Write-Host -ForegroundColor Green "Searching for updates (this may take up to 30 minutes or more)..."

    $updateSession = New-Object -com Microsoft.Update.Session
    $updateSearcher = $updateSession.CreateupdateSearcher()
    try
    {

      $searchResult = $updateSearcher.Search("Type='Software' and IsHidden=0 and IsInstalled=0").Updates
      $searchResult = $searchResult | where {$_.Title | Select-String -Pattern "(Security)|(Critical)|(Preview)|(Update)|(Microsoft)"}

    }
    catch
    {

     Write-Host -ForegroundColor Red "InstallWindowsUpdates: Update attempt failed."
      $updateFailed = $true
    }

    if(!($updateFailed)) {
      foreach ($updateItem in $searchResult) {
        $UpdatesToDownload = New-Object -com Microsoft.Update.UpdateColl
        if (!($updateItem.EulaAccepted)) {
          $updateItem.AcceptEula()
        }
        $UpdatesToDownload.Add($updateItem)
        $Downloader = $UpdateSession.CreateUpdateDownloader()
        $Downloader.Updates = $UpdatesToDownload
        $Downloader.Download()
        $UpdatesToInstall = New-Object -com Microsoft.Update.UpdateColl
        $UpdatesToInstall.Add($updateItem)
        $Title = $updateItem.Title
        Write-host -ForegroundColor Green "  Installing Update: $Title"
        $Installer = $UpdateSession.CreateUpdateInstaller()
        $Installer.Updates = $UpdatesToInstall
        $InstallationResult = $Installer.Install()
        Write-Host -ForegroundColor Green "InstallWindowsUpdates: Installed update $Title."
      }

      if (!($searchResult.Count)) {
        Write-Host -ForegroundColor Green "InstallWindowsUpdates: No updates available."
      }
      Write-Host -ForegroundColor Green "InstallWindowsUpdates: Done Installing Updates."
    }
Exit 0
