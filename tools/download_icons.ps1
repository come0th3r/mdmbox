$icons = @("speed","dns","route","settings","terminal","info","remove","close","check_box_outline_blank","content_paste","bolt","power_settings_new","language","expand_more","drag_indicator","add","upload","download","restart_alt","edit","public","shield","block")
$outDir = "C:\Users\0th3r\nekoray\nekoray-main\res\icons"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
foreach ($icon in $icons) {
    $url = "https://raw.githubusercontent.com/google/material-design-icons/master/symbols/web/$icon/materialsymbolsoutlined/${icon}_24px.svg"
    $out = "$outDir\$icon.svg"
    try {
        Invoke-WebRequest -Uri $url -OutFile $out -TimeoutSec 15 -ErrorAction Stop
        Write-Host "OK: $icon"
    } catch {
        Write-Host "FAIL: $icon - $($_.Exception.Message)"
    }
}
Write-Host "Done!"
