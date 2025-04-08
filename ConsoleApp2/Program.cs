using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.RegularExpressions;
using Microsoft.Win32;

class WindowsOptimizerUltimate
{
    private static readonly string DesktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
    private static readonly string LogFile = Path.Combine(DesktopPath, "OptimizationLog.txt");
    private static readonly string RestoreLog = Path.Combine(DesktopPath, "RestorePoint_Log.txt");
    private static bool _defenderDisabled = false;

    static void Main()
    {
        try
        {
            Console.Title = "Windows Optimizer Ultimate v8.1 [STABLE]";
            File.WriteAllText(LogFile, $"Оптимизация начата: {DateTime.Now}\n\n");

            if (!IsAdmin())
            {
                Log("Требуются права администратора!", true);
                Console.ReadKey();
                return;
            }

            bool createRestorePoint = AskUser("Создать точку восстановления перед оптимизацией? (Y/N)");
            bool defenderOriginallyEnabled = IsDefenderEnabled();

            Log("=== НАЧАЛО ГЛУБОКОЙ ОПТИМИЗАЦИИ ===");
ToggleDefenderDuringActivation();
            if (createRestorePoint)
            {
                CreateRestorePoint();
            }

            if (IsWindows11OrHigher())
            {
                ApplyWindows11SpecificPatches();
            }

            if (AskUser("Выполнить расширенную активацию Windows? (Y/N)"))
            {
                ActivateWindowsWithKeySelection();
            }

            
            OptimizeSystemServices();
            RemoveOneDrive();
            DisableUAC();
            DisableBackgroundApps();
            SetMaxPowerPlan();
            ManageBitLocker();
            FinalDefenderChoice(defenderOriginallyEnabled);

            Log("\n=== ОПТИМИЗАЦИЯ ЗАВЕРШЕНА ===");
            Process.Start("notepad.exe", LogFile);
        }
        catch (Exception ex)
        {
            Log($"\n!!! КРИТИЧЕСКАЯ ОШИБКА: {ex.Message}", true);
        }
        finally
        {
            Console.ReadKey();
        }
    }

    #region Активация Windows
    static void ActivateWindowsWithKeySelection()
    {
        try
        {
            Log("\n[1/10] Интеллектуальная активация Windows...");

            string kmsKey = GetKmsKeyForCurrentEdition();
            string[] kmsServers = {
            "kms.digiboy.ir",
            "kms03.kmserver.ru",
            "s8.uk.to",
            "kms.chinancr.com"
        };

            ExecuteCmd("slmgr /upk", 1000);
            ExecuteCmd($"slmgr /ipk {kmsKey}", 2000);

            bool activationSuccess = false;
            foreach (var server in kmsServers)
            {
                Log($"Попытка активации через: {server}");

                // Выполняем активацию
                ExecuteCmd($"slmgr /skms {server} && slmgr /ato", 3000);

                // Проверяем статус лицензии
                string licenseCheck = ExecuteCmd(
                    "wmic path SoftwareLicensingProduct where \"PartialProductKey is not null\" get Description, LicenseStatus | findstr /v /c:\"BINARY\"",
                    2000);

                if (IsLicenseActive(licenseCheck))
                {
                    Log($"[УСПЕХ] Система активирована через {server}");
                    activationSuccess = true;
                    break;
                }
            }

            if (!activationSuccess)
            {
                Log("Запуск альтернативного метода активации...");
                ExecutePowerShell("irm https://get.activated.win | iex");

                // Финальная проверка
                string finalCheck = ExecuteCmd(
                    "wmic path SoftwareLicensingProduct where \"PartialProductKey is not null\" get LicenseStatus",
                    2000);

                if (!IsLicenseActive(finalCheck))
                {
                    Log("Ошибка активации! Проверьте подключение к интернету");
                }
            }
        }
        catch
        {
            ExecutePowerShell("Start-Process chrome.exe 'https://kms.msguides.com' -WindowStyle Hidden");
        }
    }

    static bool IsLicenseActive(string licenseOutput)
    {
        try
        {
            // Ищем статус лицензии в выводе
            var lines = licenseOutput.Split('\n')
                .Where(line => !string.IsNullOrWhiteSpace(line))
                .Select(line => line.Trim());

            foreach (var line in lines)
            {
                if (line.Contains("Windows(R)") || line.Contains("Операционная система"))
                {
                    var match = Regex.Match(line, @"\b1\b");
                    return match.Success;
                }
            }
        }
        catch
        {
            // Резервная проверка через slmgr
            string slmgrStatus = ExecuteCmd("slmgr /xpr", 1000);
            return slmgrStatus.Contains("активирована") || slmgrStatus.Contains("activated");
        }
        return false;
    }

    static string GetKmsKeyForCurrentEdition()
    {
        var edition = ExecutePowerShell("(Get-WmiObject -Class Win32_OperatingSystem).Caption");
        var keys = new System.Collections.Generic.Dictionary<string, string>()
        {
            {"Pro", "W269N-WFGWX-YVC9B-4J6C9-T83GX"},
            {"Pro N", "MH37W-N47XK-V7XM9-C7227-GCQG9"},
            {"Enterprise", "NPPR9-FWDCX-D2C8J-H872K-2YT43"},
            {"Education", "NW6C2-QMPVW-D7KKK-3GKT6-VCFB2"}
        };

        foreach (var key in keys)
        {
            if (edition.Contains(key.Key)) return key.Value;
        }
        return "W269N-WFGWX-YVC9B-4J6C9-T83GX";
    }
    #endregion

    #region Оптимизация Windows 11
    static bool IsWindows11OrHigher()
    {
        var version = Environment.OSVersion.Version;
        return version.Major >= 10 && version.Build >= 22000;
    }

    static void ApplyWindows11SpecificPatches()
    {
        Log("\n[2/10] Специальные патчи для Windows 11...");

        ExecutePowerShell(
            "reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot' /v 'UEFISecureBootEnabled' /t REG_DWORD /d 0 /f;" +
            "reg add 'HKLM\\SYSTEM\\Setup\\MoSetup' /v 'AllowUpgradesWithUnsupportedTPMOrCPU' /t REG_DWORD /d 1 /f");

        string[] bloatware = {
            "MicrosoftTeams", "XboxGameCallableUI",
            "Clipchamp", "WindowsWebExperienceHost"
        };

        foreach (var app in bloatware)
        {
            ExecutePowerShell(
                $"Get-AppxPackage *{app}* | Foreach {{ " +
                "try { Remove-AppxPackage -Package $_.PackageFullName -AllUsers -Force } " +
                "catch { Write-Output $_.Exception.Message } }");
        }

        ExecuteCmd("reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced /v TaskbarDa /f", 500);
    }
    #endregion

    #region Системные службы
    static void OptimizeSystemServices()
    {
        Log("\n[3/10] Оптимизация системных служб...");
        string[] services = {
            "MapsBroker", "lfsvc", "WpcMonSvc",
            "XblAuthManager", "XblGameSave", "XboxNetApiSvc",
            "wisvc", "WalletService", "AssignedAccessManager"
        };

        foreach (var service in services)
        {
            ExecuteCmd($"sc stop {service} && sc config {service} start= disabled", 500);
            Log($"Служба {service} отключена");
        }
    }
    #endregion

    #region OneDrive
    static void RemoveOneDrive()
    {
        try
        {
            Log("\n[4/10] Полное удаление OneDrive...");

            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string oneDrivePath = Path.Combine(localAppData, "Microsoft", "OneDrive");

            ExecutePowerShell(
                "taskkill /f /im OneDrive.exe;" +
                $"Remove-Item -Path '{oneDrivePath}' -Recurse -Force -ErrorAction SilentlyContinue;" +
                "reg delete 'HKCU\\Software\\Microsoft\\OneDrive' /f;" +
                "reg delete 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\OneDrive' /f");
        }
        catch (Exception ex)
        {
            Log($"Ошибка: {ex.Message}");
        }
    }
    #endregion

    #region Безопасность
    static void DisableUAC()
    {
        try
        {
            Log("\n[5/10] Отключение UAC...");
            using (var key = Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"))
            {
                key.SetValue("EnableLUA", 0, RegistryValueKind.DWord);
                key.SetValue("ConsentPromptBehaviorAdmin", 0, RegistryValueKind.DWord);
            }
            Log("UAC полностью отключен!");
        }
        catch (Exception ex)
        {
            Log($"Ошибка: {ex.Message}");
        }
    }
    #endregion

    #region Фоновые процессы
    static void DisableBackgroundApps()
    {
        try
        {
            Log("\n[6/10] Очистка фоновых процессов...");
            ExecutePowerShell(
                "Get-AppxPackage | Where-Object {$_.NonRemovable -eq $false} | " +
                "Foreach { try { Remove-AppxPackage -Package $_.PackageFullName -Force } catch {} }");
        }
        catch (Exception ex)
        {
            Log($"Ошибка: {ex.Message}");
        }
    }
    #endregion

    #region Питание
    static void SetMaxPowerPlan()
    {
        try
        {
            Log("\n[7/10] Настройка режима питания...");
            ExecuteCmd("powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c", 1000);
            ExecutePowerShell("powercfg /hibernate off");
            Log("Режим 'Максимальная производительность' активирован");
        }
        catch (Exception ex)
        {
            Log($"Ошибка: {ex.Message}");
        }
    }
    #endregion

    #region BitLocker
    static void ManageBitLocker()
    {
        try
        {
            Log("\n[8/10] Управление BitLocker...");
            ExecutePowerShell(
                "if (Get-Command Manage-bde -ErrorAction SilentlyContinue) {" +
                "   Manage-bde -off C: -Force" +
                "} else {" +
                "   reg add 'HKLM\\SOFTWARE\\Policies\\Microsoft\\FVE' /v 'UseAdvancedStartup' /t REG_DWORD /d 1 /f;" +
                "   reg add 'HKLM\\SOFTWARE\\Policies\\Microsoft\\FVE' /v 'EnableBDEWithNoTPM' /t REG_DWORD /d 1 /f" +
                "}");
        }
        catch (Exception ex)
        {
            Log($"Ошибка: {ex.Message}");
        }
    }
    #endregion

    #region Защитник Windows
    static void ToggleDefenderDuringActivation()
    {
        if (AskUser("Отключить системную защиту на время оптимизации? (Y/N)"))
        {
            ToggleDefender(false);
            _defenderDisabled = true;
        }
    }

    static void FinalDefenderChoice(bool originalState)
    {
        if (!_defenderDisabled) return;

        if (AskUser("Включить системную защиту обратно? (Y/N)"))
        {
            ToggleDefender(true);
        }
        else
        {
            Log("Защита остаётся отключённой!");
            if (originalState) Log("ВНИМАНИЕ: Защита была активна до оптимизации");
        }
    }

    static void ToggleDefender(bool enable)
    {
        Log($"\n{(enable ? "Включение" : "Отключение")} системной защиты...");
        ExecutePowerShell(
            "Set-MpPreference -DisableRealtimeMonitoring $true;" +
            "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender' -Name 'DisableAntiSpyware' -Value 1 -Force;" +
            "reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\SecurityHealthService' /v 'Start' /t REG_DWORD /d 4 /f");
    }

    static bool IsDefenderEnabled()
    {
        try
        {
            return ExecuteCmd("sc query WinDefend", 500).Contains("RUNNING");
        }
        catch
        {
            return false;
        }
    }
    #endregion

    #region Вспомогательные методы
    static void CreateRestorePoint()
    {
        try
        {
            Log("\nСоздание точки восстановления...");
            ExecutePowerShell(
                "Checkpoint-Computer -Description 'Pre-Optimize' -RestorePointType MODIFY_SETTINGS;" +
                $"Get-ComputerRestorePoint | Out-File '{RestoreLog}'");
        }
        catch (Exception ex)
        {
            Log($"Ошибка: {ex.Message}");
        }
    }

    static bool IsAdmin() => new WindowsPrincipal(WindowsIdentity.GetCurrent())
        .IsInRole(WindowsBuiltInRole.Administrator);

    static bool AskUser(string question)
    {
        Console.WriteLine($"\n{question}");
        while (true)
        {
            var key = Console.ReadKey(true).Key;
            if (key == ConsoleKey.Y) { Console.WriteLine("Да"); return true; }
            if (key == ConsoleKey.N) { Console.WriteLine("Нет"); return false; }
        }
    }

    static string ExecuteCmd(string command, int timeout)
    {
        try
        {
            using (var process = new Process())
            {
                process.StartInfo = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/c {command}",
                    WindowStyle = ProcessWindowStyle.Hidden,
                    RedirectStandardOutput = true,
                    UseShellExecute = false
                };

                process.Start();
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit(timeout);

                File.AppendAllText(LogFile, $"\n[CMD] {command}\n{output}");
                return output;
            }
        }
        catch (Exception ex)
        {
            Log($"Ошибка команды: {ex.Message}");
            return string.Empty;
        }
    }

    static string ExecutePowerShell(string script)
    {
        try
        {
            using (var process = new Process())
            {
                process.StartInfo = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-ExecutionPolicy Bypass -Command \"{script}\"",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                process.Start();
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit(15000);

                File.AppendAllText(LogFile, $"\n[PowerShell]\n{output}");
                return output;
            }
        }
        catch
        {
            return string.Empty;
        }
    }

    static void Log(string message, bool showConsole = true)
    {
        string logEntry = $"{DateTime.Now:HH:mm:ss} - {message}";
        File.AppendAllText(LogFile, $"{logEntry}\n");
        if (showConsole) Console.WriteLine(logEntry);
    }
    #endregion
}