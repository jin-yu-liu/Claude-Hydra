!define HYDRA_SANDBOXIE_SETUP "${__FILEDIR__}\..\binaries\Sandboxie-Plus-Setup.exe"
!define MUI_WELCOMEPAGE_TEXT "安装程序将使用 Windows 管理员权限安装 Claude Hydra，并在需要时配置 Sandboxie-Plus 驱动。$\r$\n$\r$\n安装完成后，可在每个环境的「沙箱隔离」设置中选择是否启用。"

; Match the runtime's discovery paths. Keep existing installations and their settings.
Function HydraFindSandboxie
  ReadRegStr $0 HKLM "SYSTEM\CurrentControlSet\Services\SbieDrv" "ImagePath"
  StrCmp $0 "" missing
  ReadRegStr $0 HKLM "SYSTEM\CurrentControlSet\Services\SbieSvc" "ImagePath"
  StrCmp $0 "" missing
  !macro CheckSandboxieDir
    ${If} $0 != ""
    ${AndIf} ${FileExists} "$0\Start.exe"
    ${AndIf} ${FileExists} "$0\SbieIni.exe"
      Push 1
      Return
    ${EndIf}
  !macroend
  ReadRegStr $0 HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Sandboxie-Plus_is1" "InstallLocation"
  !insertmacro CheckSandboxieDir
  ReadRegStr $0 HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Sandboxie-Plus" "InstallLocation"
  !insertmacro CheckSandboxieDir
  StrCpy $0 "$PROGRAMFILES64\Sandboxie-Plus"
  !insertmacro CheckSandboxieDir
  StrCpy $0 "$PROGRAMFILES64\Sandboxie"
  !insertmacro CheckSandboxieDir
  missing:
  Push 0
FunctionEnd

!macro NSIS_HOOK_PREINSTALL
  Push $0
  Call HydraFindSandboxie
  Pop $0
  ${If} $0 == 0
    DetailPrint "正在使用安装程序的管理员权限配置 Sandboxie-Plus 驱动…"
    InitPluginsDir
    File "/oname=$PLUGINSDIR\Sandboxie-Plus-Setup.exe" "${HYDRA_SANDBOXIE_SETUP}"
    ClearErrors
    ; A SYSTEM service must live in an administrator-controlled directory.
    ; For custom Hydra locations use the upstream protected default.
    StrCpy $0 ""
    ${If} $INSTDIR == "$PROGRAMFILES64\Claude-Hydra"
      StrCpy $0 '/DIR="$INSTDIR\Sandboxie-Plus"'
    ${EndIf}
    ExecWait '"$PLUGINSDIR\Sandboxie-Plus-Setup.exe" /ALLUSERS $0 /MERGETASKS=!DesktopIcon /NOICONS /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /RESTARTEXITCODE=3010' $0
    ${If} ${Errors}
      StrCpy $0 "无法启动"
      Goto hydra_setup_failed
    ${EndIf}
    ${If} $0 == 3010
      SetRebootFlag true
    ${ElseIf} $0 != 0
      Goto hydra_setup_failed
    ${EndIf}
    Call HydraFindSandboxie
    Pop $0
    ${If} $0 == 0
      StrCpy $0 "未检测到沙箱组件"
      hydra_setup_failed:
      MessageBox MB_OK|MB_ICONSTOP "Sandboxie-Plus 驱动安装失败（$0）。请检查系统安装限制后重新运行 Claude Hydra 安装程序。" /SD IDOK
      SetErrorLevel 1
      Abort
    ${EndIf}
  ${EndIf}
  Pop $0
!macroend
