; RustMap NSIS installer hooks
; Adds/removes the install directory to/from the user PATH so that
; `rustmap` (CLI) is available from any terminal after installation.

!macro NSIS_HOOK_POSTINSTALL
  ; Read the current user-level PATH
  ReadRegStr $0 HKCU "Environment" "Path"

  ; Check if $INSTDIR is already in PATH (avoid duplicates)
  Push $0
  Push $INSTDIR
  Call PostInstall_StrContains
  Pop $1
  StrCmp $1 "" 0 postinstall_skip

  ; Append $INSTDIR to PATH
  StrLen $2 $0
  IntCmp $2 0 postinstall_empty
    StrCpy $0 "$0;$INSTDIR"
    Goto postinstall_write
  postinstall_empty:
    StrCpy $0 "$INSTDIR"
  postinstall_write:
  WriteRegExpandStr HKCU "Environment" "Path" $0
  ; Notify running applications of the environment change
  SendMessage ${HWND_BROADCAST} ${WM_SETTINGCHANGE} 0 "STR:Environment" /TIMEOUT=5000

  postinstall_skip:
!macroend

; Helper: check if $R1 (needle) is a substring of $R0 (haystack)
; Returns needle in stack if found, empty string if not
Function PostInstall_StrContains
  Exch $R1 ; needle
  Exch
  Exch $R0 ; haystack
  Push $R2
  Push $R3
  Push $R4
  StrLen $R3 $R1
  StrLen $R4 $R0
  StrCpy $R2 0

  postinstall_loop:
    IntCmp $R2 $R4 postinstall_notfound postinstall_notfound
    StrCpy $R5 $R0 $R3 $R2
    StrCmp $R5 $R1 postinstall_found
    IntOp $R2 $R2 + 1
    Goto postinstall_loop

  postinstall_found:
    StrCpy $R0 $R1
    Goto postinstall_done

  postinstall_notfound:
    StrCpy $R0 ""

  postinstall_done:
  Pop $R4
  Pop $R3
  Pop $R2
  Pop $R1
  Exch $R0
FunctionEnd

!macro NSIS_HOOK_PREUNINSTALL
  ; Read the current user-level PATH
  ReadRegStr $0 HKCU "Environment" "Path"

  ; Remove $INSTDIR from PATH using a rebuild approach:
  ; Split on ";", skip entries matching $INSTDIR, rejoin
  Push $0
  Push $INSTDIR
  Call un.PreUninstall_RemoveFromPath
  Pop $0

  WriteRegExpandStr HKCU "Environment" "Path" $0
  ; Notify running applications of the environment change
  SendMessage ${HWND_BROADCAST} ${WM_SETTINGCHANGE} 0 "STR:Environment" /TIMEOUT=5000
!macroend

; Helper: remove a specific directory entry from a semicolon-delimited PATH string
; Stack: PATH_STRING, DIR_TO_REMOVE -> RESULT_STRING
Function un.PreUninstall_RemoveFromPath
  Exch $R1 ; directory to remove
  Exch
  Exch $R0 ; original PATH
  Push $R2 ; result
  Push $R3 ; current segment
  Push $R4 ; remaining
  Push $R5 ; char

  StrCpy $R2 "" ; result starts empty
  StrCpy $R4 $R0 ; remaining = original

  uninstall_split_loop:
    StrLen $R5 $R4
    IntCmp $R5 0 uninstall_split_done uninstall_split_done

    ; Find next semicolon
    Push $R4
    Push ";"
    Call un.PreUninstall_FindFirst
    Pop $R3 ; segment before semicolon
    Pop $R4 ; remainder after semicolon

    ; Compare segment with directory to remove (case-insensitive not needed, paths are consistent)
    StrCmp $R3 $R1 uninstall_skip_segment
    StrCmp $R3 "" uninstall_skip_segment

    ; Append to result
    StrLen $R5 $R2
    IntCmp $R5 0 uninstall_first_segment
      StrCpy $R2 "$R2;$R3"
      Goto uninstall_split_loop
    uninstall_first_segment:
      StrCpy $R2 $R3
      Goto uninstall_split_loop

  uninstall_skip_segment:
    Goto uninstall_split_loop

  uninstall_split_done:
  StrCpy $R0 $R2

  Pop $R5
  Pop $R4
  Pop $R3
  Pop $R2
  Pop $R1
  Exch $R0
FunctionEnd

; Helper: split string at first occurrence of delimiter
; Stack: STRING, DELIMITER -> BEFORE, AFTER
Function un.PreUninstall_FindFirst
  Exch $R1 ; delimiter
  Exch
  Exch $R0 ; string
  Push $R2 ; position
  Push $R3 ; length
  Push $R4 ; char
  Push $R5 ; delim length

  StrLen $R3 $R0
  StrLen $R5 $R1
  StrCpy $R2 0

  uninstall_find_loop:
    IntCmp $R2 $R3 uninstall_find_notfound uninstall_find_notfound
    StrCpy $R4 $R0 $R5 $R2
    StrCmp $R4 $R1 uninstall_find_found
    IntOp $R2 $R2 + 1
    Goto uninstall_find_loop

  uninstall_find_found:
    StrCpy $R4 $R0 $R2 ; before
    IntOp $R2 $R2 + $R5
    StrCpy $R0 $R0 "" $R2 ; after
    StrCpy $R1 $R4 ; before goes in R1
    Goto uninstall_find_done

  uninstall_find_notfound:
    StrCpy $R1 $R0 ; entire string is "before"
    StrCpy $R0 "" ; nothing "after"

  uninstall_find_done:
  Pop $R5
  Pop $R4
  Pop $R3
  Pop $R2
  Exch $R0 ; after
  Exch
  Exch $R1 ; before
FunctionEnd
