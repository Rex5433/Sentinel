Option Explicit
Dim shell, files, folder, entry, executable, command, shortcut
Set shell = CreateObject("WScript.Shell")
Set files = CreateObject("Scripting.FileSystemObject")
folder = files.GetParentFolderName(WScript.ScriptFullName)
entry = folder & "\scripts\desktop.pyw"
shell.CurrentDirectory = folder

' Regenerate this local shortcut after moving or cloning the folder.
On Error Resume Next
Set shortcut = shell.CreateShortcut(folder & "\Sentinel V5.5.lnk")
shortcut.TargetPath = shell.ExpandEnvironmentStrings("%SystemRoot%\System32\wscript.exe")
shortcut.Arguments = """" & WScript.ScriptFullName & """"
shortcut.WorkingDirectory = folder
shortcut.IconLocation = shell.ExpandEnvironmentStrings("%SystemRoot%\System32\shell32.dll,13")
shortcut.Description = "Open Sentinel V5.5 and its local start/stop controls"
shortcut.Save
Err.Clear

executable = folder & "\.venv\Scripts\pythonw.exe"
If files.FileExists(executable) Then
    command = """" & executable & """ """ & entry & """"
Else
    command = "pyw.exe -3 """ & entry & """"
End If
shell.Run command, 0, False
If Err.Number <> 0 Then
    Err.Clear
    shell.Run "pythonw.exe """ & entry & """", 0, False
    If Err.Number <> 0 Then
        MsgBox "Install Python 3.11 or newer with the Python launcher and Tcl/Tk, then try again. Start Sentinel.bat is the terminal fallback.", 48, "Sentinel setup"
    End If
End If
