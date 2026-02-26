' Helper-VBS (wird von login.vbs per ExecuteGlobal referenziert)
Function GetFileContent(path)
    Dim fso
    Set fso = CreateObject("Scripting.FileSystemObject")
    GetFileContent = ""
End Function
' Ruft optional ein weiteres Skript auf
' WScript.Shell.Run "optional.vbs", 1, False
