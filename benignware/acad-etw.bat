@echo off

REM This batch file registers the ETW event manifest or runs the product with some basic logging on.
REM USAGE:
REM    Run acad-etw.bat /register to register the event manifest

REM    Run acad-etw.bat without any parameters to collect some basic events from AutoCAD and the system

REM ONLY VISTA AND LATER ARE SUPPORTED
if not exist "%SystemRoot%\system32\wevtutil.exe" goto unsupported

setlocal

rem Extract the exedir from the full path to this batch file. If you copy this batch file somewhere else
rem then you must update this.
set EXEDIR=%~dp0
if /I "%1"=="/register" (
    rem copy acpal.dll to the ALLUSERSPROFILE folder. Hopefully, ALLUSERSPROFILE is a 'real' path. 
    rem This path must be accessible globally by the LOCAL_SERVICE account. It cannot be a subst drive.
    rem This dll contains resource strings that acad-etw.man references. The OS must have this available.

    pushd %EXEDIR%
    echo Copying message resource dll
    copy /y acpal.dll "%ALLUSERSPROFILE%\acad-etw.dll" >nul
    copy /y AcIPC_2_x64.dll "%ALLUSERSPROFILE%\acipc-etw.dll" >nul
    rem register event manifest
    echo Registering event manifest

    wevtutil um acad-etw.man
    wevtutil im acad-etw.man

    wevtutil um acipc-etw.man
    wevtutil im acipc-etw.man

    if errorlevel 1 goto error

    popd
    rem Are we just registering? Exit now.
    goto :eof
)

rem Otherwise, turn on event logging code

rem Turn on event logging
rem The GUID below is the Autodesk-AutoCAD provider. Please see acad-etw.man for details.
logman create trace acad -p {F28FCF55-106E-43C7-8BF5-A36FC1D7F705} -o "%ALLUSERSPROFILE%\acad.etl" -ets
logman create trace "NT Kernel Logger" -p "Windows Kernel Trace" (process,thread,img,disk,file,hf,profile) -bs 1024 -o "%ALLUSERSPROFILE%\base.etl" -ets

if not "%ETW_PRODNAME%" == "" (
	rem Run product using the ETW_PRODNAME
	"%EXEDIR%%ETW_PRODNAME%"
) else (
	rem Run product using the old style PRODNAME EXE
	"%EXEDIR%acad.exe"
)

logman stop acad -ets
logman stop "NT Kernel Logger" -ets

echo The traces you have just captured may contain personally identifiable information, including but not necessarily 
echo limited to paths to files accessed, paths to registry accessed and process names. Exact information depends on the
echo events that were logged. Please be aware of this when sharing out this trace with other people.
echo The files were saved to
echo "%ALLUSERSPROFILE%\acad.etl"
echo "%ALLUSERSPROFILE%\base.etl"
goto :eof

:unsupported
echo Only Windows Vista and later are supported.
goto :eof

:error
echo An error has occured.
goto :eof