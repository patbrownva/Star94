@echo off
:CONVERT
if "%~1"=="" goto :EOF

set DAT=OFF
echo %~n1
set /p CART=Cart# 
if "%CART%"=="" goto :XML
set /p CUT=Cut# 
if "%CUT%"=="" goto :XML

rem for /f %%L in ('python "%~dp0\wavfilelength.py" "D:\Library\%~n1.wav"') do set rem LENGTH=%%L

set OUTXML="%~dpn1.xml"
echo ^<XMLDAT^> >%OUTXML%
echo     ^<Version^>1^</Version^> >>%OUTXML%
echo     ^<Cart^>%CART%^</Cart^> >>%OUTXML%
echo     ^<Cut^>%CUT%^</Cut^> >>%OUTXML%
echo     ^<Type^>1^</Type^> >>%OUTXML%
echo     ^<Category^>Spots^</Category^> >>%OUTXML%
echo     ^<Title^>%~n1^</Title^> >>%OUTXML%
echo     ^<Start_Time^>01/01/2001 00:00:00^</Start_Time^> >>%OUTXML%
echo     ^<End_Time^>01/01/2099 00:00:00^</End_Time^> >>%OUTXML%
echo     ^<Archive_Time^>01/01/2099 00:00:00^</Archive_Time^> >>%OUTXML%
echo     ^<Modified_Time^>%DATE:~4% %TIME:~,8%^</Modified_Time^> >>%OUTXML%
echo     ^<File_Name^>%~n1.wav^</File_Name^> >>%OUTXML%
echo     ^<Length^>0^</Length^> >>%OUTXML%
echo     ^<Intro_3^>0^</Intro_3^> >>%OUTXML%
echo     ^<Outro^>0^</Outro^> >>%OUTXML%
echo     ^<Intro_Start^>0^</Intro_Start^> >>%OUTXML%
echo     ^<Outro_Start^>0^</Outro_Start^> >>%OUTXML%
echo     ^<Cross_Fade^>0^</Cross_Fade^> >>%OUTXML%
echo     ^<Comments^>^</Comments^> >>%OUTXML%
echo     ^<Erase_Time^>01/01/2099 00:00:10^</Erase_Time^> >>%OUTXML%
echo     ^<Replay^>0^</Replay^> >>%OUTXML%
echo     ^<User_Define^>^</User_Define^> >>%OUTXML%
echo     ^<Fade^>0^</Fade^> >>%OUTXML%
echo     ^<Fade_Up_Start^>-1^</Fade_Up_Start^> >>%OUTXML%
echo     ^<Fade_Up_Length^>-1^</Fade_Up_Length^> >>%OUTXML%
echo     ^<Fade_Down_Start^>-1^</Fade_Down_Start^> >>%OUTXML%
echo     ^<Fade_Down_Length^>-1^</Fade_Down_Length^> >>%OUTXML%
echo     ^<Intro_1^>0^</Intro_1^> >>%OUTXML%
echo     ^<Intro_2^>0^</Intro_2^> >>%OUTXML%
echo     ^<AudioNotes^>^</AudioNotes^> >>%OUTXML%
echo     ^<ProductionType^>0^</ProductionType^> >>%OUTXML%
echo     ^<ISCI_Code^>^</ISCI_Code^> >>%OUTXML%
echo     ^<Brand^>^</Brand^> >>%OUTXML%
echo     ^<Keywords^>^</Keywords^> >>%OUTXML%
echo     ^<Out_Cue^>^</Out_Cue^> >>%OUTXML%
echo     ^<MediaStartSpotId^>0^</MediaStartSpotId^> >>%OUTXML%
echo     ^<MediaStartCartId^>0^</MediaStartCartId^> >>%OUTXML%
echo ^</XMLDAT^> >>%OUTXML%
set DAT=ON
:XML

"C:\Program Files (x86)\RCS\AFC4\PsiAfc.exe" /P=ON /B=70 /E=70 /T=%DAT% /F=MPEG /L=50 /I=%~1 /N=D:\Library\%~n1.wav

shift
goto CONVERT

