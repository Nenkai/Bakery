@echo off

if ["%~1"]==[""] (
    echo No file provided. Drag drop a cake file to this script.
    goto end
)
	  

%~dp0/CakeTool.exe unpack-cak -i %1

:end
pause