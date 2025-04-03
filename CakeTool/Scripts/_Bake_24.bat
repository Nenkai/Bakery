@echo off

if ["%~1"]==[""] (
    echo No file provided. Drag drop a folder to this batch script.
    goto end
)

echo Packing for 9.2.
	  
CakeTool.exe pack -i %1 -v 9.3

:end
pause