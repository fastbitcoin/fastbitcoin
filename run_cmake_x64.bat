setlocal
call ".\setenv_x64.bat"
cd %~dp0
cd ..
cd ..
cmake-gui -G "Visual Studio 12 Win64"
