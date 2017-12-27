@echo off
set FBTC_ROOT=D:\blockchain_project\fbtc\
echo Using %FBTC_ROOT% as FBTC root directory

set OPENSSL_ROOT=%FBTC_ROOT%\OpenSSL.x64
set OPENSSL_ROOT_DIR=%OPENSSL_ROOT%
set OPENSSL_INCLUDE_DIR=%OPENSSL_ROOT%\include
set DBROOTDIR=%FBTC_ROOT%\BerkeleyDB.x64
set QTDIR=%FBTC_ROOT%\QT.x64
set ICUROOT=%FBTC_ROOT%\ICU.x64
set BOOST_ROOT=%FBTC_ROOT%\boost_1.55.x64
set TCL_ROOT=%FBTC_ROOT%\tcl.x64
set NPM_INSTALL_PREFIX=%FBTC_ROOT%\npm

set PATH=%NPM_INSTALL_PREFIX%;"%APPDATA%"\npm;%QTDIR%\bin;%ICUROOT%\bin;%ICUROOT%\lib;%FBTC_ROOT%\bin;%TCL_ROOT%\bin;%FBTC_ROOT%\Cmake\bin;%BOOST_ROOT%\stage\lib;%PATH%
set CMAKE_PREFIX_PATH=%QTDIR%
set QT_QPA_PLATFORM_PLUGIN_PATH=%QTDIR%\plugins\platforms

echo Setting up VS2013 environment...
call "%VS120COMNTOOLS%\..\..\VC\vcvarsall.bat" x86_amd64
