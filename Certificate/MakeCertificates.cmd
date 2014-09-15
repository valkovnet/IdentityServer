@echo off

if not exist "%~dp0vcvars64.cmd" goto exit
call "%~dp0vcvars64.cmd"

makecert -r -n "CN=*.identity.com" -cy authority -b 01/01/2000 -e 01/01/2099 -a sha1 -sr localMachine -sky Exchange -sp "Microsoft RSA SChannel Cryptographic Provider" -sy 12 -sv identity.com.pvk identity.com.cer

cert2spc identity.com.cer identity.com.spc

pvk2pfx -pvk identity.com.pvk -spc identity.com.cer -pfx identity.com.pfx -pi "qwerty"

:exit