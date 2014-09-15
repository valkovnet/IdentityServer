@echo off

echo Removing certificates...
echo.

certutil -delstore My "localhost"

certutil -delstore My "identity.com"

echo.
echo Clean up finished!
echo.
