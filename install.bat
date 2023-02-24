echo off
::color 02

call npm i
call node encryption.js
call npm run electron-builder --win
::call npm start