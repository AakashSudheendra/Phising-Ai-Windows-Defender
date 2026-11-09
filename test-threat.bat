@echo off
title PhishGuard AI - Link Click Interception Test
echo ========================================================
echo  Testing PhishGuard Real-Time Navigation Interception
echo  Simulating user clicking a phishing link in WhatsApp...
echo  Target: http://paypa1-secure-login.xyz/verify
echo ========================================================
cd /d "%~dp0apps\desktop"
npx electron . "http://paypa1-secure-login.xyz/verify"
