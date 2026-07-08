@echo off
chcp 65001 >nul
cd /d "%~dp0"

:: 检查 paramiko 是否已安装
python -c "import paramiko" 2>nul
if %errorlevel% neq 0 (
    echo [*] Installing paramiko...
    pip install paramiko
    if %errorlevel% neq 0 (
        echo [!] Failed to install paramiko. Check your Python/pip installation.
        pause
        exit /b 1
    )
)

:: 用 pythonw 启动则不显示命令行窗口，失败则回退到 python
start "" pythonw "%~dp0net_inspect_gui.py" 2>nul
if %errorlevel% neq 0 (
    start "" python "%~dp0net_inspect_gui.py"
)
