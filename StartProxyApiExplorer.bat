@echo off
:: 设置控制台编码为UTF-8
chcp 65001 >nul

cls
echo.
echo ==========================================
echo         ProxyApiExplorer
echo        代理API探索器
echo ==========================================
echo.
echo Starting API exploration service...
echo 正在启动API探索服务...
echo.
echo Proxy: localhost:8888
echo 代理: localhost:8888
echo.
echo Config: ProxyApiExplorer_config.json  
echo 配置: ProxyApiExplorer_config.json
echo.
echo Press Ctrl+C to stop and generate reports
echo 按 Ctrl+C 停止并生成报告
echo ==========================================
echo.

:: 启动程序
ProxyApiExplorer.exe

echo.
echo ==========================================
echo API exploration stopped successfully!
echo API探索已成功停止！
echo.
echo Reports generated in: api_explorer_reports/
echo 报告已生成到: api_explorer_reports/
echo ==========================================
echo.
pause