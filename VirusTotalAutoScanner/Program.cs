using System;
using System.IO;
using NLog;
using NLog.Interface;
using VirusTotalNET;
using VirusTotalNET.Objects;

namespace VirusTotalAutoScanner
{
    public static class Program
    {
        private static ILogger _logger;

        static void Main()
        {
            _logger = new LoggerAdapter(LogManager.GetCurrentClassLogger());

            try
            {
            var vt = new VirusTotal("e49c455020f74072f577ad2f614800b9a8cce2c77c6e927e17f141100a2d9091");

            //var fileInfo2 = new FileInfo(@"C:\Users\Paul\Documents\Grindr db analysis.txt");

            //var report2 = vt.GetFileReport(fileInfo2);

            const string watchPath = @"C:\Users\Paul\Downloads\";

            var fsw = new FileSystemWatcher(watchPath,"*.*") {IncludeSubdirectories = true};

            //fsw.BeginInit();
            //fsw.NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.CreationTime;

                while (true)
                {
                    var fswResult = fsw.WaitForChanged(WatcherChangeTypes.Created | WatcherChangeTypes.Changed);

                    try
                    {
                        _logger.Debug("Change Type: {0}. FileName: {1}", fswResult.ChangeType, fswResult.Name);

                        var fullPath = watchPath + fswResult.Name;

                        _logger.Trace("fullPath: {0}", fullPath);

                        var fileInfo = new FileInfo(fullPath);

                        if (fileInfo.Length == 0)
                        {
                            _logger.Debug("File is zero bytes");
                            continue;
                        }

                        var report = vt.GetFileReport(fileInfo);

                        _logger.Info("ResponseCode: {0}", report.ResponseCode);

                        if (report.ResponseCode == ReportResponseCode.Present)
                            _logger.Info("File has {0} positives", report.Positives);

                        //if (report.ResponseCode == ReportResponseCode.NotPresent)
                        //{
                        //    var scanResult = vt.ScanFile(fileInfo);
                        //    _logger.Debug("Scan result: {0}", scanResult.ResponseCode);


                        //}
                    }
                    catch (Exception ex)
                    {
                        _logger.Error("File change handler error",ex);
                    }

                }
            }
            catch (Exception ex)
            {
                _logger.Fatal("Program crashed",ex);
                throw;
            }

        }
    }
}
