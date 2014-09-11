﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using System.Timers;
using NLog;
using NLog.Interface;
using VirusTotalNET;
using VirusTotalNET.Objects;
using Timer = System.Timers.Timer;

namespace VirusTotalAutoScanner
{
    public static class Program
    {
        private const string ApiKey = "e49c455020f74072f577ad2f614800b9a8cce2c77c6e927e17f141100a2d9091";
        private static ILogger _logger;

        private static List<FileInfoAndScanResult> _sessionScan;
        private static List<string> _procssed = new List<string>(); 

        public static void Main()
        {
            _logger = new LoggerAdapter(LogManager.GetCurrentClassLogger());

            try
            {
                _sessionScan = new List<FileInfoAndScanResult>();
                var timer = new Timer {AutoReset = true,Interval = 60000};

                const string watchPath = @"C:\Users\Paul\Downloads\";

                var fsw = new FileSystemWatcher(watchPath,"*.*") {IncludeSubdirectories = true,EnableRaisingEvents = true};

                fsw.Created += FswOnCreatedOrChanged;
                fsw.Changed += FswOnCreatedOrChanged;

                timer.Elapsed += CheckScans;
                timer.Start();

                Thread.Sleep(Timeout.Infinite);
            }
            catch (Exception ex)
            {
                _logger.Fatal("Program crashed",ex);
                throw;
            }

        }

        private static void FswOnCreatedOrChanged(object sender, FileSystemEventArgs fileSystemEventArgs)
        {
            _logger.Trace("FswOnCreatedOrChanged");

            try
            {
                _logger.Debug("Change Type: {0}. FileName: {1}", fileSystemEventArgs.ChangeType, fileSystemEventArgs.Name);

                var fullPath = fileSystemEventArgs.FullPath;

                _logger.Trace("fullPath: {0}", fullPath);

                if (_procssed.Contains(fullPath))
                {
                    _logger.Debug("File already processed");
                    return;
                }

                var fileInfo = new FileInfo(fullPath);

                if (fileInfo.Length == 0)
                {
                    _logger.Debug("File is zero bytes");
                    return;
                }

                if (IsAlreadyDenyRead(fullPath))
                {
                    _logger.Trace("File already has permission denied");
                    return;
                }

                var vt = new VirusTotal(ApiKey);

                var report = vt.GetFileReport(fileInfo);

                _logger.Info("ResponseCode: {0}", report.ResponseCode);

                if (report.ResponseCode == ReportResponseCode.Present)
                {
                    _logger.Log(report.Positives == 0 ? LogLevel.Info : LogLevel.Warn, "File has {0} positives", report.Positives);
                }
                    

                if (report.ResponseCode == ReportResponseCode.Present && report.Positives > 0)
                    RemoveExecutePermission(fullPath);

                if (report.ResponseCode == ReportResponseCode.NotPresent)
                {
                    var scanResult = vt.ScanFile(fileInfo);
                    _logger.Debug("Scan result: {0}", scanResult.ResponseCode);
                    lock (_sessionScan)
                        _sessionScan.Add(new FileInfoAndScanResult { FilePath = fileInfo.FullName, ScanResult = scanResult });
                }

                _procssed.Add(fullPath);
            }
            catch (Exception ex)
            {
                _logger.Error("File change handler error", ex);
            }
        }

        private static void CheckScans(object param, ElapsedEventArgs e)
        {
            try
            {
                _logger.Debug("Doing CheckScans");

                if (_sessionScan == null)
                {
                    _logger.Trace("SessionScan is null");
                    return;
                }

                if (_sessionScan.Count == 0)
                {
                    _logger.Trace("SessionScan is empty");
                    return;
                }

                var vt = new VirusTotal(ApiKey);

                lock (_sessionScan)
                {

                    for (var i = 0; i <= _sessionScan.Count; i++)
                    {
                        var scanResult = _sessionScan[i].ScanResult;
                        var filePath = _sessionScan[i].FilePath;

                        _logger.Info("Doing check for \"{0}\"", filePath);

                        var report = vt.GetFileReport(scanResult.Resource);

                        _logger.Info("ResponseCode: {0}", report.ResponseCode);

                        if (report.ResponseCode == ReportResponseCode.Present)
                        {
                            _logger.Info("File has {0} positives", report.Positives);
                            if (report.Positives > 0)
                                RemoveExecutePermission(filePath);
                             _sessionScan.Remove(_sessionScan[i]);
                        }
                        else
                        {
                            i++;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.Fatal("CheckScans thread crashed",ex);
                throw;
            }
        }

        private static void RemoveExecutePermission(string filePath)
        {
            var fileInfo = new FileInfo(filePath);

            var permissions = fileInfo.GetAccessControl(AccessControlSections.Access);

            var rule = new FileSystemAccessRule("Everyone",FileSystemRights.ReadData | FileSystemRights.ExecuteFile , AccessControlType.Deny);

            permissions.AddAccessRule(rule);

            fileInfo.SetAccessControl(permissions);

            _logger.Info("Removed execute permission for \"{0}\"", filePath);
        }

        private static bool IsAlreadyDenyRead(string filePath)
        {
            var permissions = new FileSecurity(filePath, AccessControlSections.Access);

            var rules = permissions.GetAccessRules(true, false, typeof (SecurityIdentifier));

            for (var i = 0; i < rules.Count; i++)
            {
                var rule = (FileSystemAccessRule)rules[i];

                if (rule != null &&
                    rule.IdentityReference.Value == Everybody && rule.AccessControlType == AccessControlType.Deny &&
                    rule.FileSystemRights == (FileSystemRights.ReadData | FileSystemRights.ExecuteFile))
                    return true;
            }
                return false;
        }

        private static string _everybody;

        private static string Everybody
        {
            get { return _everybody ?? (_everybody = new SecurityIdentifier(WellKnownSidType.WorldSid, null).Value); }
        }

    }

    public class FileInfoAndScanResult
    {
        public ScanResult ScanResult;
        public string FilePath;
    }
}
