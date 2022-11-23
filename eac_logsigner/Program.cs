// SPDX-FileCopyrightText: Copyright 2022 TautCony
// SPDX-License-Identifier: GPL-3.0-or-later

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using CommandLine;

namespace eac_logsigner;

class Program
{
    private static readonly string CHECKSUM_MIN_VERSION = "1.0.1";
        
    [Verb("verify", HelpText = "Verify a log")]
    class VerifyOptions {
        [Value(1, MetaName = "files", Required = true, HelpText = "input log file(s)")]
        public IEnumerable<FileInfo>? Files { get; set; }
    }

    [Verb("sign", HelpText = "Sign or fix an existing log")]
    class SignOptions {
        [Option('f', "force", Default = false, HelpText = "orces signing even if EAC version is too old")]
        public bool Force { get; set; }

        [Value(1, MetaName = "input_file", Required = true, HelpText = "input log file")]
        public FileInfo? InputFile { get; set; }
            
        [Value(2, MetaName = "output_file", Required = true, HelpText = "output log file")]
        public FileInfo? OutputFile { get; set; }
    }
        
    public static void Main(string[] args)
    {
        Parser.Default.ParseArguments<VerifyOptions, SignOptions>(args)
              .MapResult(
                  (VerifyOptions opts) => RunVerify(opts),
                  (SignOptions opts) => RunSign(opts),
                  errs => 1);
            
        static int RunVerify(VerifyOptions opts)
        {
            var files = opts.Files?.ToList();
            if (files == null)
            {
                Console.WriteLine("No files specified");
                return 1;
            }

            var maxLength = files.Select(file => file.Name.Length).Max();
                
            foreach (var file in files)
            {
                var prefix = file.Name.PadRight(maxLength + 2, ' ') + ": ";
                try
                {
                    using var reader = new StreamReader(file.FullName, Encoding.Unicode, detectEncodingFromByteOrderMarks: true);
                    var (data, version, oldSignature, actualSignature) = LogChecker.eac_verify(reader.ReadToEnd())[0];
                    if (string.IsNullOrEmpty(version))
                    {
                        Console.WriteLine(prefix + "Not a log file");
                    }
                    else if (string.IsNullOrEmpty(oldSignature))
                    {
                        Console.WriteLine(prefix + "Log file without a signature");
                    }
                    else if (oldSignature != actualSignature)
                    {
                        Console.WriteLine(prefix + "Malformed");
                    }
                    else if (new Version(version) < new Version(CHECKSUM_MIN_VERSION))
                    {
                        Console.WriteLine(prefix + "Forged");
                    }
                    else
                    {
                        Console.WriteLine(prefix + "OK");
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine(prefix + e.Message);
                }
            }

            return 0;
        }
            
        static int RunSign(SignOptions opts)
        {
            var inputFile = opts.InputFile;
            var outputFile = opts.OutputFile;
            if (inputFile == null || outputFile == null)
            {
                Console.WriteLine("No files specified");
                return 1;
            }

            if (!inputFile.Exists)
            {
                Console.WriteLine($"File {inputFile} does not exist");
                return 1;
            }
                
            using var reader = new StreamReader(inputFile.FullName, Encoding.Unicode, detectEncodingFromByteOrderMarks: true);
            var (data, version, oldSignature, actualSignature) = LogChecker.eac_verify(reader.ReadToEnd())[0];
            if (!opts.Force && (string.IsNullOrEmpty(version) || new Version(version) < new Version(CHECKSUM_MIN_VERSION)))
            {
                Console.WriteLine("EAC version is too old");
                return 1;
            }

            data += $"\r\n\r\n==== Log checksum {actualSignature} ====\r\n";
                
            using var writer = new StreamWriter(outputFile.FullName, false, Encoding.Unicode);
            writer.Write(data);
            writer.Flush();

            return 0;
        }
    }
}