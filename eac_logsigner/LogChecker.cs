// SPDX-FileCopyrightText: Copyright 2022 TautCony
// SPDX-License-Identifier: GPL-3.0-or-later

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace eac_logsigner;

public static class LogChecker
{
    private static readonly Regex EacVersionRegex = new("Exact Audio Copy V(?<version>[\\d\\.]+)( (?:pre)?beta (?<beta>\\d+))? from [^\r\n]+");
        
    private static string compute_checksum(string inputString)
    {
        inputString = inputString.Replace("\n", "").Replace("\r", "");
        var utf16Array = Encoding.Unicode.GetBytes(inputString);
        var key = Convert.FromHexString("9378716cf13e4265ae55338e940b376184da389e50647726b35f6f341ee3efd9");
        var cipher = new Rijndael(key, 256 / 8);
        var signature = Convert.FromHexString("0000000000000000000000000000000000000000000000000000000000000000");
        for (var i = 0; i < utf16Array.Length; i += 32)
        {
            var plaintextBlock = new byte[32];
            var length = Math.Min(utf16Array.Length - i, 32);
            Array.Copy(utf16Array, i, plaintextBlock, 0, length);
            for (var j = 0; j < 32; ++j)
            {
                plaintextBlock[j] ^= signature[j];
            }
            signature = cipher.encrypt(plaintextBlock);
        }
        return Convert.ToHexString(signature);
    }

    private static IEnumerable<(string, string, string)> extract_infos(string text)
    {
        return Regex.Split(text, new string('-', 60)).Select(extract_info);
    }

    private static (string unsigned_text, string version, string old_signature) extract_info(string text)
    {
        var version = "";
        var ret = EacVersionRegex.Match(text);
        if (ret.Success)
        {
            var mainVersion = ret.Groups["version"];
            var betaVersion = ret.Groups["beta"];
            version = mainVersion + "." + (betaVersion.Success ? betaVersion.Value : "999");
        }

        var signatures = Regex.Matches(text, "\r\n\r\n====.* ([0-9A-F]{64}) ====(?:\r\n)?");
        if (signatures.Count == 0)
            return (text, version, "");
        // get last signature
        var signature = signatures[^1].Groups[1].Value.Trim();
        var fullLine = signatures[^1].Value;

        var unsignedText = text.Replace(fullLine, "");
        return (unsignedText, version, signature);

    }

    public static List<(string data, string version, string oldSignature, string actualSignature)> eac_verify(string text)
    {
        var ret = new List<(string, string, string, string)>();

        foreach (var (unsignedText, version, oldSignature) in extract_infos(text))
        {
            ret.Add((unsignedText, version, oldSignature, compute_checksum(unsignedText)));
        }
        return ret;
    }
}