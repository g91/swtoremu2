using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SWTORParser.Classes
{
    class Utils
    {
    }

    public static class Extensions
    {
        public static IEnumerable<string> SplitIntoChunks(this string text, int chunkSize)
        {
            int offset = 0;
            while (offset < text.Length)
            {
                int size = Math.Min(chunkSize, text.Length - offset);
                yield return text.Substring(offset, size);
                offset += size;
            }
        }

        public static string ToHEX(this byte[] inBuff)
        {
            return InternalToHEX(inBuff, inBuff.Length);
        }

        public static string ToHEX(this byte[] inBuff, int pLength)
        {
            return InternalToHEX(inBuff, pLength);
        }

        private static string InternalToHEX(byte[] inBuff, int pLength)
        {
            if (pLength < 1 || inBuff.Length < 1) return "";

            List<string> hexSplit = BitConverter.ToString(inBuff, 0, pLength)
                                                .Replace('-', ' ')
                                                .Trim()
                                                .SplitIntoChunks(18 * 3)
                                                .ToList();

            List<string> hexText = new List<string>();
            int h = 0;
            int j = 0;
            for (int i = 0; i < pLength; i++)
            {
                if (h == 0) hexText.Add("| ");
                h++;
                if (inBuff[i] > 31 && inBuff[i] < 127)
                    hexText[j] += (char)inBuff[i];
                else
                    hexText[j] += '.';

                if (h == 18)
                {
                    h = 0;
                    j++;
                }
            }

            for (int i = 0; i < hexSplit.Count; i++)
            {
                int tLength = hexSplit[i].Split(' ').Length;
                if (tLength < 19)
                {
                    for (int d = 0; d < 19 - tLength; d++)
                    {
                        if (d > 16 - tLength)
                            hexSplit[i] += "  ";
                        else
                            hexSplit[i] += "   ";
                    }
                }
            }

            var sb = new StringBuilder();

            for (int i = 0; i < hexSplit.Count; i++)
                sb.AppendLine("   " + hexSplit[i] + hexText[i]);

            return sb.ToString();
        }
    }
}
