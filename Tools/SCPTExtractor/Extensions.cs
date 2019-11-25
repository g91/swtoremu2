using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows;
using System.Windows.Interop;
using System.IO;

namespace SCPTExtractor    
{
    public static class Extensions
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct MARGINS
        {
            public int cxLeftWidth;      // width of left border that retains its size
            public int cxRightWidth;     // width of right border that retains its size
            public int cyTopHeight;      // height of top border that retains its size
            public int cyBottomHeight;   // height of bottom border that retains its size
        };

        [DllImport("DwmApi.dll")]
        private static extern int DwmExtendFrameIntoClientArea(IntPtr hwnd, ref MARGINS pMarInset);

        private const int GWL_STYLE = -16;
        private const int GWL_EXSTYLE = -20;
        private const int WS_EX_DLGMODALFRAME = 0x00000001;

        private const int WS_SYSMENU = 0x80000;
        [DllImport("user32.dll", SetLastError = true)]
        private static extern int GetWindowLong(IntPtr hWnd, int nIndex);
        [DllImport("user32.dll")]
        private static extern int SetWindowLong(IntPtr hWnd, int nIndex, int dwNewLong);

        public static void HideCloseButton(this Window Win)
        {
            // Get the window handle
            IntPtr mainWindowPtr = new WindowInteropHelper(Win).Handle;

            // Hide the close button
            SetWindowLong(mainWindowPtr, GWL_STYLE, GetWindowLong(mainWindowPtr, GWL_STYLE) & ~WS_SYSMENU);
        }

        public static void HideIcon(this Window Win)
        {
            // Get the window handle
            IntPtr mainWindowPtr = new WindowInteropHelper(Win).Handle;

            // Hide Icon
            int extendedStyle = GetWindowLong(mainWindowPtr, GWL_EXSTYLE);
            SetWindowLong(mainWindowPtr, GWL_EXSTYLE, extendedStyle | WS_EX_DLGMODALFRAME);
        }

        public static void ExtendGlassHook(this Window Win)
        {
            Win.Loaded += delegate(object sender, RoutedEventArgs e)
            {
                try
                {
                    // Get the window handle
                    IntPtr mainWindowPtr = new WindowInteropHelper(Win).Handle;
                    HwndSource mainWindowSrc = HwndSource.FromHwnd(mainWindowPtr);

                    // Make everything glass-y
                    mainWindowSrc.CompositionTarget.BackgroundColor = System.Windows.Media.Colors.Transparent;

                    // Extend to the whole window
                    MARGINS margins = new MARGINS();
                    margins.cxLeftWidth = -1;
                    margins.cxRightWidth = 0;
                    margins.cyBottomHeight = 0;
                    margins.cyTopHeight = 0;

                    int hr = DwmExtendFrameIntoClientArea(mainWindowSrc.Handle, ref margins);
                    if (hr >= 0)
                        Win.Background = System.Windows.Media.Brushes.Transparent;
                }
                catch (DllNotFoundException) // We are running XP - make everything white
                {
                    Application.Current.MainWindow.Background = System.Windows.Media.Brushes.White;
                }
            };
        }

        public static void ExtendGlass(this Window Win)
        {
            try
            {
                // Get the window handle
                IntPtr mainWindowPtr = new WindowInteropHelper(Win).Handle;
                HwndSource mainWindowSrc = HwndSource.FromHwnd(mainWindowPtr);

                // Make everything glass-y
                mainWindowSrc.CompositionTarget.BackgroundColor = System.Windows.Media.Colors.Transparent;

                // Extend to the whole window
                MARGINS margins = new MARGINS();
                margins.cxLeftWidth = -1;
                margins.cxRightWidth = 0;
                margins.cyBottomHeight = 0;
                margins.cyTopHeight = 0;

                int hr = DwmExtendFrameIntoClientArea(mainWindowSrc.Handle, ref margins);
                if (hr >= 0)
                    Win.Background = System.Windows.Media.Brushes.Transparent;
            }
            catch (DllNotFoundException) // We are running XP - make everything white
            {
                Application.Current.MainWindow.Background = System.Windows.Media.Brushes.White;
            }
        }

        public static string GetHEX(this byte[] value)
        {
            string outStr = "";
            foreach (byte nByte in value)
                outStr += String.Format("{0:X2}", nByte);
            return outStr;
        }

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

        public static int ReadInt24(this BinaryReader Reader)
        {
            byte[] bBuff = Reader.ReadBytes(3);
            return (bBuff[0] << 16) + (bBuff[1] << 8) + (bBuff[2]);
        }

        public static long ReadVarNumeric(this BinaryReader Reader)
        {
            long value = 0L;
            byte num1 = Reader.ReadByte();
            if ((int)num1 < 192)
                value = (long)num1;
            else if ((int)(byte)((uint)num1 + 56U) > 7)
            {
                if ((int)(byte)((uint)num1 + 64U) > 7)
                {
                    if ((int)num1 != 208)
                        throw new Exception("Invalid token in stream");
                    value = long.MinValue;
                }
                byte num2 = (byte)((uint)num1 - 191U);
                ulong num3 = Reader.ReadPacked((int)num2);
                value = -(long)num3;
            }
            else
            {
                byte num2 = (byte)((uint)num1 - 199U);
                ulong num3 = Reader.ReadPacked((int)num2);
                value = (long)num3;
            }
            return value;
        }

        public static ulong ReadPacked(this BinaryReader Reader, int length)
        {
            ulong value = 0UL;
            if (length > 8)
                return value;
            byte[] numArray = Reader.ReadBytes((int)((uint)length));
            for (byte index = (byte)0x00; (int)index < length; ++index)
                value = value << 8 | (ulong)numArray[(int)index];
            return value;
        }
    }
}
