using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Windows;
using Microsoft.Win32;
using MiscUtil.Conversion;
using SWTORParser.Classes;
using SWTORParser.Parsing;
using SWTORParser.Parsing.Handlers;

namespace SWTORParser.Forms
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public static String LastFolder;
        private readonly List<Packet> _packets = new List<Packet>();
        private String RemoteIP;

        public MainWindow()
        {
            InitializeComponent();

            /*var temp = new Byte[]
                           {
                               0x00, 0x00, 0x00, 0x00,
                               0x01, 0x4D, 0xCC, 0x1A, 0xC6, 0x88, 0xD5, 0x3E, 0xAA, 0xCF, 0x40, 0x00, 0x00, 0x03, 0x98, 0x6E, 0x86, 0x71, 0x00, 0x05, 0x07, 0x18,
                               0x29, 0x15, 0xCF, 0xE0, 0x00, 0x4E, 0x7B, 0x39, 0xFD, 0xC9, 0x8B, 0x8C, 0x4A, 0xBE, 0x41, 0xA5, 0xBD, 0xC1, 0x3D, 0xAF, 0xE5, 0x32,
                               0xC2, 0xC0, 0xCC, 0x1A, 0xC6, 0x88, 0xD5, 0x40, 0xAA, 0xCF, 0x40, 0x00, 0x00, 0x03, 0x98, 0x6E, 0x86, 0x71, 0x00, 0x05, 0x07, 0x18,
                               0x29, 0x15, 0xCF, 0xE0, 0x00, 0x4C, 0x7B, 0x39, 0xFC, 0x35, 0x61, 0xE1, 0xFA, 0xAA, 0x41, 0x85, 0xEB, 0x91, 0xBE, 0x6A, 0x5E, 0x28,
                               0xC2, 0xC0, 0xCC, 0x1A, 0xC6, 0x88, 0xD5, 0x42, 0xAA, 0xCF, 0x40, 0x00, 0x00, 0x03, 0x98, 0x6E, 0x86, 0x71, 0x00, 0x05, 0x07, 0x18,
                               0x29, 0x15, 0xCF, 0xE0, 0x00, 0x4D, 0x7B, 0x39, 0xFC, 0x37, 0xDC, 0x24, 0x97, 0xC4, 0x41, 0x0E, 0xBE, 0xB0, 0xBD, 0xE7, 0x7B, 0x27,
                               0xC2, 0xC0, 0xCC, 0x1A, 0xC6, 0x89, 0x67, 0xA3, 0x7A, 0xCF, 0xE0, 0x00, 0x99, 0xCA, 0x18, 0x16, 0x01, 0xBE, 0xCC, 0x1A, 0xC6, 0x88,
                               0xBE, 0x1E, 0x01, 0x02, 0x00, 0x00, 0x00, 0x41, 0xEC, 0xA7, 0x01, 0x00, 0x00, 0x00, 0x40, 0x0B, 0x56, 0xC0, 0x01, 0x00, 0x00, 0x00,
                               0x40, 0x05, 0x08, 0xC9, 0x01, 0xA2, 0x2A, 0xC9, 0x01, 0x87, 0x4D, 0x84, 0x75, 0xC2, 0xC8, 0x07, 0xDD, 0xC0, 0x53, 0x94, 0xFF, 0xC2,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 0xC1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x3F, 0xCD, 0xCC, 0xCC, 0x3D, 0x02, 0x01,
                               0xCC, 0x1A, 0xC6, 0x89, 0x67, 0xA5, 0xCC, 0x1A, 0xC6, 0x89, 0x67, 0xA7, 0xCC, 0x1A, 0xC6, 0x89, 0x67, 0xA8, 0xCC, 0x1A, 0xC6, 0x89,
                               0x67, 0xA9, 0xCF, 0x40, 0x00, 0x00, 0x0C, 0x5C, 0xCB, 0xAD, 0x0D, 0xCC, 0x1A, 0xC6
                           };

            var reader = new EndianBinaryReader(EndianBitConverter.Little, new MemoryStream(temp));
            Handlers.HandlerAreaAwarenessEntered(new Packet() { Reader = reader });*/
        }

        private void BrowseSniffClick(Object sender, RoutedEventArgs e)
        {
            var ofd = new OpenFileDialog
            {
                Filter = "PCap Files|*.pcap",
                InitialDirectory = LastFolder ?? Directory.GetCurrentDirectory()
            };

            ofd.FileOk += (o, args) => {
                pcapBox.Text = ofd.FileName;
                LastFolder = ofd.FileName.Substring(0, ofd.FileName.LastIndexOf('\\'));
            };
            ofd.ShowDialog();
        }

        private void BrowseKeyClick(object sender, RoutedEventArgs e)
        {
            var ofd = new OpenFileDialog
            {
                Filter = "Key Files|*.dat|All Files|*.*",
                InitialDirectory = LastFolder ?? Directory.GetCurrentDirectory()
            };

            ofd.FileOk += (o, args) =>
            {
                keyBox.Text = ofd.FileName;
                LastFolder = ofd.FileName.Substring(0, ofd.FileName.LastIndexOf('\\'));
            };
            ofd.ShowDialog();
        }

        private void ParseBtnClick(object sender, RoutedEventArgs e)
        {
            if (!File.Exists(pcapBox.Text))
            {
                MessageBox.Show("Missing PCap file!");
                return;
            }

            if (!File.Exists(keyBox.Text))
            {
                MessageBox.Show("Missing key file!");
                return;
            }
            _packets.Clear();
            RemoteIP = "";
            progressBar.Value = 0;

            var info = new ProcessStartInfo(String.Format("{0}\\PcapConv.exe", Directory.GetCurrentDirectory()),
                                            String.Format("\"{0}\" tmp_encrypted.dat {1}", pcapBox.Text, portBox.Text))
            {
                WorkingDirectory = String.Format(@"{0}\", Directory.GetCurrentDirectory()),
                WindowStyle = ProcessWindowStyle.Hidden,
                UseShellExecute = false,
                RedirectStandardOutput = true
            };

            var proc = Process.Start(info);
            proc.BeginOutputReadLine();
            proc.WaitForExit();

            info = new ProcessStartInfo(String.Format("{0}\\PcapConv.exe", Directory.GetCurrentDirectory()),
                                        String.Format("-decrypt tmp_encrypted.dat tmp_decrypted.dat \"{0}\"", keyBox.Text))
            {
                WorkingDirectory = String.Format(@"{0}\", Directory.GetCurrentDirectory()),
                WindowStyle = ProcessWindowStyle.Hidden,
                UseShellExecute = false,
                RedirectStandardOutput = true
            };

            proc = Process.Start(info);
            proc.BeginOutputReadLine();
            proc.WaitForExit();

            progressBar.Value = 5;

            var data = File.ReadAllBytes("tmp_decrypted.dat");
            if (data.Length < 16)
            {
                MessageBox.Show("Invalid input file!");
                return;
            }

            for (var i = 0; i + 16 <= data.Length; )
            {
                var senderIp = String.Format("{0}.{1}.{2}.{3}:{4}", data[i], data[i + 1], data[i + 2], data[i + 3], BitConverter.ToUInt16(data, i + 4));
                i += 6;

                //var receiverIp = String.Format("{0}.{1}.{2}.{3}:{4}", data[i], data[i + 1], data[i + 2], data[i + 3], BitConverter.ToUInt16(data, i + 4));
                i += 6;

                var size = BitConverter.ToInt32(data, i);
                i += 4;

                if (size > data.Length - i)
                {
                    MessageBox.Show("Read fault!");
                    break;
                }

                var block = new Byte[size];
                Array.Copy(data, i, block, 0, size);
                i += size;

                if (block[0] == 3)
                    RemoteIP = senderIp;

                var ps = new PacketStream(block, RemoteIP == senderIp);

                _packets.AddRange(ps.Packets);
            }

            progressBar.Value = 5;

            var pct = (progressBar.Maximum - progressBar.Value) / _packets.Count;

            Parser.SaveFile();

            foreach (var p in _packets)
            {
                Parser.Parse(p);
                progressBar.Value += pct;
            }

            Parser.OutStream.Flush();
            Parser.OutStream.Close();
            Parser.OutStream = null;
        }
    }
}
