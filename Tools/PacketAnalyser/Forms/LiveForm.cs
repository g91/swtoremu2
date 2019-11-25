using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Net;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.Threading;
using Be.Windows.Forms;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using ComponentAce.Compression.Libs.zlib;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;

namespace PacketAnalyser.Forms
{
    public partial class LiveForm : Form
    {
        List<byte[]> Packets;
        List<Packet> DecPackets;
        IPAddress LocalIP = null;
        bool IsConnected = false, GotHandShake = false, CryptoInit = false;
        Process DumperProc;
        int ShardPort = 0;
        string ShardAddr = null;

        byte[] Key01 = null, Key02 = null, IV01 = null, IV02 = null;

        public LiveForm()
        {
            InitializeComponent();

            Packets = new List<byte[]>();
            DecPackets = new List<Packet>();
        }

        private IStreamCipher _dec01;
        private IStreamCipher _dec02;

        private ZStream _iStream01;
        private ZStream _iStream02;

        public void InitCrypto()
        {
            Console.WriteLine("Initialized decrypters and inflaters!");
            _dec01 = new Salsa20Engine();
            _dec01.Init(false, new ParametersWithIV(new KeyParameter(Key02), IV02));

            _dec02 = new Salsa20Engine();
            _dec02.Init(false, new ParametersWithIV(new KeyParameter(Key01), IV01));

            _iStream01 = new ZStream();
            _iStream01.inflateInit(-15);

            _iStream02 = new ZStream();
            _iStream02.inflateInit(-15);

            CryptoInit = true;
        }

        private void button1_Click(object sender, EventArgs e)
        {
            // Start Live Capture
            if (KeyDumpPath.Text.Length < 5 || KeyDumpPath.Text == "KeyDumper Executable Location" || !File.Exists(KeyDumpPath.Text))
                return;

            button1.Text = "Stop Live Capture";

            InitDumper();

            Thread EncTh = new Thread(EncThread);
            EncTh.Start();

            Thread CapTh = new Thread(InitCapture);
            CapTh.Start();
        }

        private void InitCapture()
        {
            IList<LivePacketDevice> allDevices = LivePacketDevice.AllLocalMachine;

            if (allDevices.Count == 0)
            {
                Console.WriteLine("No interfaces found! Make sure WinPcap is installed.");
                return;
            }

            // Print the list
            for (int i = 0; i != allDevices.Count; ++i)
            {
                LivePacketDevice device = allDevices[i];
                Console.Write((i + 1) + ". " + device.Name);
                if (device.Description != null)
                    Console.WriteLine(" (" + device.Description + ")");
                else
                    Console.WriteLine(" (No description available)");
            }

            int deviceIndex = 0;
            do
            {
                Console.WriteLine("Enter the interface number (1-" + allDevices.Count + "):");
                string deviceIndexString = Console.ReadLine();
                if (!int.TryParse(deviceIndexString, out deviceIndex) || deviceIndex < 1 || deviceIndex > allDevices.Count)
                {
                    deviceIndex = 0;
                }
            } while (deviceIndex == 0);

            // Take the selected adapter
            PacketDevice selectedDevice = allDevices[deviceIndex - 1];

            using (PacketCommunicator communicator = selectedDevice.Open(262140, PacketDeviceOpenAttributes.Promiscuous, 1000))
            {
                Console.Clear();
                Console.WriteLine("Started capture");

                communicator.SetFilter("tcp");
                communicator.ReceivePackets(0, PcapPacketHandler);
            }
        }

        void PcapPacketHandler(PcapDotNet.Packets.Packet packet)
        {
            IpV4Datagram ipPacket = packet.Ethernet.IpV4;
            TcpDatagram tcpPacket = ipPacket.Tcp;
            Datagram tcpData = tcpPacket.Payload;
            byte[] PacketData = tcpData.ToMemoryStream().ToArray();

            if (PacketData.Length > 5)
            {
                string srcIp = ipPacket.Source.ToString();
                string dstIp = ipPacket.Destination.ToString();
                int srcPort = tcpPacket.SourcePort;
                int dstPort = tcpPacket.DestinationPort;

                if (LocalIP == null)
                {
                    IPHostEntry _IPHostEntry = Dns.GetHostEntry(System.Net.Dns.GetHostName());

                    foreach (IPAddress _IPAddress in _IPHostEntry.AddressList)
                        if (_IPAddress.AddressFamily.ToString() == "InterNetwork")
                            if (_IPAddress.ToString() == srcIp.ToString() || _IPAddress.ToString() == dstIp.ToString())
                                LocalIP = _IPAddress;
                }

                if (!IsConnected)
                {
                    if (PacketData.Length == 14)
                    {
                        if (PacketData[0] == 0x03 && PacketData[1] == 0x0E)
                        {
                            if (srcPort >= 20050 && srcPort <= 20080)
                            {
                                Console.WriteLine("Got ClientHello on port {0}!", srcPort);
                                ShardAddr = srcIp;
                                ShardPort = srcPort;
                                IsConnected = true;
                            }
                        }
                    }
                    return;
                }

                if (!GotHandShake)
                {
                    if (PacketData[0] == 0x04)
                    {
                        Console.WriteLine("Got ClientHandshake!");
                        GotHandShake = true;
                    }
                    return;
                }

                if (LocalIP.ToString() == dstIp.ToString() && srcPort == ShardPort && srcIp.ToString() == ShardAddr.ToString())
                {
                    // Server -> Client
                    byte[] gPacket = new byte[PacketData.Length + 1];
                    gPacket[0] = 0x00;
                    Array.Copy(PacketData, 0, gPacket, 1, PacketData.Length);
                    Packets.Add(gPacket);
                }
                else if (dstPort == ShardPort && dstIp.ToString() == ShardAddr.ToString())
                {
                    // Client -> Server
                    byte[] gPacket = new byte[PacketData.Length + 1];
                    gPacket[0] = 0x01;
                    Array.Copy(PacketData, 0, gPacket, 1, PacketData.Length);
                    Packets.Add(gPacket);
                }
            }
        }

        delegate void AddPacketShitCallback(byte[] bPacket, bool FromServer);

        byte[] LastPacket = new byte[] { };

        void AddPacketShit(byte[] bPacket, bool FromServer)
        {
            if (this.packetList.InvokeRequired)
            {
                AddPacketShitCallback d = new AddPacketShitCallback(AddPacketShit);
                this.Invoke(d, new object[] { bPacket, FromServer });
            }
            else
            {

                if (bPacket.Length < 8)
                    return;

                List<byte[]> PacketPack = new List<byte[]>();
                PacketPack.Add(bPacket);

                if (bPacket.Length == 1452)
                {
                    // TODO: This isn't working as intended
                    Console.WriteLine("Got multipart packet");
                    // Multipart packet
                    byte pStatus = (byte)(FromServer ? 0x00 : 0x01);
                    int iIndex = 1;

                    while (PacketPack[PacketPack.Count - 1].Length == 1452)
                    {
                        while (Packets[iIndex][0] != pStatus)
                            iIndex++;

                        byte[] tempBuff = new byte[Packets[iIndex].Length - 1];
                        Array.Copy(Packets[iIndex], 1, tempBuff, 0, tempBuff.Length);

                        PacketPack.Add(tempBuff);
                        Packets.RemoveAt(iIndex);
                    }
                }

                if (FromServer)
                {
                    PacketStream PStream = new PacketStream(PacketPack, _dec02, _iStream02);
                    foreach (Packet iPacket in PStream.Packets)
                    {
                        DecPackets.Add(iPacket);
                        packetList.Items.Add("S => C " + iPacket.GetPacketStr());
                        Console.WriteLine("S => C " + iPacket.GetPacketStr());
                    }
                }
                else
                {
                    PacketStream PStream = new PacketStream(PacketPack, _dec01, _iStream01);
                    foreach (Packet iPacket in PStream.Packets)
                    {
                        DecPackets.Add(iPacket);
                        packetList.Items.Add("C => S " + iPacket.GetPacketStr());
                        Console.WriteLine("C => S " + iPacket.GetPacketStr());
                    }
                }
            }
        }

        void EncThread()
        {
            while (!CryptoInit)
            {
                Thread.Sleep(10);
            }

            while (true)
            {
                if (Packets.Count > 0)
                {
                    byte[] pBuffer = new byte[Packets[0].Length - 1];
                    Array.Copy(Packets[0], 1, pBuffer, 0, pBuffer.Length);
                    if (Packets[0][0] == 0x00)
                        AddPacketShit(pBuffer, true);
                    else
                        AddPacketShit(pBuffer, false);
                    Packets.RemoveAt(0);
                }
                Thread.Sleep(100);
            }
        }


        void InitDumper()
        {
            string[] fileEntries = Directory.GetFiles(Path.GetDirectoryName(KeyDumpPath.Text));

            // Clear old key dumps
            foreach (string fileName in fileEntries)
                if (Path.GetFileName(fileName).StartsWith("keys_") && Path.GetFileName(fileName).EndsWith(".dat"))
                    File.Delete(fileName);

            // Start the key dumper
            ProcessStartInfo info = new ProcessStartInfo(KeyDumpPath.Text);
            info.WorkingDirectory = Path.GetDirectoryName(KeyDumpPath.Text);
            info.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
            info.UseShellExecute = false;
            info.RedirectStandardOutput = true;
            DumperProc = Process.Start(info);
            DumperProc.BeginOutputReadLine();

            Thread KeysThread = new Thread(GetKeys);
            KeysThread.Start();
        }

        void GetKeys()
        {
            string DumpPath = Path.GetDirectoryName(KeyDumpPath.Text);
            while (Key01 == null || Key02 == null || IV01 == null || IV02 == null)
            {
                string[] fileEntries = Directory.GetFiles(DumpPath);

                // Clear old key dumps
                foreach (string fileName in fileEntries)
                {
                    if (Path.GetFileName(fileName).StartsWith("keys_game"))
                    {
                        FileInfo fInfo = new FileInfo(fileName);
                        if (fInfo.Length < 5)
                            continue;

                        DumperProc.Kill();

                        Thread.Sleep(500);

                        byte[] FileData;
                        using (FileStream fs = new FileStream(fileName, FileMode.Open, FileAccess.Read))
                        {
                            using (BinaryReader br = new BinaryReader(fs))
                            {
                                FileData = br.ReadBytes((int)br.BaseStream.Length);
                            }
                        }

                        if (FileData.Length > 0)
                        {
                            MemoryStream Stream = new MemoryStream(FileData);
                            EndianBinaryReader Reader = new EndianBinaryReader(MiscUtil.Conversion.EndianBitConverter.Little, Stream);
                            Reader.ReadBytes(0x04);
                            Key01 = Reader.ReadBytes(0x20);
                            IV01 = Reader.ReadBytes(0x08);
                            Reader.ReadBytes(0x0C);
                            Key02 = Reader.ReadBytes(0x20);
                            IV02 = Reader.ReadBytes(0x08);
                            InitCrypto();
                        }
                    }
                }

                Thread.Sleep(100);
            }
        }

        private MemoryStream decStream = null;
        private MemoryStream defStream = null;
        private DynamicFileByteProvider decProvider = null;
        private DynamicFileByteProvider defProvider = null;

        private void packetList_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (decStream != null)
                decStream.Dispose();

            if (defStream != null)
                defStream.Dispose();

            if (decProvider != null)
                decProvider.Dispose();

            if (defProvider != null)
                defProvider.Dispose();

            decStream = new MemoryStream(this.DecPackets[this.packetList.SelectedIndex].Data);
            defStream = new MemoryStream(this.DecPackets[this.packetList.SelectedIndex].cData);
            decProvider = new DynamicFileByteProvider(decStream);
            defProvider = new DynamicFileByteProvider(defStream);
            this.decBox.ByteProvider = decProvider;
            this.defBox.ByteProvider = defProvider;
        }

        private void MainFrm_Resize(object sender, EventArgs e)
        {
            int iSize = this.defBox.Size.Width - 80 - 24;
            int numBytes = iSize / 33;
            this.defBox.BytesPerLine = numBytes;
            this.decBox.BytesPerLine = numBytes;
        }

        private void decBox_SelectionLengthChanged(object sender, EventArgs e)
        {
            try
            {
                SetDecBoxDecimal();
            }
            catch (Exception ex)
            {
            }
        }

        private void defBox_SelectionLengthChanged(object sender, EventArgs e)
        {
            try
            {
                SetDefBoxDecimal();
            }
            catch (Exception ex)
            {
            }
        }

        private void SetDefBoxDecimal()
        {
            int iLength = 1;
            if (this.defBox.SelectionLength >= 8)
                iLength = 8;
            else if (this.defBox.SelectionLength >= 4)
                iLength = 4;
            else if (this.defBox.SelectionLength >= 2)
                iLength = 2;

            byte[] iBuff = new byte[iLength];
            for (int i = 0; i < iLength; i++)
                iBuff[i] = this.defProvider.ReadByte(this.defBox.SelectionStart + i);

            setDecText(iLength, iBuff);
            setFloatText(iLength, iBuff);
        }

        private void SetDecBoxDecimal()
        {
            int iLength = 1;
            if (this.decBox.SelectionLength >= 8)
                iLength = 8;
            else if (this.decBox.SelectionLength >= 4)
                iLength = 4;
            else if (this.decBox.SelectionLength >= 2)
                iLength = 2;

            byte[] iBuff = new byte[iLength];
            for (int i = 0; i < iLength; i++)
                iBuff[i] = this.decProvider.ReadByte(this.decBox.SelectionStart + i);

            setDecText(iLength, iBuff);
            setFloatText(iLength, iBuff);
        }

        private void setDecText(int iLength, byte[] iBuff)
        {
            switch (iLength)
            {
                case 1:
                    this.decText.Text = ((int)iBuff[0]).ToString();
                    break;
                case 2:
                    this.decText.Text = ((int)BitConverter.ToUInt16(iBuff, 0)).ToString();
                    break;
                case 4:
                    this.decText.Text = ((int)BitConverter.ToUInt32(iBuff, 0)).ToString();
                    break;
                case 8:
                    this.decText.Text = ((int)BitConverter.ToUInt64(iBuff, 0)).ToString();
                    break;
            }
        }

        private void setFloatText(int iLength, byte[] iBuff)
        {
            switch (iLength)
            {
                case 4:
                    this.floatText.Text = ((float)BitConverter.ToSingle(iBuff, 0)).ToString();
                    break;
                case 8:
                    this.floatText.Text = ((double)BitConverter.ToDouble(iBuff, 0)).ToString();
                    break;
            }
        }

        private void analyzeBtn_Click(object sender, EventArgs e)
        {
            this.analyzeBox.Items.Clear();

            byte[] iB = this.DecPackets[this.packetList.SelectedIndex].Data;

            int index = 8;

            while (index < iB.Length - 1)
            {
                var g = BitConverter.ToUInt16(iB, index);
                if (g >= 0 && iB[index + 2] != 0x00 && iB.Length - index >= g)
                {
                    index += 2;
                    analyzeBox.Items.Add(String.Format("Int16 [0x{0:X4}]", g));
                    Console.WriteLine("Int16 [0x{0:X4}]", g);
                }
                else
                {
                    uint h = 0;
                    try
                    {
                        h = BitConverter.ToUInt32(iB, index);
                    }
                    catch
                    {
                    }
                    if (h == 1 && iB[index + 4] == 0x00)
                    {
                        analyzeBox.Items.Add("NULL String");
                        Console.WriteLine("NULL String");
                        index += 5;
                    }
                    else if (h >= 0 && iB.Length - index - 4 >= h)
                    {
                        index += 4;
                        int b = 0;

                        try
                        {
                            for (int i = 0; i < h - 1; i++)
                                if (IsChar(iB[index + i]))
                                    b++;
                        }
                        catch { }

                        if (b == h - 1)
                        {
                            analyzeBox.Items.Add("String: " + Encoding.ASCII.GetString(GetBuff(iB, index, (int)h - 1)));
                            Console.WriteLine("String: " + Encoding.ASCII.GetString(GetBuff(iB, index, (int)h - 1)));
                            index += (int)h;
                        }
                        else
                        {
                            try
                            {
                                if (iB.Length - index == h && h > 1)
                                {
                                    analyzeBox.Items.Add("Data Blob [Length: " + h.ToString() + "]");
                                    Console.WriteLine("Data Blob [Length: " + h.ToString() + "]");
                                    index += (int)h;
                                }
                                else if (iB[index - 2] == 0x00 || iB[index] == 0x00 || iB[index - 1] == 0x00)
                                {
                                    analyzeBox.Items.Add(String.Format("Int32 [0x{0:X8}]", h));
                                    Console.WriteLine("Int32 [0x{0:X8}]", h);
                                }
                                else
                                {
                                    analyzeBox.Items.Add("Data Blob [Length: " + h.ToString() + "]");
                                    Console.WriteLine("Data Blob [Length: " + h.ToString() + "]");
                                    index += (int)h;
                                }
                            }
                            catch { }
                        }
                    }
                    else if (index == iB.Length - 4 || (iB[index + 3] == 0x00 && iB[index + 4] != 0x00))
                    {
                        analyzeBox.Items.Add(String.Format("Int32 [0x{0:X8}]", h));
                        Console.WriteLine("Int32 [0x{0:X8}]", h);
                        index += 4;
                    }
                    else
                    {
                        try
                        {
                            analyzeBox.Items.Add(String.Format("Int64 [0x{0:X16}]", BitConverter.ToUInt64(iB, index)));
                            //Console.WriteLine("Int64 [0x{0:X16}]", BitConverter.ToUInt64(iB, index));
                        }
                        catch { }
                        index += 8;
                    }
                }
            }
        }

        private bool IsChar(byte inByte)
        {
            if (inByte >= 0x20 && inByte <= 0x7E || inByte == 0x0A || inByte == 0x0D)
                return true;
            return false;
        }

        private byte[] GetBuff(byte[] inBuff, int index, int count)
        {
            byte[] outB = new byte[count];
            for (int i = index; i < index + count; i++)
            {
                outB[i - index] = inBuff[i];
            }
            return outB;
        }

        private void searchBox_TextChanged(object sender, EventArgs e)
        {
        }

        private void keyDumpBrowse_Click(object sender, EventArgs e)
        {
            if (dumpOpenDialog.ShowDialog() == DialogResult.OK)
                this.KeyDumpPath.Text = dumpOpenDialog.FileName;
        }

    }
}