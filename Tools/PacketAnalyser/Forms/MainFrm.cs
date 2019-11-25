using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows.Forms;
using Be.Windows.Forms;

namespace PacketAnalyser.Forms
{
    public partial class MainFrm : Form
    {
        string RemoteIP = null;
        List<Packet> DecPackets;

        public MainFrm()
        {
            InitializeComponent();
            DecPackets = new List<Packet>();
        }

        private void pcapButton_Click(object sender, EventArgs e)
        {
            if (pcapOpenDialog.ShowDialog() == DialogResult.OK)
                this.pcapBox.Text = pcapOpenDialog.FileName;
        }

        private void keyButton_Click(object sender, EventArgs e)
        {
            if (keyOpenDialog.ShowDialog() == DialogResult.OK)
                this.keyBox.Text = keyOpenDialog.FileName;
        }

        private void decryptButton_Click(object sender, EventArgs e)
        {
            if (pcapBox.Text.Length < 4 || keyBox.Text.Length < 4 || portBox.Text.Length < 1)
            {
                MessageBox.Show("Please fill in all the required fields.", "Application Error");
                return;
            }

            if (!File.Exists(pcapBox.Text) || !File.Exists(keyBox.Text))
            {
                MessageBox.Show("File could not be found.", "Application Error");
                return;
            }

            int iPort;
            if (!Int32.TryParse(portBox.Text, out iPort))
            {
                MessageBox.Show("Invalid port specified.", "Application Error");
                return;
            }

            if (iPort < 1 || iPort > 65535)
            {
                MessageBox.Show("Invalid port specified.", "Application Error");
                return;
            }

            DecPackets.Clear();
            packetList.Items.Clear();

            ParsePackets();
        }

        void ParsePackets()
        {
            this.progBar.Value = 0;
            ProcessStartInfo info = new ProcessStartInfo(Directory.GetCurrentDirectory() + "\\PcapConv.exe",
                "\"" + this.pcapBox.Text + "\" tmp_encrypted.dat " + this.portBox.Text);
            info.WorkingDirectory = Directory.GetCurrentDirectory() + "\\";
            info.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
            info.UseShellExecute = false;
            info.RedirectStandardOutput = true;
            Process proc = Process.Start(info);
            proc.BeginOutputReadLine();
            proc.WaitForExit();
            this.progBar.Value = 20;

            info = new ProcessStartInfo(Directory.GetCurrentDirectory() + "\\PcapConv.exe",
                "-decrypt tmp_encrypted.dat tmp_decrypted.dat \"" + this.keyBox.Text + "\"");
            info.WorkingDirectory = Directory.GetCurrentDirectory() + "\\";
            info.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
            info.UseShellExecute = false;
            info.RedirectStandardOutput = true;
            proc = Process.Start(info);
            proc.BeginOutputReadLine();
            proc.WaitForExit();
            this.progBar.Value = 60;

            byte[] Data = File.ReadAllBytes("tmp_decrypted.dat");
            for (int idx = 0; (idx + 16) <= Data.Length; )
            {
                string senderIp = Data[idx].ToString() + "." + Data[(++idx)].ToString() + "."
                    + Data[(++idx)].ToString() + "." + Data[(++idx)].ToString() + ":" + BitConverter.ToUInt16(Data, (++idx));
                idx += 2;
                string receivedIp = Data[idx].ToString() + "." + Data[(++idx)].ToString() + "."
                    + Data[(++idx)].ToString() + "." + Data[(++idx)].ToString() + ":" + BitConverter.ToUInt16(Data, (++idx));
                idx += 2;
                int sizeToRead = BitConverter.ToInt32(Data, idx);
                idx += 4;
                try
                {
                    byte[] d = new byte[sizeToRead];
                    Array.Copy(Data, idx, d, 0, sizeToRead);
                    if (d[0] == 0 || d[0] == 1)
                    {
                        string status = "C => S";
                        if (senderIp == RemoteIP)
                            status = "S => C";

                        PacketStream stream = new PacketStream(d);
                        for (int i = 0; i < stream.Packets.Count; i++)
                        {
                            DecPackets.Add(stream.Packets[i]);
                            packetList.Items.Add(status + " " + stream.Packets[i].GetPacketStr());
                        }
                    }
                    else if (d[0] == 3)
                    {
                        RemoteIP = senderIp;
                    }
                }
                catch (Exception ex)
                {
                    break;
                }
                idx += sizeToRead;
            }
            this.progBar.Value = 0;
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

        private void open_Click(object sender, EventArgs e)
        {
            OpenFileDialog openFileDialog1 = new OpenFileDialog();
            openFileDialog1.Filter = "Swtor Dump|*.swd";
            openFileDialog1.Title = "Open a Star Wars : The Old Republic Dump";

            if (openFileDialog1.ShowDialog() == DialogResult.OK)
            {
                byte[] Data = File.ReadAllBytes(openFileDialog1.FileName);
                for (int idx = 0; (idx + 16) <= Data.Length; )
                {
                    string senderIp = Data[idx].ToString() + "." + Data[(++idx)].ToString() + "."
                        + Data[(++idx)].ToString() + "." + Data[(++idx)].ToString() + ":" + BitConverter.ToUInt16(Data, (++idx));
                    idx += 2;
                    string receivedIp = Data[idx].ToString() + "." + Data[(++idx)].ToString() + "."
                        + Data[(++idx)].ToString() + "." + Data[(++idx)].ToString() + ":" + BitConverter.ToUInt16(Data, (++idx));
                    idx += 2;
                    int sizeToRead = BitConverter.ToInt32(Data, idx);
                    idx += 4;
                    try
                    {
                        byte[] d = new byte[sizeToRead];
                        Array.Copy(Data, idx, d, 0, sizeToRead);
                        if (d[0] == 0 || d[0] == 1)
                        {
                            string status = "C => S";
                            if (senderIp == RemoteIP)
                                status = "S => C";

                            PacketStream stream = new PacketStream(d);
                            for (int i = 0; i < stream.Packets.Count; i++)
                            {
                                DecPackets.Add(stream.Packets[i]);
                                packetList.Items.Add(status + " " + stream.Packets[i].GetPacketStr());
                            }
                        }
                        else if (d[0] == 3)
                        {
                            RemoteIP = senderIp;
                        }
                    }
                    catch (Exception ex)
                    {
                        break;
                    }
                    idx += sizeToRead;
                }
                this.progBar.Value = 0;
            }
        }

        private void save_Click(object sender, EventArgs e)
        {
            SaveFileDialog saveFileDialog1 = new SaveFileDialog();
            saveFileDialog1.Filter = "Swtor Dump|*.swd";
            saveFileDialog1.Title = "Save a Star Wars : The Old Republic Dump";
            saveFileDialog1.ShowDialog();

            // If the file name is not an empty string open it for saving.
            if (saveFileDialog1.FileName != "")
            {
                File.Copy("tmp_decrypted.dat", saveFileDialog1.FileName, true);
            }
        }

        private void button1_Click(object sender, EventArgs e)
        {
            LiveForm Blah = new LiveForm();
            Blah.Show();
            this.Hide();
        }
    }
}