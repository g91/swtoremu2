using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Windows;
using System.Windows.Input;
using Ookii.Dialogs.Wpf;

namespace SCPTExtractor
{
    public enum LogLevel
    {
        Debug = 1,
        Info = 2,
        Warning = 4,
        Error = 8,
        Client = 16,
    }

    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private ScriptCollection ScriptList;

        public MainWindow()
        {
            InitializeComponent();
            this.ExtendGlassHook();
            ScriptList = new ScriptCollection();
            scriptBox.DataContext = ScriptList;

            Log(LogLevel.Info, "Initialized SCPT Extractor version 0.4 by NoFaTe");
            Log(LogLevel.Info, "Special thanks to 'SWTOR Fan' for figuring out the file format.");
        }

        public void Log(LogLevel level, string text, params object[] args)
        {
            DateTime thisDate = DateTime.Now;
            CultureInfo culture = new CultureInfo("en-US");

            bool HasDebug = false;

            #if DEBUG
            HasDebug = true;
            #endif

            if (!HasDebug && level == LogLevel.Debug)
                return;

            this.consoleBox.Dispatcher.Invoke(
                System.Windows.Threading.DispatcherPriority.Normal,
                new Action(
                    delegate()
                    {
                        text = String.Format(text, args);
                        consoleBox.Text += String.Format("[{0}] {1}: {2}\r\n", thisDate.ToString("HH:mm:ss", culture), level.ToString().ToUpper(), text);
                        if (consoleBox.LineCount > 220)
                        {
                            var lines = (from item in consoleBox.Text.Split('\n') select item.Trim());
                            lines = lines.Skip(1);
                            consoleBox.Text = string.Join(Environment.NewLine, lines.ToArray());
                        }
                        consoleBox.ScrollToEnd();
                    }
            ));
        }

        private void browseBtn_Click(object sender, RoutedEventArgs e)
        {
            VistaFolderBrowserDialog dialog = new VistaFolderBrowserDialog();
            dialog.Description = "Please select a folder.";
            dialog.UseDescriptionForTitle = true;

            if ((bool)dialog.ShowDialog(this))
                pathBox.Text = dialog.SelectedPath;       
        }

        private void extractBtn_Click(object sender, RoutedEventArgs e)
        {
            if (!Directory.Exists(pathBox.Text))
            {
                Log(LogLevel.Error, "Invalid directory specified.");
                return;
            }

            string[] Files = Directory.GetFiles(pathBox.Text, "*.scpt");
            if (Files.Length == 0)
            {
                Log(LogLevel.Warning, "No script files found.");
                return;
            }

            if (!Directory.Exists(pathBox.Text + "\\Extracted"))
                Directory.CreateDirectory(pathBox.Text + "\\Extracted");

            if (!Directory.Exists(pathBox.Text + "\\Decrypted"))
                Directory.CreateDirectory(pathBox.Text + "\\Decrypted");

            ExtractPath = pathBox.Text + "\\Extracted";
            DecryptPath = pathBox.Text + "\\Decrypted";

            v5Count = 0;
            EncCount = 0;

            ScriptList.Clear();

            Thread ExtractionThread = new Thread(ExtractScripts);
            ExtractionThread.Start(Files);
        }

        private string ExtractPath;
        private string DecryptPath;

        private int v5Count;
        private int EncCount;

        private void ExtractScripts(object InObject)
        {
            string[] Scripts = InObject as string[];
            bool HasError = false;
            Log(LogLevel.Info, "Script Parser initialized.");
            Log(LogLevel.Info, "Parsing {0} Scripts.", Scripts.Length);
            for (int i = 0; i < Scripts.Length; i++)
            {
                try
                {
                    ParseScript(File.ReadAllBytes(Scripts[i]), Scripts, i);
                }
                catch (Exception ex)
                {
                    Log(LogLevel.Error, "Failed parsing script file '{0}'.\n{1}", Scripts[i], ex);
                    HasError = true;
                }
            }

            Log(LogLevel.Info, (HasError) ? "Script Parsing finished with errors." : "Script Parsing finished without any errors.");
            if (v5Count > 0)
            {
                Log(LogLevel.Info, "Restructured {0} v5 scripts out of which {1} were encrypted.", v5Count, EncCount);
                Log(LogLevel.Warning, "Reconstructed v5 files are not in regular v4 SCPT format.");
            }

            // Sort ScripList
            this.scriptBox.Dispatcher.Invoke(
                System.Windows.Threading.DispatcherPriority.Normal,
                new Action(
                    delegate()
                    {
                        if (ScriptList.Count > 0)
                        {
                            Log(LogLevel.Info, "Sorting Script List.");
                            scriptBox.DataContext =
                                from x in ScriptList
                                where (x.ToString().Length > 0)
                                orderby x.ToString()
                                select x;
                            Log(LogLevel.Info, "Script List sorted alphabetically.");
                        }
                    }
            ));
        }

        void ParseScript(byte[] Data, String[] Scripts, int Index)
        {
            //Log(LogLevel.Info, "Parsing script [{0}/{1}].", Index + 1, Count);
            MemoryStream Stream = new MemoryStream(Data);
            BinaryReader Reader = new BinaryReader(Stream);

            if (Reader.ReadUInt32() != 0x54504353)
            {
                Log(LogLevel.Warning, "Invalid script file!");
                return;
            }

            Int16 SmallVer = Reader.ReadInt16();
            Int16 BigVer = Reader.ReadInt16();

            Reader.ReadUInt64(); // 0x01
            byte[] CheckSum = Reader.ReadBytes(6);

            Log(LogLevel.Debug, "Loaded SCTP File version {0} and checksum 0x{1}.", BigVer, CheckSum.GetHEX());

            Reader.ReadBytes(2);

            if (SmallVer == 0x05 && BigVer == 0x05)
            {
                v5Count++;
                bool IsEncrypted = Reader.ReadBoolean();
                Reader.ReadUInt64();

                Int32 DataLength = Reader.ReadInt32();
                byte[] pData = Reader.ReadBytes(DataLength);

                if (IsEncrypted)
                {
                    EncCount++;
                    byte[] DecData = new Byte[pData.Length];

                    uint Unk = 0x35;
                    for (int i = 0; i < pData.Length; i++)
                    {
                        DecData[i] = (byte)(pData[i] ^ Unk);
                        Unk += 0x36;
                    }
                    pData = DecData;
                }

                File.WriteAllBytes(DecryptPath + "\\" + System.IO.Path.GetFileName(Scripts[Index]), pData);

                return;
            }

            Int32 NameLength = Reader.ReadInt32();
            String FileName = Encoding.ASCII.GetString(Reader.ReadBytes(NameLength));

            Log(LogLevel.Debug, "Got File Name: {0}.", FileName);

            HeroScript Script = new HeroScript(FileName, SmallVer, BigVer);

            Reader.ReadUInt64();
            Int32 FileSize = Reader.ReadInt32();


            int StringCount = (int)Reader.ReadVarNumeric();
            Log(LogLevel.Debug, "Found {0} Strings.", StringCount);
            for (int i = 0; i < StringCount; i++)
            {
                String TempString = Encoding.ASCII.GetString(Reader.ReadBytes((int)Reader.ReadVarNumeric()));
                Log(LogLevel.Debug, "Found String: {0}", TempString);
                Script.AddString(TempString);
            }

            long ELFLength = Reader.ReadVarNumeric();

            Script.ELF = Reader.ReadBytes((int)ELFLength);

            Log(LogLevel.Debug, "Saving ELF file '{0}.elf'.", Script.Name);

            if (Script.ELF[0] != 0x7F && Script.ELF[1] != 'E' && Script.ELF[2] != 'L')
            {
                Log(LogLevel.Error, "Invalid ELF file '{0}'.", Path.GetFileName(Scripts[Index]));
                throw new Exception(String.Format("Invalid ELF file '{0}'.", Path.GetFileName(Scripts[Index])));
            }

            Script.Save(ExtractPath);

            this.scriptBox.Dispatcher.Invoke(
                System.Windows.Threading.DispatcherPriority.Normal,
                new Action(
                    delegate()
                    {
                        ScriptList.Add(Script);
                    }
            ));
        }

        private void scriptBox_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            ScriptDialog ScriptPopup = new ScriptDialog(scriptBox.SelectedItem as HeroScript);
            ScriptPopup.ShowDialog();
        }
    }
}
