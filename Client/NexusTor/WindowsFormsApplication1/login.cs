using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Net;
using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;
using Ionic.Zip;

namespace WindowsFormsApplication1
{
    public partial class login : Form
    {
        public login()
        {
            InitializeComponent();
        }

        private string extractLang()
        {
            string[] file = Directory.GetFiles(Directory.GetCurrentDirectory() + "\\Assets\\", "assets_swtor_??_??_version.txt");
            Match matches = Regex.Match(file[0], @"(.*)[\\/]assets_swtor_([a-z]{2})_([a-z]{2})_version.txt");
            return matches.Groups[2].Value + "-" + matches.Groups[3].Value;
        }

        private void button1_Click(object sender, EventArgs e)
        {
            WebRequest request = WebRequest.Create("http://emulatornexus.com/sso/swtor.php?username=" + username.Text + "&password=" + password.Text);
            WebResponse response = request.GetResponse();
            System.IO.StreamReader reader = new System.IO.StreamReader(response.GetResponseStream());
            string[] get = reader.ReadToEnd().Split('|');

            if (get[0] == "Logged_in")
            {
                string lang = extractLang();
                ProcessStartInfo info = new ProcessStartInfo(Directory.GetCurrentDirectory() + "\\swtor\\nexusclient\\swtor-emu.exe", "-set username " + get[1] +
                    " -set password d===" +
                    " -set platform server.emulatornexus.com:443 -set environment swtor " +
                    "-set lang " + lang + " -set torsets main," + lang + " @swtor_dual.icb");

                info.WorkingDirectory = Directory.GetCurrentDirectory() + "\\swtor\\nexusclient";

                Process.Start(info);
            }

            if (get[0] == "NO")
            {
                MessageBox.Show("Failed to login.");
            }
        }

        private void login_Load(object sender, EventArgs e)
        {
            string text = System.IO.File.ReadAllText(@"version.txt");

            WebRequest request = WebRequest.Create("http://emulatornexus.com/sso/swtor/version.php");
            WebResponse response = request.GetResponse();
            System.IO.StreamReader reader = new System.IO.StreamReader(response.GetResponseStream());
            string[] get = reader.ReadToEnd().Split('|');

            if(text != get[0])
            {
                MessageBox.Show("Version outdated. Please go to Emulator Nexus for updates or press update.");
            }

            if (!Directory.Exists(Directory.GetCurrentDirectory() + "\\swtor\\nexusclient"))
            {
                update();
            }
        }

        private void MyExtract(string zipToUnpack, string unpackDirectory)
        {
            using (ZipFile zip1 = ZipFile.Read(zipToUnpack))
            {
                foreach (ZipEntry e in zip1)
                {
                    e.Extract(unpackDirectory, ExtractExistingFileAction.OverwriteSilently);
                }
            }
        }

        private void update()
        {
            button1.Enabled = false;
            button2.Enabled = false;
            backgroundWorker1.RunWorkerAsync();
        }

        private void button2_Click(object sender, EventArgs e)
        {
            update();
        }

        private void backgroundWorker1_DoWork(object sender, DoWorkEventArgs e)
        {
            WebClient webClient = new WebClient();
            webClient.DownloadFile("http://emulatornexus.com/sso/swtor/nexusclient.zip", @"nexusclient.zip");
            MyExtract("nexusclient.zip", Directory.GetCurrentDirectory() + "\\swtor\\nexusclient");

            webClient.DownloadFile("http://emulatornexus.com/sso/swtor/version.txt", @"version.txt");
        }

        private void backgroundWorker1_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            MessageBox.Show("The client has been updated, please enjoy.");
            button1.Enabled = true;
            button2.Enabled = true;
        }

        private void login_FormClosed(object sender, FormClosedEventArgs e)
        {
            Application.Exit();
        }
    }
}
