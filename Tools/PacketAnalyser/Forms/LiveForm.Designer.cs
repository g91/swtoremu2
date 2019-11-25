namespace PacketAnalyser.Forms
{
    partial class LiveForm
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.packetList = new System.Windows.Forms.ListBox();
            this.panel1 = new System.Windows.Forms.Panel();
            this.keyDumpBrowse = new System.Windows.Forms.Button();
            this.KeyDumpPath = new System.Windows.Forms.TextBox();
            this.button1 = new System.Windows.Forms.Button();
            this.panel2 = new System.Windows.Forms.Panel();
            this.panel3 = new System.Windows.Forms.Panel();
            this.floatText = new System.Windows.Forms.Label();
            this.label5 = new System.Windows.Forms.Label();
            this.decText = new System.Windows.Forms.Label();
            this.label4 = new System.Windows.Forms.Label();
            this.splitContainer1 = new System.Windows.Forms.SplitContainer();
            this.decBox = new Be.Windows.Forms.HexBox();
            this.defBox = new Be.Windows.Forms.HexBox();
            this.dumpOpenDialog = new System.Windows.Forms.OpenFileDialog();
            this.panel4 = new System.Windows.Forms.Panel();
            this.analyzeBox = new System.Windows.Forms.ListBox();
            this.analyzeBtn = new System.Windows.Forms.Button();
            this.panel1.SuspendLayout();
            this.panel2.SuspendLayout();
            this.panel3.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.splitContainer1)).BeginInit();
            this.splitContainer1.Panel1.SuspendLayout();
            this.splitContainer1.Panel2.SuspendLayout();
            this.splitContainer1.SuspendLayout();
            this.panel4.SuspendLayout();
            this.SuspendLayout();
            // 
            // packetList
            // 
            this.packetList.Dock = System.Windows.Forms.DockStyle.Fill;
            this.packetList.Font = new System.Drawing.Font("Consolas", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.packetList.FormattingEnabled = true;
            this.packetList.ItemHeight = 15;
            this.packetList.Location = new System.Drawing.Point(0, 0);
            this.packetList.Name = "packetList";
            this.packetList.Size = new System.Drawing.Size(226, 490);
            this.packetList.TabIndex = 0;
            this.packetList.SelectedIndexChanged += new System.EventHandler(this.packetList_SelectedIndexChanged);
            // 
            // panel1
            // 
            this.panel1.Controls.Add(this.keyDumpBrowse);
            this.panel1.Controls.Add(this.KeyDumpPath);
            this.panel1.Controls.Add(this.button1);
            this.panel1.Dock = System.Windows.Forms.DockStyle.Top;
            this.panel1.Location = new System.Drawing.Point(0, 0);
            this.panel1.Name = "panel1";
            this.panel1.Size = new System.Drawing.Size(1201, 76);
            this.panel1.TabIndex = 1;
            // 
            // keyDumpBrowse
            // 
            this.keyDumpBrowse.Location = new System.Drawing.Point(655, 12);
            this.keyDumpBrowse.Name = "keyDumpBrowse";
            this.keyDumpBrowse.Size = new System.Drawing.Size(75, 20);
            this.keyDumpBrowse.TabIndex = 7;
            this.keyDumpBrowse.Text = "Browse...";
            this.keyDumpBrowse.UseVisualStyleBackColor = true;
            this.keyDumpBrowse.Click += new System.EventHandler(this.keyDumpBrowse_Click);
            // 
            // KeyDumpPath
            // 
            this.KeyDumpPath.Location = new System.Drawing.Point(226, 12);
            this.KeyDumpPath.Name = "KeyDumpPath";
            this.KeyDumpPath.Size = new System.Drawing.Size(423, 20);
            this.KeyDumpPath.TabIndex = 6;
            this.KeyDumpPath.Text = "KeyDumper Executable Location";
            // 
            // button1
            // 
            this.button1.Location = new System.Drawing.Point(12, 12);
            this.button1.Name = "button1";
            this.button1.Size = new System.Drawing.Size(195, 52);
            this.button1.TabIndex = 5;
            this.button1.Text = "Start Live Capture";
            this.button1.UseVisualStyleBackColor = true;
            this.button1.Click += new System.EventHandler(this.button1_Click);
            // 
            // panel2
            // 
            this.panel2.Controls.Add(this.packetList);
            this.panel2.Dock = System.Windows.Forms.DockStyle.Left;
            this.panel2.Location = new System.Drawing.Point(0, 76);
            this.panel2.Name = "panel2";
            this.panel2.Size = new System.Drawing.Size(226, 490);
            this.panel2.TabIndex = 2;
            // 
            // panel3
            // 
            this.panel3.Controls.Add(this.floatText);
            this.panel3.Controls.Add(this.label5);
            this.panel3.Controls.Add(this.decText);
            this.panel3.Controls.Add(this.label4);
            this.panel3.Dock = System.Windows.Forms.DockStyle.Bottom;
            this.panel3.Location = new System.Drawing.Point(226, 536);
            this.panel3.Name = "panel3";
            this.panel3.Size = new System.Drawing.Size(716, 30);
            this.panel3.TabIndex = 3;
            // 
            // floatText
            // 
            this.floatText.AutoSize = true;
            this.floatText.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(161)));
            this.floatText.Location = new System.Drawing.Point(209, 8);
            this.floatText.Name = "floatText";
            this.floatText.Size = new System.Drawing.Size(14, 13);
            this.floatText.TabIndex = 3;
            this.floatText.Text = "0";
            // 
            // label5
            // 
            this.label5.AutoSize = true;
            this.label5.Location = new System.Drawing.Point(170, 8);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(33, 13);
            this.label5.TabIndex = 2;
            this.label5.Text = "Float:";
            // 
            // decText
            // 
            this.decText.AutoSize = true;
            this.decText.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(161)));
            this.decText.Location = new System.Drawing.Point(69, 8);
            this.decText.Name = "decText";
            this.decText.Size = new System.Drawing.Size(14, 13);
            this.decText.TabIndex = 0;
            this.decText.Text = "0";
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Location = new System.Drawing.Point(12, 8);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(51, 13);
            this.label4.TabIndex = 0;
            this.label4.Text = "Decimal: ";
            // 
            // splitContainer1
            // 
            this.splitContainer1.Dock = System.Windows.Forms.DockStyle.Fill;
            this.splitContainer1.Location = new System.Drawing.Point(226, 76);
            this.splitContainer1.Name = "splitContainer1";
            this.splitContainer1.Orientation = System.Windows.Forms.Orientation.Horizontal;
            // 
            // splitContainer1.Panel1
            // 
            this.splitContainer1.Panel1.Controls.Add(this.decBox);
            // 
            // splitContainer1.Panel2
            // 
            this.splitContainer1.Panel2.Controls.Add(this.defBox);
            this.splitContainer1.Size = new System.Drawing.Size(716, 460);
            this.splitContainer1.SplitterDistance = 195;
            this.splitContainer1.TabIndex = 4;
            // 
            // decBox
            // 
            this.decBox.BytesPerLine = 17;
            this.decBox.Dock = System.Windows.Forms.DockStyle.Fill;
            this.decBox.Font = new System.Drawing.Font("Courier New", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.decBox.LineInfoForeColor = System.Drawing.Color.Silver;
            this.decBox.LineInfoVisible = true;
            this.decBox.Location = new System.Drawing.Point(0, 0);
            this.decBox.Name = "decBox";
            this.decBox.ReadOnly = true;
            this.decBox.ShadowSelectionColor = System.Drawing.Color.FromArgb(((int)(((byte)(100)))), ((int)(((byte)(60)))), ((int)(((byte)(188)))), ((int)(((byte)(255)))));
            this.decBox.Size = new System.Drawing.Size(716, 195);
            this.decBox.StringViewVisible = true;
            this.decBox.TabIndex = 1;
            this.decBox.UseFixedBytesPerLine = true;
            this.decBox.VScrollBarVisible = true;
            this.decBox.SelectionStartChanged += new System.EventHandler(this.decBox_SelectionLengthChanged);
            this.decBox.SelectionLengthChanged += new System.EventHandler(this.decBox_SelectionLengthChanged);
            // 
            // defBox
            // 
            this.defBox.BytesPerLine = 17;
            this.defBox.Dock = System.Windows.Forms.DockStyle.Fill;
            this.defBox.Font = new System.Drawing.Font("Courier New", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.defBox.LineInfoForeColor = System.Drawing.Color.Silver;
            this.defBox.LineInfoVisible = true;
            this.defBox.Location = new System.Drawing.Point(0, 0);
            this.defBox.Name = "defBox";
            this.defBox.ReadOnly = true;
            this.defBox.ShadowSelectionColor = System.Drawing.Color.FromArgb(((int)(((byte)(100)))), ((int)(((byte)(60)))), ((int)(((byte)(188)))), ((int)(((byte)(255)))));
            this.defBox.Size = new System.Drawing.Size(716, 261);
            this.defBox.StringViewVisible = true;
            this.defBox.TabIndex = 0;
            this.defBox.UseFixedBytesPerLine = true;
            this.defBox.VScrollBarVisible = true;
            this.defBox.SelectionStartChanged += new System.EventHandler(this.defBox_SelectionLengthChanged);
            this.defBox.SelectionLengthChanged += new System.EventHandler(this.defBox_SelectionLengthChanged);
            // 
            // dumpOpenDialog
            // 
            this.dumpOpenDialog.DefaultExt = "pcap";
            this.dumpOpenDialog.Filter = "Executable Files|*.exe";
            // 
            // panel4
            // 
            this.panel4.Controls.Add(this.analyzeBox);
            this.panel4.Controls.Add(this.analyzeBtn);
            this.panel4.Dock = System.Windows.Forms.DockStyle.Right;
            this.panel4.Location = new System.Drawing.Point(942, 76);
            this.panel4.Name = "panel4";
            this.panel4.Size = new System.Drawing.Size(259, 490);
            this.panel4.TabIndex = 2;
            // 
            // analyzeBox
            // 
            this.analyzeBox.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left)));
            this.analyzeBox.Font = new System.Drawing.Font("Consolas", 9.75F);
            this.analyzeBox.FormattingEnabled = true;
            this.analyzeBox.ItemHeight = 15;
            this.analyzeBox.Location = new System.Drawing.Point(3, 42);
            this.analyzeBox.Name = "analyzeBox";
            this.analyzeBox.Size = new System.Drawing.Size(253, 439);
            this.analyzeBox.TabIndex = 1;
            // 
            // analyzeBtn
            // 
            this.analyzeBtn.Location = new System.Drawing.Point(3, 3);
            this.analyzeBtn.Name = "analyzeBtn";
            this.analyzeBtn.Size = new System.Drawing.Size(253, 33);
            this.analyzeBtn.TabIndex = 0;
            this.analyzeBtn.Text = "Analyze!";
            this.analyzeBtn.UseVisualStyleBackColor = true;
            this.analyzeBtn.Click += new System.EventHandler(this.analyzeBtn_Click);
            // 
            // LiveForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(1201, 566);
            this.Controls.Add(this.splitContainer1);
            this.Controls.Add(this.panel3);
            this.Controls.Add(this.panel4);
            this.Controls.Add(this.panel2);
            this.Controls.Add(this.panel1);
            this.MinimumSize = new System.Drawing.Size(1100, 604);
            this.Name = "LiveForm";
            this.Text = "Star Wars: The Old Republic - Emulator Nexus - Live Packet Analyser";
            this.Resize += new System.EventHandler(this.MainFrm_Resize);
            this.panel1.ResumeLayout(false);
            this.panel1.PerformLayout();
            this.panel2.ResumeLayout(false);
            this.panel3.ResumeLayout(false);
            this.panel3.PerformLayout();
            this.splitContainer1.Panel1.ResumeLayout(false);
            this.splitContainer1.Panel2.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)(this.splitContainer1)).EndInit();
            this.splitContainer1.ResumeLayout(false);
            this.panel4.ResumeLayout(false);
            this.ResumeLayout(false);

        }

        #endregion Windows Form Designer generated code

        private System.Windows.Forms.ListBox packetList;
        private System.Windows.Forms.Panel panel1;
        private System.Windows.Forms.Panel panel2;
        private System.Windows.Forms.Panel panel3;
        private System.Windows.Forms.SplitContainer splitContainer1;
        private System.Windows.Forms.Label decText;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.OpenFileDialog dumpOpenDialog;
        private Be.Windows.Forms.HexBox decBox;
        private Be.Windows.Forms.HexBox defBox;
        private System.Windows.Forms.Panel panel4;
        private System.Windows.Forms.Button analyzeBtn;
        private System.Windows.Forms.ListBox analyzeBox;
        private System.Windows.Forms.Label label5;
        private System.Windows.Forms.Label floatText;
        private System.Windows.Forms.Button keyDumpBrowse;
        private System.Windows.Forms.TextBox KeyDumpPath;
        private System.Windows.Forms.Button button1;
    }
}