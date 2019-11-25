namespace PacketAnalyser.Forms
{
    partial class MainFrm
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
            this.save = new System.Windows.Forms.Button();
            this.open = new System.Windows.Forms.Button();
            this.searchBox = new System.Windows.Forms.TextBox();
            this.decryptButton = new System.Windows.Forms.Button();
            this.portBox = new System.Windows.Forms.TextBox();
            this.label2 = new System.Windows.Forms.Label();
            this.keyBox = new System.Windows.Forms.TextBox();
            this.label3 = new System.Windows.Forms.Label();
            this.label1 = new System.Windows.Forms.Label();
            this.keyButton = new System.Windows.Forms.Button();
            this.pcapBox = new System.Windows.Forms.TextBox();
            this.pcapButton = new System.Windows.Forms.Button();
            this.panel2 = new System.Windows.Forms.Panel();
            this.panel3 = new System.Windows.Forms.Panel();
            this.floatText = new System.Windows.Forms.Label();
            this.label5 = new System.Windows.Forms.Label();
            this.progBar = new System.Windows.Forms.ProgressBar();
            this.decText = new System.Windows.Forms.Label();
            this.label4 = new System.Windows.Forms.Label();
            this.splitContainer1 = new System.Windows.Forms.SplitContainer();
            this.decBox = new Be.Windows.Forms.HexBox();
            this.defBox = new Be.Windows.Forms.HexBox();
            this.pcapOpenDialog = new System.Windows.Forms.OpenFileDialog();
            this.keyOpenDialog = new System.Windows.Forms.OpenFileDialog();
            this.panel4 = new System.Windows.Forms.Panel();
            this.analyzeBox = new System.Windows.Forms.ListBox();
            this.analyzeBtn = new System.Windows.Forms.Button();
            this.button1 = new System.Windows.Forms.Button();
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
            this.panel1.Controls.Add(this.button1);
            this.panel1.Controls.Add(this.save);
            this.panel1.Controls.Add(this.open);
            this.panel1.Controls.Add(this.searchBox);
            this.panel1.Controls.Add(this.decryptButton);
            this.panel1.Controls.Add(this.portBox);
            this.panel1.Controls.Add(this.label2);
            this.panel1.Controls.Add(this.keyBox);
            this.panel1.Controls.Add(this.label3);
            this.panel1.Controls.Add(this.label1);
            this.panel1.Controls.Add(this.keyButton);
            this.panel1.Controls.Add(this.pcapBox);
            this.panel1.Controls.Add(this.pcapButton);
            this.panel1.Dock = System.Windows.Forms.DockStyle.Top;
            this.panel1.Location = new System.Drawing.Point(0, 0);
            this.panel1.Name = "panel1";
            this.panel1.Size = new System.Drawing.Size(1201, 76);
            this.panel1.TabIndex = 1;
            // 
            // save
            // 
            this.save.Location = new System.Drawing.Point(102, 13);
            this.save.Name = "save";
            this.save.Size = new System.Drawing.Size(75, 23);
            this.save.TabIndex = 7;
            this.save.Text = "Save";
            this.save.UseVisualStyleBackColor = true;
            this.save.Click += new System.EventHandler(this.save_Click);
            // 
            // open
            // 
            this.open.Location = new System.Drawing.Point(12, 13);
            this.open.Name = "open";
            this.open.Size = new System.Drawing.Size(75, 23);
            this.open.TabIndex = 6;
            this.open.Text = "Open";
            this.open.UseVisualStyleBackColor = true;
            this.open.Click += new System.EventHandler(this.open_Click);
            // 
            // searchBox
            // 
            this.searchBox.Location = new System.Drawing.Point(12, 50);
            this.searchBox.Name = "searchBox";
            this.searchBox.Size = new System.Drawing.Size(203, 20);
            this.searchBox.TabIndex = 5;
            this.searchBox.TextChanged += new System.EventHandler(this.searchBox_TextChanged);
            // 
            // decryptButton
            // 
            this.decryptButton.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.decryptButton.Location = new System.Drawing.Point(897, 40);
            this.decryptButton.Name = "decryptButton";
            this.decryptButton.Size = new System.Drawing.Size(292, 27);
            this.decryptButton.TabIndex = 4;
            this.decryptButton.Text = "Load and Decrypt!";
            this.decryptButton.UseVisualStyleBackColor = true;
            this.decryptButton.Click += new System.EventHandler(this.decryptButton_Click);
            // 
            // portBox
            // 
            this.portBox.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.portBox.Location = new System.Drawing.Point(824, 44);
            this.portBox.Name = "portBox";
            this.portBox.Size = new System.Drawing.Size(67, 20);
            this.portBox.TabIndex = 3;
            this.portBox.Text = "20061";
            // 
            // label2
            // 
            this.label2.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(771, 16);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(47, 13);
            this.label2.TabIndex = 2;
            this.label2.Text = "Key File:";
            // 
            // keyBox
            // 
            this.keyBox.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.keyBox.Location = new System.Drawing.Point(824, 13);
            this.keyBox.Name = "keyBox";
            this.keyBox.Size = new System.Drawing.Size(281, 20);
            this.keyBox.TabIndex = 1;
            this.keyBox.Text = "C:\\SWTor\\Captures\\New\\Login-CreateCharacter-EnterWorld\\game.key";
            // 
            // label3
            // 
            this.label3.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(764, 47);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(54, 13);
            this.label3.TabIndex = 2;
            this.label3.Text = "Port Filter:";
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(267, 15);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(66, 13);
            this.label1.TabIndex = 2;
            this.label1.Text = "Capture File:";
            // 
            // keyButton
            // 
            this.keyButton.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.keyButton.Location = new System.Drawing.Point(1114, 12);
            this.keyButton.Name = "keyButton";
            this.keyButton.Size = new System.Drawing.Size(75, 20);
            this.keyButton.TabIndex = 0;
            this.keyButton.Text = "Browse...";
            this.keyButton.UseVisualStyleBackColor = true;
            this.keyButton.Click += new System.EventHandler(this.keyButton_Click);
            // 
            // pcapBox
            // 
            this.pcapBox.Location = new System.Drawing.Point(339, 12);
            this.pcapBox.Name = "pcapBox";
            this.pcapBox.Size = new System.Drawing.Size(345, 20);
            this.pcapBox.TabIndex = 1;
            this.pcapBox.Text = "C:\\SWTor\\Captures\\New\\Login-CreateCharacter-EnterWorld\\Capture.pcap";
            // 
            // pcapButton
            // 
            this.pcapButton.Location = new System.Drawing.Point(690, 12);
            this.pcapButton.Name = "pcapButton";
            this.pcapButton.Size = new System.Drawing.Size(75, 20);
            this.pcapButton.TabIndex = 0;
            this.pcapButton.Text = "Browse...";
            this.pcapButton.UseVisualStyleBackColor = true;
            this.pcapButton.Click += new System.EventHandler(this.pcapButton_Click);
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
            this.panel3.Controls.Add(this.progBar);
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
            // progBar
            // 
            this.progBar.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.progBar.Location = new System.Drawing.Point(386, 0);
            this.progBar.Name = "progBar";
            this.progBar.Size = new System.Drawing.Size(330, 30);
            this.progBar.TabIndex = 1;
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
            // pcapOpenDialog
            // 
            this.pcapOpenDialog.DefaultExt = "pcap";
            this.pcapOpenDialog.Filter = "PCAP Files|*.pcap";
            // 
            // keyOpenDialog
            // 
            this.keyOpenDialog.DefaultExt = "key";
            this.keyOpenDialog.Filter = "DAT Files|*.dat|Key Files|*.key|All Files|*.*";
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
            // button1
            // 
            this.button1.Location = new System.Drawing.Point(270, 45);
            this.button1.Name = "button1";
            this.button1.Size = new System.Drawing.Size(118, 25);
            this.button1.TabIndex = 8;
            this.button1.Text = "Launch Live Dumper";
            this.button1.UseVisualStyleBackColor = true;
            this.button1.Click += new System.EventHandler(this.button1_Click);
            // 
            // MainFrm
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
            this.Name = "MainFrm";
            this.Text = "Star Wars: The Old Republic - Emulator Nexus - Packet Analyser";
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
        private System.Windows.Forms.Button decryptButton;
        private System.Windows.Forms.TextBox portBox;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.TextBox keyBox;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Button keyButton;
        private System.Windows.Forms.TextBox pcapBox;
        private System.Windows.Forms.Button pcapButton;
        private System.Windows.Forms.ProgressBar progBar;
        private System.Windows.Forms.Label decText;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.OpenFileDialog pcapOpenDialog;
        private System.Windows.Forms.OpenFileDialog keyOpenDialog;
        private Be.Windows.Forms.HexBox decBox;
        private Be.Windows.Forms.HexBox defBox;
        private System.Windows.Forms.Panel panel4;
        private System.Windows.Forms.Button analyzeBtn;
        private System.Windows.Forms.ListBox analyzeBox;
        private System.Windows.Forms.TextBox searchBox;
        private System.Windows.Forms.Label label5;
        private System.Windows.Forms.Label floatText;
        private System.Windows.Forms.Button open;
        private System.Windows.Forms.Button save;
        private System.Windows.Forms.Button button1;
    }
}