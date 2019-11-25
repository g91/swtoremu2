using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

namespace TorLib
{
    /// <summary>
    /// Class used to manage a single .tor file
    /// </summary>
    public class Archive
    {
        private Dictionary<ulong, FileInfo> fileLookup = new Dictionary<ulong, FileInfo>();

        internal Library Library { get; set; }
        public string FileName { get; set; }
        public bool Initialized { get; private set; }

        public File FindFile(FileId fileId)
        {
            return FindFile(fileId.AsUInt64());
        }

        public File FindFile(ulong fileId)
        {
            if (!Initialized) { this.Initialize(); }

            FileInfo fileInfo;

            if (!fileLookup.TryGetValue(fileId, out fileInfo))
            {
                return null;
            }

            File file = new File();
            file.Archive = this;
            file.FileInfo = fileInfo;

            return file;
        }

        internal FileStream OpenStreamAt(long offset)
        {
            var fs = System.IO.File.Open(this.FileName, FileMode.Open, FileAccess.Read, FileShare.Read);
            fs.Seek(offset, SeekOrigin.Begin);
            return fs;
        }

        internal FileStream OpenStream(FileInfo fileInfo)
        {
            var offset = fileInfo.Offset + fileInfo.HeaderSize;
            return OpenStreamAt(offset);
        }

        /// <summary>Load file tables and fill-in fileLookup dictionary</summary>
        private void Initialize()
        {
            this.Initialized = true;

            using (var fs = this.OpenStreamAt(0))
            using (var reader = new BinaryReader(fs))
            {
                int magicNumber = reader.ReadInt32();
                if (magicNumber != 0x50594D) {
                    throw new InvalidOperationException("Wait a minute! " + this.FileName + " isn't a MYP file!");
                }

                fs.Seek(12, SeekOrigin.Begin);
                long fileTableOffset = reader.ReadInt64();
                while (fileTableOffset != 0)
                {
                    fs.Seek(fileTableOffset, SeekOrigin.Begin);

                    int numFiles = reader.ReadInt32();
                    fileTableOffset = reader.ReadInt64();

                    for (var i = 0; i < numFiles; i++)
                    {
                        // Read file info blocks
                        FileInfo info = new FileInfo();
                        info.Offset = reader.ReadInt64();
                        if (info.Offset == 0)
                        {
                            // No file offset, no file -- skip this entry and try the next one
                            fs.Seek(26, SeekOrigin.Current);
                            continue;
                        }

                        info.HeaderSize = reader.ReadInt32();
                        info.CompressedSize = reader.ReadUInt32();
                        info.UncompressedSize = reader.ReadUInt32();
                        info.FileId = reader.ReadUInt64();
                        info.Checksum = reader.ReadUInt32();
                        info.CompressionMethod = reader.ReadInt16();

                        this.fileLookup.Add(info.FileId, info);
                    }
                }
            }
        }
    }
}
