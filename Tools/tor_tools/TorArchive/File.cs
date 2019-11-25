using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using ICSharpCode.SharpZipLib.Zip.Compression.Streams;

namespace TorLib
{
    public class FileInfo
    {
        public long Offset { get; set; }
        public int HeaderSize { get; set; }
        public uint CompressedSize { get; set; }
        public uint UncompressedSize { get; set; }
        public ulong FileId { get; set; }
        /// <summary>CRC32 checksum</summary>
        public uint Checksum { get; set; }
        public short CompressionMethod { get; set; }
        public bool IsCompressed { get { return this.CompressionMethod != 0; } }
    }

    /// <summary>A file stored in a .tor archive</summary>
    public class File
    {
        public Archive Archive { get; set; }
        public FileInfo FileInfo { get; set; }
        public string FilePath { get; set; }

        public Stream Open()
        {
            //var archiveStream = this.Archive.OpenStreamAt(this.FileInfo.Offset);
            var archiveStream = this.Archive.OpenStreamAt(this.FileInfo.Offset + this.FileInfo.HeaderSize);

            if (this.FileInfo.IsCompressed)
            {
                // Wrap stream in a a sharpziplib inflater
                var inflaterStream = new InflaterInputStream(archiveStream);
                return inflaterStream;
            }
            else
            {
                return archiveStream;
            }
        }

        public Stream OpenCopyInMemory()
        {
            var fs = Open();
            var buffer = new byte[this.FileInfo.UncompressedSize];
            var memStream = new MemoryStream(buffer);
            fs.CopyTo(memStream);
            memStream.Position = 0;
            return memStream;
        }
    }
}
