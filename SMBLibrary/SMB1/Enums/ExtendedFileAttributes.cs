namespace SMBLibrary.SMB1
{
    /// <summary>
    /// SMB_EXT_FILE_ATTR
    /// </summary>
    public struct ExtendedFileAttributes 
    {
        public uint Value;

        public static uint ReadOnly = 0x00000001;        // ATTR_READONLY
        public static uint Hidden = 0x00000002;          // ATTR_HIDDEN
        public static uint System = 0x00000004;          // ATTR_SYSTEM
        public static uint Directory = 0x00000010;       // ATTR_DIRECTORY
        public static uint Archive = 0x00000020;         // ATTR_ARCHIVE

        /// <summary>
        /// The file has no other attributes set. This attribute is valid only if used alone.
        /// </summary>
        public static uint Normal = 0x00000080;          // ATTR_NORMAL
        public static uint Temporary = 0x00000100;       // ATTR_TEMPORARY
        public static uint Sparse = 0x00000200;          // ATTR_SPARSE, SMB 1.0 Addition
        public static uint ReparsePoint = 0x00000400;    // ATTR_REPARSE_POINT, SMB 1.0 Addition
        public static uint Compressed = 0x00000800;      // ATTR_COMPRESSED
        public static uint Offline = 0x00001000;         // ATTR_OFFLINE, SMB 1.0 Addition
        public static uint NotIndexed = 0x00002000;      // ATTR_NOT_CONTENT_INDEXED, SMB 1.0 Addition
        public static uint Encrypted = 0x00004000;       // ATTR_ENCRYPTED, SMB 1.0 Addition
        public static uint PosixSemantics = 0x01000000;  // POSIX_SEMANTICS
        public static uint BackupSemantics = 0x02000000; // BACKUP_SEMANTICS
        public static uint DeleteOnClose = 0x04000000;   // DELETE_ON_CLOSE
        public static uint SequentialScan = 0x08000000;  // SEQUENTIAL_SCAN
        public static uint RandomAccess = 0x10000000;    // RANDOM_ACCESS
        public static uint NoBuffering = 0x10000000;     // NO_BUFFERING
        public static uint WriteThrough = 0x80000000;    // WRITE_THROUGH
        
         
        public static implicit operator ExtendedFileAttributes(uint x)
        {
            return new ExtendedFileAttributes { Value = x };
        }
        public static explicit operator uint(ExtendedFileAttributes x)
        {
            return x.Value;
        } 
        public static implicit operator ExtendedFileAttributes(FileAttributes x)
        {
            return new ExtendedFileAttributes { Value = x.Value };
        }
        public static explicit operator FileAttributes(ExtendedFileAttributes x)
        {
            return new FileAttributes { Value = x.Value};
        }
    }
}
