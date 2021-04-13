namespace SMBLibrary
{
    /// <summary>
    /// [MS-FSCC] 2.6 - FileAttributes 
    /// </summary>
    public struct FileAttributes
    {
        public uint Value;
        
        public static uint ReadOnly = 0x00000001;          // FILE_ATTRIBUTE_READONLY
        public static uint Hidden = 0x00000002;            // FILE_ATTRIBUTE_HIDDEN
        public static uint System = 0x00000004;            // FILE_ATTRIBUTE_SYSTEM
        public static uint Directory = 0x00000010;         // FILE_ATTRIBUTE_DIRECTORY
        public static uint Archive = 0x00000020;           // FILE_ATTRIBUTE_ARCHIVE
        
        /// <summary>
        /// A file that does not have other attributes set.
        /// This attribute is valid only when used alone.
        /// </summary>
        public static uint Normal = 0x00000080;            // FILE_ATTRIBUTE_NORMAL
        public static uint Temporary = 0x00000100;         // FILE_ATTRIBUTE_TEMPORARY
        public static uint SparseFile = 0x00000200;        // FILE_ATTRIBUTE_SPARSE_FILE
        public static uint ReparsePoint = 0x00000400;      // FILE_ATTRIBUTE_REPARSE_POINT
        public static uint Compressed = 0x00000800;        // FILE_ATTRIBUTE_COMPRESSED
        public static uint Offline = 0x00001000;           // FILE_ATTRIBUTE_OFFLINE
        public static uint NotContentIndexed = 0x00002000; // FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
        public static uint Encrypted = 0x00004000;         // FILE_ATTRIBUTE_ENCRYPTED
        public static uint IntegrityStream = 0x00008000;   // FILE_ATTRIBUTE_INTEGRITY_STREAM
        public static uint NoScrubData = 0x00020000;       // FILE_ATTRIBUTE_NO_SCRUB_DATA
        
        public static implicit operator FileAttributes(uint x)
        {
            return new FileAttributes { Value = x };
        }
        public static explicit operator uint(FileAttributes counter)
        {
            return counter.Value;
        }
    }
}
