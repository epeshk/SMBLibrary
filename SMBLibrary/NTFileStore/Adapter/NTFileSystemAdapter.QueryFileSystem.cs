/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using MemoryPools.Memory;

namespace SMBLibrary
{
    public partial class NTFileSystemAdapter
    {
        public NTStatus GetFileSystemInformation(out FileSystemInformation result, FileSystemInformationClass informationClass)
        {
            switch (informationClass)
            {
                case FileSystemInformationClass.FileFsVolumeInformation:
                    {
                        var information = new FileFsVolumeInformation();
                        information.SupportsObjects = false;
                        result = information;
                        return NTStatus.STATUS_SUCCESS;
                    }
                case FileSystemInformationClass.FileFsSizeInformation:
                    {
                        var information = new FileFsSizeInformation();
                        information.TotalAllocationUnits = m_fileSystem.Size / ClusterSize;
                        information.AvailableAllocationUnits = m_fileSystem.FreeSpace / ClusterSize;
                        information.SectorsPerAllocationUnit = ClusterSize / BytesPerSector;
                        information.BytesPerSector = BytesPerSector;
                        result = information;
                        return NTStatus.STATUS_SUCCESS;
                    }
                case FileSystemInformationClass.FileFsDeviceInformation:
                    {
                        var information = new FileFsDeviceInformation();
                        information.DeviceType = DeviceType.Disk;
                        information.Characteristics = DeviceCharacteristics.IsMounted;
                        result = information;
                        return NTStatus.STATUS_SUCCESS;
                    }
                case FileSystemInformationClass.FileFsAttributeInformation:
                    {
                        var information = new FileFsAttributeInformation();
                        information.FileSystemAttributes = FileSystemAttributes.CasePreservedNamed | FileSystemAttributes.UnicodeOnDisk;
                        information.MaximumComponentNameLength = 255;
                        information.FileSystemName = Arrays.RentFrom<char>(m_fileSystem.Name);
                        result = information;
                        return NTStatus.STATUS_SUCCESS;
                    }
                case FileSystemInformationClass.FileFsControlInformation:
                    {
                        var information = new FileFsControlInformation();
                        information.FileSystemControlFlags = FileSystemControlFlags.ContentIndexingDisabled;
                        information.DefaultQuotaThreshold = UInt64.MaxValue;
                        information.DefaultQuotaLimit = UInt64.MaxValue;
                        result = information;
                        return NTStatus.STATUS_SUCCESS;
                    }
                case FileSystemInformationClass.FileFsFullSizeInformation:
                    {
                        var information = new FileFsFullSizeInformation();
                        information.TotalAllocationUnits = m_fileSystem.Size / ClusterSize;
                        information.CallerAvailableAllocationUnits = m_fileSystem.FreeSpace / ClusterSize;
                        information.ActualAvailableAllocationUnits = m_fileSystem.FreeSpace / ClusterSize;
                        information.SectorsPerAllocationUnit = ClusterSize / BytesPerSector;
                        information.BytesPerSector = BytesPerSector;
                        result = information;
                        return NTStatus.STATUS_SUCCESS;
                    }
                case FileSystemInformationClass.FileFsObjectIdInformation:
                    {
                        result = null;
                        // STATUS_INVALID_PARAMETER is returned when the file system does not implement object IDs
                        // See: https://msdn.microsoft.com/en-us/library/cc232106.aspx
                        return NTStatus.STATUS_INVALID_PARAMETER;
                    }
                case FileSystemInformationClass.FileFsSectorSizeInformation:
                    {
                        var information = new FileFsSectorSizeInformation();
                        information.LogicalBytesPerSector = BytesPerSector;
                        information.PhysicalBytesPerSectorForAtomicity = BytesPerSector;
                        information.PhysicalBytesPerSectorForPerformance = BytesPerSector;
                        information.FileSystemEffectivePhysicalBytesPerSectorForAtomicity = BytesPerSector;
                        information.ByteOffsetForSectorAlignment = 0;
                        information.ByteOffsetForPartitionAlignment = 0;
                        result = information;
                        return NTStatus.STATUS_SUCCESS;
                    }
                default:
                    {
                        result = null;
                        return NTStatus.STATUS_INVALID_INFO_CLASS;
                    }
            }
        }

        public NTStatus SetFileSystemInformation(FileSystemInformation information)
        {
            return NTStatus.STATUS_NOT_SUPPORTED;
        }
    }
}
