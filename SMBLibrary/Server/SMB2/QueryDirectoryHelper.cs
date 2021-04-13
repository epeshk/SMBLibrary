/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using MemoryPools.Memory;
using SMBLibrary.Client;
using SMBLibrary.SMB2;
using Utilities;

namespace SMBLibrary.Server.SMB2
{
    internal class QueryDirectoryHelper
    {
        internal static SMB2Command GetQueryDirectoryResponse(QueryDirectoryRequest request, ISMBShare share, SMB2ConnectionState state)
        {
            var session = state.GetSession(request.Header.SessionId);
            var openFile = session.GetOpenFileObject(request.FileId);
            if (openFile == null)
            {
                state.LogToServer(Severity.Verbose, "Query Directory failed. Invalid FileId. (SessionID: {0}, TreeID: {1}, FileId: {2})", request.Header.SessionId, request.Header.TreeId, request.FileId.Volatile);
                return ObjectsPool<ErrorResponse>.Get().Init(request.CommandName, NTStatus.STATUS_FILE_CLOSED);
            }

            if (!((FileSystemShare)share).HasReadAccess(session.SecurityContext, openFile.Path))
            {
                state.LogToServer(Severity.Verbose, "Query Directory on '{0}{1}' failed. User '{2}' was denied access.", share.Name, openFile.Path, session.UserName);
                return ObjectsPool<ErrorResponse>.Get().Init(request.CommandName, NTStatus.STATUS_ACCESS_DENIED);
            }

            var fileSystemShare = (FileSystemShare)share;

            var fileID = request.FileId;
            var openSearch = session.GetOpenSearch(fileID);
            if (openSearch == null || request.Reopen)
            {
                if (request.Reopen)
                {
                    session.RemoveOpenSearch(fileID);
                }
                List<FindFilesQueryResult> entries;
                var searchStatus = share.FileStore.QueryDirectory(out entries, openFile.Handle, request.FileName, request.FileInformationClass);
                if (searchStatus != NTStatus.STATUS_SUCCESS)
                {
                    state.LogToServer(Severity.Verbose, "Query Directory on '{0}{1}', Searched for '{2}', NTStatus: {3}", share.Name, openFile.Path, request.FileName, searchStatus.ToString());
                    return ObjectsPool<ErrorResponse>.Get().Init(request.CommandName, searchStatus);
                }
                state.LogToServer(Severity.Information, "Query Directory on '{0}{1}', Searched for '{2}', found {3} matching entries", share.Name, openFile.Path, request.FileName, entries.Count);
                openSearch = session.AddOpenSearch(fileID, entries, 0);
            }

            if (request.Restart || request.Reopen)
            {
                openSearch.EnumerationLocation = 0;
            }

            if (openSearch.Entries.Count == 0)
            {
                // [MS-SMB2] If there are no entries to return [..] the server MUST fail the request with STATUS_NO_SUCH_FILE.
                session.RemoveOpenSearch(fileID);
                return ObjectsPool<ErrorResponse>.Get().Init(request.CommandName, NTStatus.STATUS_NO_SUCH_FILE);
            }

            if (openSearch.EnumerationLocation == openSearch.Entries.Count)
            {
                return ObjectsPool<ErrorResponse>.Get().Init(request.CommandName, NTStatus.STATUS_NO_MORE_FILES);
            }

            var page = new List<QueryDirectoryFileInformation>();
            var pageLength = 0;
            for (var index = openSearch.EnumerationLocation; index < openSearch.Entries.Count; index++)
            {
                var fileInformation = openSearch.Entries[index];
                
                throw new NotImplementedException();
                // if (fileInformation.FileInformationClass != request.FileInformationClass)
                // {
                //     // We do not support changing FileInformationClass during a search (unless SMB2_REOPEN is set).
                //     return ObjectsPool<ErrorResponse>.Get().Init(request.CommandName, NTStatus.STATUS_INVALID_PARAMETER);
                // }
                //
                // var entryLength = fileInformation.Length;
                // if (pageLength + entryLength <= request.OutputBufferLength)
                // {
                //     page.Add(fileInformation);
                //     var paddedLength = (int)Math.Ceiling((double)entryLength / 8) * 8;
                //     pageLength += paddedLength;
                //     openSearch.EnumerationLocation = index + 1;
                // }
                // else
                // {
                //     break;
                // }
                //
                // if (request.ReturnSingleEntry)
                // {
                //     break;
                // }
            }
            
            var response = new QueryDirectoryResponse();
            response.SetFileInformationList(page);
            return response;
        }
    }
}
