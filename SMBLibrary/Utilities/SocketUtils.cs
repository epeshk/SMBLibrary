/* Copyright (C) 2012-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * Copyright (C) 2023 Eugene Peshkov and SMBLibrary.Async contributors. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace Utilities
{
    public class SocketUtils
    {
        public static void SetKeepAlive(Socket socket, TimeSpan timeout)
        {
            // The default settings when a TCP socket is initialized sets the keep-alive timeout to 2 hours and the keep-alive interval to 1 second.
            SetKeepAlive(socket, true, timeout, TimeSpan.FromSeconds(1));
        }

        /// <param name="timeout">the timeout, in milliseconds, with no activity until the first keep-alive packet is sent</param>
        /// <param name="interval">the interval, in milliseconds, between when successive keep-alive packets are sent if no acknowledgement is received</param>
        public static void SetKeepAlive(Socket socket, bool enable, TimeSpan timeout, TimeSpan interval)
        {
            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
            
            const SocketOptionName TcpKeepAliveTimeOptionName = (SocketOptionName)3;        // SocketOptionName.TcpKeepAliveTime in .NET Core 3.0
            const SocketOptionName TcpKeepAliveIntervalOptionName = (SocketOptionName)17;   // SocketOptionName.TcpKeepAliveInterval in .NET Core 3.0
            const SocketOptionName TcpKeepAliveRetryCountOptionName = (SocketOptionName)16; // SocketOptionName.TcpKeepAliveRetryCount in .NET Core 3.0

            socket.SetSocketOption(SocketOptionLevel.Tcp, TcpKeepAliveTimeOptionName, (int)timeout.TotalSeconds);
            socket.SetSocketOption(SocketOptionLevel.Tcp, TcpKeepAliveIntervalOptionName, (int)interval.TotalSeconds);
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                // Note: TcpKeepAliveRetryCount is only supported on Windows since Windows 10 version 1709
                // For uniformity, we make cross-platform use of the same value used in earlier Windows versions 
                const int RetryCount = 10;
                socket.SetSocketOption(SocketOptionLevel.Tcp, TcpKeepAliveRetryCountOptionName, RetryCount);
            }
        }

        /// <summary>
        /// Socket will be forcefully closed and all pending data will be ignored.
        /// </summary>
        public static void ReleaseSocket(Socket socket)
        {
            if (socket != null)
            {
                if (socket.Connected)
                {
                    try
                    {
                        socket.Shutdown(SocketShutdown.Both);
                        socket.Disconnect(false);
                    }
                    catch (ObjectDisposedException)
                    {
                        return;
                    }
                    catch (SocketException)
                    {
                    }
                }
                // Closing socket closes the connection, and Close is a wrapper-method around Dispose.
                socket.Close();
            }
        }
    }
}
