using System;
using System.Threading;

namespace Utilities
{
    public class CountdownLatch
    {
        private int m_count;
        private EventWaitHandle m_waitHandle = new EventWaitHandle(true, EventResetMode.ManualReset);

        public void Increment()
        {
            var count = Interlocked.Increment(ref m_count);
            if (count == 1)
            {
                m_waitHandle.Reset();
            }
        }

        public void Add(int value)
        {
            var count = Interlocked.Add(ref m_count, value);
            if (count == value)
            {
                m_waitHandle.Reset();
            }
        }

        public void Decrement()
        {
            var count = Interlocked.Decrement(ref m_count);
            if (m_count == 0)
            {
                m_waitHandle.Set();
            }
            else if (count < 0)
            {
                throw new InvalidOperationException("Count must be greater than or equal to 0");
            }
        }

        public void WaitUntilZero()
        {
            m_waitHandle.WaitOne();
        }
    }
}
