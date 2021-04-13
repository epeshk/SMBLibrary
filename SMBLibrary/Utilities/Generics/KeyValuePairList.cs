using System.Collections.Generic;
using System.ComponentModel;

namespace Utilities
{
    public class KeyValuePairList<TKey, TValue> : List<KeyValuePair<TKey, TValue>>
    {
        public KeyValuePairList()
        {
        }

        public KeyValuePairList(List<KeyValuePair<TKey, TValue>> collection) : base(collection)
        {
        }

        public bool ContainsKey(TKey key)
        {
            return (IndexOfKey(key) != -1);
        }

        public int IndexOfKey(TKey key)
        {
            for (var index = 0; index < Count; index++)
            {
                if (this[index].Key.Equals(key))
                {
                    return index;
                }
            }

            return -1;
        }

        public TValue ValueOf(TKey key)
        {
            for (var index = 0; index < Count; index++)
            {
                if (this[index].Key.Equals(key))
                {
                    return this[index].Value;
                }
            }

            return default;
        }

        public void Add(TKey key, TValue value)
        {
            Add(new KeyValuePair<TKey, TValue>(key, value));
        }

        public List<TKey> Keys
        {
            get
            {
                var result = new List<TKey>();
                for (var index = 0; index < Count; index++)
                {
                    var entity = this[index];
                    result.Add(entity.Key);
                }

                return result;
            }
        }

        public List<TValue> Values
        {
            get
            {
                var result = new List<TValue>();
                for (var index = 0; index < Count; index++)
                {
                    var entity = this[index];
                    result.Add(entity.Value);
                }

                return result;
            }
        }

        new public void Sort()
        {
            Sort(Comparer<TKey>.Default);
        }

        public void Sort(ListSortDirection sortDirection)
        {
            Sort(Comparer<TKey>.Default, sortDirection);
        }

        public void Sort(IComparer<TKey> comparer, ListSortDirection sortDirection)
        {
            if (sortDirection == ListSortDirection.Ascending)
            {
                Sort(comparer);
            }
            else
            {
                Sort(new ReverseComparer<TKey>(comparer));
            }
        }

        public void Sort(IComparer<TKey> comparer)
        {
            Sort(delegate(KeyValuePair<TKey, TValue> a, KeyValuePair<TKey, TValue> b)
            {
                return comparer.Compare(a.Key, b.Key);
            });
        }

        public new KeyValuePairList<TKey, TValue> GetRange(int index, int count)
        {
            return new KeyValuePairList<TKey, TValue>(base.GetRange(index, count));
        }
    }
}
