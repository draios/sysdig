#pragma once

#include <algorithm>
#include <memory>
#include <array>

#include <cstdint>
#include <cstring>
#include <cassert>

template<class V, std::size_t N> class radix_leaf;
template<class T, class V, std::size_t N> class radix_tree;

template<class V> class radix_accessor {
public:
	typedef V value_type;

	static inline V get(V val) { return val; }
	static inline void set(V& dst, V src) { dst = src; }
	static inline V nil() { return V(); }
	static inline void del(V& val) { }

	static const bool explicit_delete = false;
};

template<class V> class radix_accessor<V*> {
public:
	typedef V *value_type;

	static inline V* get(V* val) { return val; }
	static inline void set(V*& dst, V* src) {
		delete dst;
		dst = src;
	}
	static inline V* nil() { return nullptr; }
	static inline void del(V*& val) { delete val; }

	static const bool explicit_delete = true;
};

template<class V> class radix_accessor<unique_ptr<V>> {
public:
	typedef V *value_type;

	static inline V* get(unique_ptr<V>& val) { return val.get(); }
	static inline void set(unique_ptr<V>& dst, V* src) { dst.reset(src); }
	static inline V* nil() { return nullptr; }
	static inline void del(unique_ptr<V>& val) { }

	static const bool explicit_delete = false;
};


template<class T, class V> class radix_iterator {
public:
	typedef std::pair<uint64_t, typename radix_accessor<V>::value_type> pair_t;

	radix_iterator(T* arr, uint64_t idx) : m_idx(idx), m_arr(arr)
	{
	}

	radix_iterator& operator++()
	{
		m_idx = m_arr->skip_nulls(m_idx + 1);
		return *this;
	}

	pair_t operator*()
	{
		return std::make_pair(m_idx, (*m_arr)[m_idx]);
	}

	bool operator==(const radix_iterator& other)
	{
		return m_idx == other.m_idx && m_arr == other.m_arr;
	}

	bool operator!=(const radix_iterator& other)
	{
		return !(*this == other);
	}

private:
	uint64_t m_idx;
	T *m_arr;
};

template<class T, class V> class radix_value_iterator {
public:
	radix_value_iterator(T* arr, uint64_t idx) : m_idx(idx), m_arr(arr)
	{
	}

	radix_value_iterator& operator++()
	{
		m_idx = m_arr->skip_nulls(m_idx + 1);
		return *this;
	}

	typename radix_accessor<V>::value_type operator*()
	{
		return (*m_arr)[m_idx];
	}

	typename radix_accessor<V>::value_type operator->()
	{
		return (*m_arr)[m_idx];
	}

	bool operator==(const radix_value_iterator& other)
	{
		return m_idx == other.m_idx && m_arr == other.m_arr;
	}

	bool operator!=(const radix_value_iterator& other)
	{
		return !(*this == other);
	}

private:
	uint64_t m_idx;
	T *m_arr;
};

template<class V, std::size_t N> class radix_leaf {
	static_assert(N > 0, "size must be positive");
public:
	typedef radix_leaf<V, N> myself_t;
	typedef radix_iterator<myself_t, V> iterator;
	typedef radix_value_iterator<myself_t, V> value_iterator;
	typedef typename radix_accessor<V>::value_type value_type;

	radix_leaf()
	{
		m_elts = new V[N];
		init();
	}

	radix_leaf(const radix_leaf& other) = delete;
	radix_leaf& operator=(const radix_leaf& other) = delete;

	~radix_leaf()
	{
		destruct();
		delete[] m_elts;
	}

	void clear()
	{
		destruct();
		init();
	}

	value_type operator[] (uint64_t i) const
	{
		return radix_accessor<V>::get(m_elts[i]);
	}

	V& ref(uint64_t i)
	{
		return m_elts[i];
	}

	bool insert(uint64_t i, value_type val)
	{
		auto& elt = m_elts[i];
		bool inserted = false;
		if (!elt)
		{
			++m_count;
			inserted = true;
		}
		radix_accessor<V>::set(elt, val);
		return inserted;
	}

	bool erase(uint64_t i)
	{
		auto& elt = m_elts[i];
		bool deleted = false;
		if (elt)
		{
			--m_count;
			deleted = true;
		}
		radix_accessor<V>::set(elt, radix_accessor<V>::nil());
		return deleted;
	}

	bool empty() const
	{
		return m_count == 0;
	}

	uint64_t size() const
	{
		return m_count;
	}

	static constexpr uint64_t max_size()
	{
		return N;
	}

	iterator pairs_begin()
	{
		return iterator(this, skip_nulls(0));
	}

	iterator pairs_end()
	{
		return iterator(this, max_size());
	}

	value_iterator begin()
	{
		return value_iterator(this, skip_nulls(0));
	}

	value_iterator end()
	{
		return value_iterator(this, max_size());
	}

	uint64_t skip_nulls(uint64_t idx)
	{
		while(idx < max_size() && !m_elts[idx]) {
			++idx;
		}
		return idx;
	}

private:
	void init()
	{
		m_count = 0;
		memset(m_elts, 0, N * sizeof(V));
	}

	void destruct()
	{
		if (radix_accessor<V>::explicit_delete)
		{
			for (auto i=0; i<N; ++i)
			{
				radix_accessor<V>::del(m_elts[i]);
			}
		}
	}

	size_t m_count;
	V* m_elts;
};

template<class T, class V, std::size_t N> class radix_tree {
	static_assert(N > 0, "size must be positive");
	static_assert(N * T::max_size() > N, "size must not overflow");
public:
	typedef radix_tree<T, V, N> myself_t;
	typedef radix_iterator<myself_t, V> iterator;
	typedef radix_value_iterator<myself_t, V> value_iterator;
	typedef typename radix_accessor<V>::value_type value_type;

	radix_tree()
	{
		m_elts = new T*[N];
		init();
	}

	radix_tree(const radix_tree& other) = delete;
	radix_tree& operator=(const radix_tree& other) = delete;

	~radix_tree()
	{
		destruct();
		delete[] m_elts;
	}

	void clear()
	{
		destruct();
		init();
	}

	value_type operator[] (uint64_t i) const
	{
		const T* b = m_elts[i / T::max_size()];
		if (b)
		{
			return (*b)[i % T::max_size()];
		} else {
			return radix_accessor<V>::nil();
		}
	}

	V& ref(uint64_t i)
	{
		T* b = m_elts[i / T::max_size()];
		if (!b)
		{
			b = m_elts[i / T::max_size()] = new T;
		}
		return b->ref(i % T::max_size());
	}

	bool insert(uint64_t i, value_type val)
	{
		T* b = m_elts[i / T::max_size()];
		if (!b)
		{
			b = m_elts[i / T::max_size()] = new T;
		}
		bool inserted = b->insert(i % T::max_size(), val);
		if (inserted)
		{
			m_count++;
		}
		return inserted;
	}

	bool erase(uint64_t i)
	{
		T* b = m_elts[i / T::max_size()];
		bool deleted = false;
		if (b)
		{
			deleted = b->erase(i % T::max_size());
			if (b->empty())
			{
				delete m_elts[i / T::max_size()];
				m_elts[i / T::max_size()] = nullptr;
			}
		}
		if (deleted)
		{
			m_count--;
		}
		return deleted;
	}

	bool empty() const
	{
		return m_count == 0;
	}

	uint64_t size() const
	{
		return m_count;
	}

	static constexpr uint64_t max_size()
	{
		return N * T::max_size();
	}

	iterator pairs_begin()
	{
		return iterator(this, skip_nulls(0));
	}

	iterator pairs_end()
	{
		return iterator(this, max_size());
	}

	value_iterator begin()
	{
		return value_iterator(this, skip_nulls(0));
	}

	value_iterator end()
	{
		return value_iterator(this, max_size());
	}

	uint64_t skip_nulls(uint64_t idx)
	{
		uint64_t bidx = idx / T::max_size();
		uint64_t off = idx % T::max_size();

		while (bidx < N) {
			T *b = m_elts[bidx];
			if (b && !b->empty()) {
				off = b->skip_nulls(off);
				if (off != b->max_size())
					return bidx * T::max_size() + off;
			}
			off = 0;
			bidx++;
		}

		return max_size();
	}


private:
	void init()
	{
		m_count = 0;
		memset(m_elts, 0, N * sizeof(T*));
	}

	void destruct()
	{
		for (auto i=0; i<N; ++i)
		{
			if (m_elts[i])
			{
				m_elts[i]->clear();
			}
		}
	}

	T* bucket(uint64_t i)
	{
		return m_elts[i / T::max_size()];
	}

	const T* bucket(uint64_t i) const
	{
		return m_elts[i / T::max_size()];
	}

	uint64_t m_count;
	T** m_elts;
};


template <class T> using radix_tree_8 = radix_leaf<T, 256>;
template <class T> using radix_tree_16 = radix_tree<radix_tree_8<T>, T, 256>;
template <class T> using radix_tree_24 = radix_tree<radix_tree_16<T>, T, 256>;
template <class T> using radix_tree_32 = radix_tree<radix_tree_24<T>, T, 256>;
