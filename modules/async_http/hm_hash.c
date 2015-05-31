#include "hm_hash.h"

extern int hash_size;

/*!
 * \brief Initialize the global http multi table
 * \param size size of the table
 * \return 0 on success, -1 on failure
 */
int init_http_m_table(unsigned int size)
{
	unsigned int i;

	hm_table = (struct http_m_table*)shm_malloc
		( sizeof(struct http_m_table) + size*sizeof(struct http_m_entry) );
	if (hm_table==0) {
		LM_ERR("no more shm mem\n");
		return -1;
	}

	memset( hm_table, 0, sizeof(struct http_m_table) );
	hm_table->size = size;
	hm_table->entries = (struct http_m_entry*)(hm_table+1);

	for( i=0 ; i<size; i++ ) {
		memset( &(hm_table->entries[i]), 0, sizeof(struct http_m_entry) );
	}

	LM_DBG("hash table %p initialized with size %d", hm_table, size);
	return 0;
}
unsigned int build_hash_key(void *p)
{
	str			*hash_str;
	char		*pointer_str;
	int			len;

	unsigned int hash;

	pointer_str = (char *)pkg_malloc(sizeof(p) + 1);

	if (pointer_str==0) {
		LM_ERR("no more pkg mem\n");
		return 0;
	}

	sprintf(pointer_str, "%p", p);
	len = strlen(pointer_str);
	LM_DBG("received id %p (%d)-> %s (%d)", p, (int)sizeof(p), pointer_str, len);

	hash_str = (str *)pkg_malloc(sizeof(str));
	if (hash_str==0) {
		LM_ERR("no more pkg mem\n");
		pkg_free(pointer_str);
		return 0;
	}
	hash_str->s = pointer_str;
	hash_str->len = len;

	hash = core_hash(hash_str, 0, hash_size);

	LM_DBG("hash for %p is %d", p, hash);

	pkg_free(pointer_str);
	pkg_free(hash_str);

	return hash;

}

struct http_m_cell* build_http_m_cell(void *p)
{
	struct http_m_cell *cell= NULL;
	int len;

	len = sizeof(struct http_m_cell);
	cell = (struct http_m_cell*)shm_malloc(len);
	if (cell==0) {
		LM_ERR("no more shm mem\n");
		return 0;
	}

	memset( cell, 0, len);

	cell->hmt_entry = build_hash_key(p);
	cell->easy = p;

	LM_DBG("hash id for %p is %d", p, cell->hmt_entry);

	return cell;
}

void link_http_m_cell(struct http_m_cell *cell)
{
	struct http_m_entry *hmt_entry;

	hmt_entry = &(hm_table->entries[cell->hmt_entry]);

	LM_DBG("linking new cell %p to table %p [%u]\n", cell, hm_table, cell->hmt_entry);
	if (hmt_entry->first==0) {
		hmt_entry->first = cell;
		hmt_entry->first = hmt_entry->last = cell;
	}
	else {
		hmt_entry->last->next = cell;
		cell->prev = hmt_entry->last;
		hmt_entry->last = cell;
	}

	return;
}

struct http_m_cell *http_m_cell_lookup(CURL *p)
{
	struct http_m_entry	*hmt_entry;
	struct http_m_cell	*current_cell;

	unsigned int		entry_idx;

	entry_idx = build_hash_key(p);

	hmt_entry = &(hm_table->entries[entry_idx]);

	for (current_cell = hmt_entry->first; current_cell; current_cell = current_cell->next) {
		if (current_cell->easy == p) {
			LM_DBG("http_m_cell with easy=%p found on table entry %u", p, entry_idx);
			return current_cell;
		}
	}

	/* not found */
	LM_DBG("No http_m_cell with easy=%p found on table entry %u", p, entry_idx);
	return 0;
}

