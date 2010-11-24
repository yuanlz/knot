#include <assert.h>
#include <stdio.h>

#include <ldns/rdata.h>

#include "zone-data-structure.h"
#include "cuckoo-hash-table.h"
#include "zone-node.h"

/*----------------------------------------------------------------------------*/

zds_zone *zds_create( uint item_count )
{
	ck_hash_table *table = ck_create_table(item_count);
    return table;
}

/*----------------------------------------------------------------------------*/

int zds_insert( zds_zone *zone, zn_node *node )
{
	assert(zn_owner(node) != NULL);
	assert(ldns_rdf_get_type(zn_owner(node)) == LDNS_RDF_TYPE_DNAME);
	return ck_insert_item(zone, (char *)ldns_rdf_data(zn_owner(node)),
						  ldns_rdf_size(zn_owner(node)), node);
}

/*----------------------------------------------------------------------------*/

zn_node *zds_find( zds_zone *zone, const ldns_rdf *owner )
{
	assert(ldns_rdf_get_type(owner) == LDNS_RDF_TYPE_DNAME);
	const ck_hash_table_item *item = ck_find_item(zone,
										(char *)ldns_rdf_data(owner),
										ldns_rdf_size(owner));
    if (item == NULL) {
        return NULL;
    }

    debug_zdb("Item found\n");

    return item->value;
}

/*----------------------------------------------------------------------------*/

int zds_remove( zds_zone *zone, ldns_rdf *owner )
{
	assert(ldns_rdf_get_type(owner) == LDNS_RDF_TYPE_DNAME);
	if (ck_remove_item(zone, (char *)ldns_rdf_data(owner), ldns_rdf_size(owner),
					   zn_destructor, 0) != 0) {
		log_info("Trying to remove non-existing item: %s\n",
				 ldns_rdf_data(owner));
		return -1;
	}
	return 0;
}

/*----------------------------------------------------------------------------*/

void zds_destroy( zds_zone **zone, void (*dtor_zone_node)( void *value ) )
{
	ck_destroy_table(zone, dtor_zone_node, 0);
}
