#include "sinsp.h"
#include "sinsp_int.h"

#ifdef GATHER_INTERNAL_STATS
namespace internal_metrics
{

counter::~counter()
{
}

counter::counter()
{
	m_value = 0;
}

void registry::clear_all_metrics()
{
	for(metric_map_iterator_t it = get_metrics().begin(); it != get_metrics().end(); it++)
	{
		it->second->clear();
	}

}

}
#endif
