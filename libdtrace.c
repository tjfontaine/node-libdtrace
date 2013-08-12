/*
 * For whatever reason, g++ on Solaris defines _XOPEN_SOURCE -- which in
 * turn will prevent us from pulling in our desired definition for boolean_t.
 * We don't need it, so explicitly undefine it.
 */
#ifdef _XOPEN_SOURCE
#undef _XOPEN_SOURCE
#endif

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include "shim.h"

/*
 * Sadly, libelf refuses to compile if _FILE_OFFSET_BITS has been manually
 * jacked to 64 on a 32-bit compile.  In this case, we just manually set it
 * back to 32.
 */
#if defined(_ILP32) && (_FILE_OFFSET_BITS != 32)
#undef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 32
#endif

#include <dtrace.h>

/*
 * This is a tad unsightly:  if we didn't find the definition of the
 * llquantize() aggregating action, we're going to redefine it here (along
 * with its support cast of macros).  This allows node-libdtrace to operate
 * on a machine that has llquantize(), even if it was compiled on a machine
 * without the support.
 */
#ifndef DTRACEAGG_LLQUANTIZE

#define	DTRACEAGG_LLQUANTIZE			(DTRACEACT_AGGREGATION + 9)

#define	DTRACE_LLQUANTIZE_FACTORSHIFT		48
#define	DTRACE_LLQUANTIZE_FACTORMASK		((uint64_t)UINT16_MAX << 48)
#define	DTRACE_LLQUANTIZE_LOWSHIFT		32
#define	DTRACE_LLQUANTIZE_LOWMASK		((uint64_t)UINT16_MAX << 32)
#define	DTRACE_LLQUANTIZE_HIGHSHIFT		16
#define	DTRACE_LLQUANTIZE_HIGHMASK		((uint64_t)UINT16_MAX << 16)
#define	DTRACE_LLQUANTIZE_NSTEPSHIFT		0
#define	DTRACE_LLQUANTIZE_NSTEPMASK		UINT16_MAX

#define DTRACE_LLQUANTIZE_FACTOR(x)             \
	(uint16_t)(((x) & DTRACE_LLQUANTIZE_FACTORMASK) >> \
	DTRACE_LLQUANTIZE_FACTORSHIFT)

#define DTRACE_LLQUANTIZE_LOW(x)                \
        (uint16_t)(((x) & DTRACE_LLQUANTIZE_LOWMASK) >> \
        DTRACE_LLQUANTIZE_LOWSHIFT)

#define DTRACE_LLQUANTIZE_HIGH(x)               \
        (uint16_t)(((x) & DTRACE_LLQUANTIZE_HIGHMASK) >> \
        DTRACE_LLQUANTIZE_HIGHSHIFT)

#define DTRACE_LLQUANTIZE_NSTEP(x)              \
        (uint16_t)(((x) & DTRACE_LLQUANTIZE_NSTEPMASK) >> \
        DTRACE_LLQUANTIZE_NSTEPSHIFT)
#endif

typedef struct agg_baton_s {
  shim_ctx_t* ctx;
  shim_val_t* cb;
  dtrace_hdl_t* handle;
} agg_baton_t;

void
weak_cb(shim_val_t* val, void* data)
{
/* TODO
	if (dtc_ranges != NULL)
		delete [] dtc_ranges;
*/

  printf("external has been reaped\n");

  agg_baton_t* baton = (agg_baton_t*)data;

	dtrace_hdl_t *dtp = baton->handle;

	dtrace_close(dtp);

  shim_persistent_dispose(val);
  shim_persistent_dispose(baton->cb);

  free(baton);
}

shim_val_t*
probedesc(shim_ctx_t* ctx, const dtrace_probedesc_t *pd)
{
  shim_val_t* probe = shim_obj_new(ctx, NULL, NULL);
	shim_obj_set_prop_name(ctx, probe, "provider",
    shim_string_new_copy(ctx, pd->dtpd_provider));
	shim_obj_set_prop_name(ctx, probe, "module",
    shim_string_new_copy(ctx, pd->dtpd_mod));
	shim_obj_set_prop_name(ctx, probe, "function",
    shim_string_new_copy(ctx, pd->dtpd_func));
	shim_obj_set_prop_name(ctx, probe, "name",
    shim_string_new_copy(ctx, pd->dtpd_name));

	return (probe);
}

int
_bufhandler(const dtrace_bufdata_t *bufdata, void *arg)
{
	dtrace_probedata_t *data = bufdata->dtbda_probe;
	const dtrace_recdesc_t *rec = bufdata->dtbda_recdesc;
	agg_baton_t* dtc = (agg_baton_t *)arg;
  shim_ctx_t* ctx = dtc->ctx;

	if (rec == NULL || rec->dtrd_action != DTRACEACT_PRINTF)
		return (DTRACE_HANDLE_OK);

  shim_val_t* probe = probedesc(ctx, data->dtpda_pdesc);
  shim_val_t* record = shim_obj_new(ctx, NULL, NULL);
	shim_obj_set_prop_name(ctx, record, "data",
    shim_string_new_copy(ctx, bufdata->dtbda_buffered));
	shim_val_t* argv[2] = { probe, record };

  shim_val_t* rval = malloc(sizeof(shim_val_t*));
  shim_func_call_val(ctx, NULL, dtc->cb, 2, argv, rval);
  shim_value_release(rval);

	return (DTRACE_HANDLE_OK);
}

int
Consumer(shim_ctx_t* ctx, shim_args_t *args)
{
	int err;
	dtrace_hdl_t *dtp;

	if ((dtp = dtrace_open(DTRACE_VERSION, 0, &err)) == NULL)
  {
    shim_throw_error(ctx, dtrace_errmsg(NULL, err));
    return FALSE;
  }

	/*
	 * Set our buffer size and aggregation buffer size to the de facto
	 * standard of 4M.
	 */
	(void) dtrace_setopt(dtp, "bufsize", "4m");
	(void) dtrace_setopt(dtp, "aggsize", "4m");

  agg_baton_t* baton = malloc(sizeof(agg_baton_t));

  shim_val_t* cb = shim_args_get(args, 0);

  baton->ctx = ctx;
  baton->handle = dtp;
  baton->cb = shim_persistent_new(ctx, cb);

	if (dtrace_handle_buffered(dtp, _bufhandler, baton) == -1)
  {
    shim_throw_error(ctx, dtrace_errmsg(dtp, dtrace_errno(dtp)));
    return FALSE;
  }

/* TODO
	dtc_ranges = NULL;
*/

  shim_val_t* external = shim_external_new(ctx, dtp);
  shim_val_t* pexternal = shim_persistent_new(ctx, external);
  shim_obj_make_weak(ctx, pexternal, baton, weak_cb);

  shim_args_set_rval(ctx, args, external);

  return TRUE;
};

const char *
_action(const dtrace_recdesc_t *rec, char *buf, int size)
{
	static struct {
		dtrace_actkind_t action;
		const char *name;
	} act[] = {
		{ DTRACEACT_NONE,	"<none>" },
		{ DTRACEACT_DIFEXPR,	"<DIF expression>" },
		{ DTRACEACT_EXIT,	"exit()" },
		{ DTRACEACT_PRINTF,	"printf()" },
		{ DTRACEACT_PRINTA,	"printa()" },
		{ DTRACEACT_LIBACT,	"<library action>" },
		{ DTRACEACT_USTACK,	"ustack()" },
		{ DTRACEACT_JSTACK,	"jstack()" },
		{ DTRACEACT_USYM,	"usym()" },
		{ DTRACEACT_UMOD,	"umod()" },
		{ DTRACEACT_UADDR,	"uaddr()" },
		{ DTRACEACT_STOP,	"stop()" },
		{ DTRACEACT_RAISE,	"raise()" },
		{ DTRACEACT_SYSTEM,	"system()" },
		{ DTRACEACT_FREOPEN,	"freopen()" },
		{ DTRACEACT_STACK,	"stack()" },
		{ DTRACEACT_SYM,	"sym()" },
		{ DTRACEACT_MOD,	"mod()" },
		{ DTRACEAGG_COUNT,	"count()" },
		{ DTRACEAGG_MIN,	"min()" },
		{ DTRACEAGG_MAX,	"max()" },
		{ DTRACEAGG_AVG,	"avg()" },
		{ DTRACEAGG_SUM,	"sum()" },
		{ DTRACEAGG_STDDEV,	"stddev()" },
		{ DTRACEAGG_QUANTIZE,	"quantize()" },
		{ DTRACEAGG_LQUANTIZE,	"lquantize()" },
		{ DTRACEAGG_LLQUANTIZE,	"llquantize()" },
		{ DTRACEACT_NONE,	NULL },
	};

	dtrace_actkind_t action = rec->dtrd_action;
	int i;

	for (i = 0; act[i].name != NULL; i++) {
		if (act[i].action == action)
			return (act[i].name);
	}

	(void) snprintf(buf, size, "<unknown action 0x%x>", action);

	return (buf);
}

void
_error(shim_ctx_t* ctx, const char *fmt, ...)
{
	char buf[1024], buf2[1024];
	char *err = buf;
	va_list ap;

	va_start(ap, fmt);
	(void) vsnprintf(buf, sizeof (buf), fmt, ap);

	if (buf[strlen(buf) - 1] != '\n') {
		/*
		 * If our error doesn't end in a new-line, we'll append the
		 * strerror of errno.
		 */
		(void) snprintf(err = buf2, sizeof (buf2),
		    "%s: %s", buf, strerror(errno));
	} else {
		buf[strlen(buf) - 1] = '\0';
	}

	shim_throw_error(ctx, err);
}

shim_val_t*
_badarg(shim_ctx_t* ctx, const char *msg)
{
	return (shim_string_new_copy(ctx, msg));
}

int
_valid(const dtrace_recdesc_t *rec)
{
	dtrace_actkind_t action = rec->dtrd_action;

	switch (action) {
	case DTRACEACT_DIFEXPR:
	case DTRACEACT_SYM:
	case DTRACEACT_MOD:
	case DTRACEACT_USYM:
	case DTRACEACT_UMOD:
	case DTRACEACT_UADDR:
		return (B_TRUE);

	default:
		return (B_FALSE);
	}
}

shim_val_t*
_record(const dtrace_recdesc_t *rec, caddr_t addr, agg_baton_t* dtp, shim_ctx_t* ctx)
{
	switch (rec->dtrd_action) {
	case DTRACEACT_DIFEXPR:
		switch (rec->dtrd_size) {
		case sizeof (uint64_t):
			return (shim_number_new(ctx, *((int64_t *)addr)));
      break;
		case sizeof (uint32_t):
			return (shim_number_new(ctx, *((int32_t *)addr)));
      break;
		case sizeof (uint16_t):
			return (shim_number_new(ctx, *((uint16_t *)addr)));
      break;
		case sizeof (uint8_t):
			return (shim_number_new(ctx, *((uint8_t *)addr)));
      break;
		default:
			return (shim_string_new_copy(dtp->ctx, (const char *)addr));
      break;
		}
    break;

	case DTRACEACT_SYM:
	case DTRACEACT_MOD:
	case DTRACEACT_USYM:
	case DTRACEACT_UMOD:
	case DTRACEACT_UADDR:
  {
		char buf[2048];
    char *tick, *plus;

		buf[0] = '\0';

		if (DTRACEACT_CLASS(rec->dtrd_action) == DTRACEACT_KERNEL) {
			uint64_t pc = ((uint64_t *)addr)[0];
			dtrace_addr2str(dtp->handle, pc, buf, sizeof (buf) - 1);
		} else {
			uint64_t pid = ((uint64_t *)addr)[0];
			uint64_t pc = ((uint64_t *)addr)[1];
			dtrace_uaddr2str(dtp->handle, pid, pc, buf, sizeof (buf) - 1);
		}

		if (rec->dtrd_action == DTRACEACT_MOD ||
		    rec->dtrd_action == DTRACEACT_UMOD) {
			/*
			 * If we're looking for the module name, we'll
			 * return everything to the left of the left-most
			 * tick -- or "<undefined>" if there is none.
			 */
			if ((tick = strchr(buf, '`')) == NULL)
				return (shim_string_new_copy(dtp->ctx, "<unknown>"));

			*tick = '\0';
		} else if (rec->dtrd_action == DTRACEACT_SYM ||
		    rec->dtrd_action == DTRACEACT_USYM) {
			/*
			 * If we're looking for the symbol name, we'll
			 * return everything to the left of the right-most
			 * plus sign (if there is one).
			 */
			if ((plus = strrchr(buf, '+')) != NULL)
				*plus = '\0';
		}

		return (shim_string_new_copy(dtp->ctx, buf));
    }
    break;
	}

	assert(B_FALSE);
	return (shim_number_new(ctx, -1));
}

int
strcompile(shim_ctx_t* ctx, shim_args_t *args)
{
  size_t argc = shim_args_length(args);

  shim_val_t* arg0 = shim_args_get(args, 0);
  shim_val_t* arg1 = shim_args_get(args, 1);

	dtrace_hdl_t *dtp = (dtrace_hdl_t*)shim_external_value(ctx, arg0);
	dtrace_prog_t *dp;
	dtrace_proginfo_t info;

	if (argc < 2) {
		shim_args_set_rval(ctx, args, _badarg(ctx, "expected program"));
  }

  char* program = shim_string_value(arg1);

	if ((dp = dtrace_program_strcompile(dtp, program,
	    DTRACE_PROBESPEC_NAME, 0, 0, NULL)) == NULL) {
		_error(ctx, "couldn't compile '%s': %s\n", program,
      dtrace_errmsg(dtp, dtrace_errno(dtp)));
    return FALSE;
	}

  free(program);

	if (dtrace_program_exec(dtp, dp, &info) == -1) {
		_error(ctx, "couldn't execute '%s': %s\n", program,
      dtrace_errmsg(dtp, dtrace_errno(dtp)));
    return FALSE;
	}

	return TRUE;
}

int
setopt(shim_ctx_t* ctx, shim_args_t *args)
{
  size_t argc = shim_args_length(args);

  shim_val_t* arg0 = shim_args_get(args, 0);
  shim_val_t* arg1 = shim_args_get(args, 1);
  shim_val_t* arg2 = shim_args_get(args, 2);

	dtrace_hdl_t *dtp = (dtrace_hdl_t*)shim_external_value(ctx, arg0);
	int rval;

	if (argc < 2) {
		shim_args_set_rval(ctx, args, _badarg(ctx, "expected an option to set"));
    return FALSE;
  }

  const char* option = shim_string_value(arg1);

	if (argc >= 3) {
    /*
		if (args[2]->IsArray())
			return (dtc->badarg("option value can't be an array"));

		if (args[2]->IsObject())
			return (dtc->badarg("option value can't be an object"));
    */

    const char* optval = shim_string_value(arg2);
		rval = dtrace_setopt(dtp, option, optval);
    free(optval);
	} else {
		rval = dtrace_setopt(dtp, option, NULL);
	}


	if (rval != 0) {
		_error(ctx, "couldn't set option '%s': %s\n", option,
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
    free(option);
    return FALSE;
	}

  free(option);
	return TRUE;
}

int
go(shim_ctx_t* ctx, shim_args_t *args)
{
  shim_val_t* arg = shim_args_get(args, 0);
	dtrace_hdl_t *dtp = (dtrace_hdl_t*)shim_external_value(ctx, arg);

	if (dtrace_go(dtp) == -1) {
		_error(ctx, "couldn't enable tracing: %s\n",
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
    return FALSE;
	}

	return TRUE;
}

int
stop(shim_ctx_t* ctx, shim_args_t *args)
{
  shim_val_t* arg = shim_args_get(args, 0);
	dtrace_hdl_t *dtp = (dtrace_hdl_t*)shim_external_value(ctx, arg);

	if (dtrace_stop(dtp) == -1) {
    _error(ctx, "couldn't disable tracing: %s\n",
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
    return FALSE;
	}

	return TRUE;
}

int
_consume(const dtrace_probedata_t *data,
    const dtrace_recdesc_t *rec, void *arg)
{
  agg_baton_t* dtc = (agg_baton_t*)arg;
  shim_ctx_t* ctx = dtc->ctx;
	dtrace_probedesc_t *pd = data->dtpda_pdesc;

	shim_val_t* probe = probedesc(ctx, data->dtpda_pdesc);

	if (rec == NULL) {
		shim_val_t* argv[1] = { probe };
    shim_val_t* rval = malloc(sizeof(shim_val_t*));
    shim_func_call_val(ctx, NULL, dtc->cb, 1, argv, rval);
    shim_value_release(rval);
		return (DTRACE_CONSUME_NEXT);
	}

	if (!_valid(rec)) {
		char errbuf[256];
	
		/*
		 * If this is a printf(), we'll defer to the bufhandler.
		 */
		if (rec->dtrd_action == DTRACEACT_PRINTF)
			return (DTRACE_CONSUME_THIS);

		_error(ctx, "unsupported action %s "
		    "in record for %s:%s:%s:%s\n",
		    _action(rec, errbuf, sizeof (errbuf)),
		    pd->dtpd_provider, pd->dtpd_mod,
		    pd->dtpd_func, pd->dtpd_name);	
		return (DTRACE_CONSUME_ABORT);
	}

  shim_val_t* record = shim_obj_new(ctx, NULL, NULL);
	shim_obj_set_prop_name(ctx, record, "data", _record(rec, data->dtpda_data, dtc, ctx));
	shim_val_t* argv[2] = { probe, record };
  shim_val_t* rval = malloc(sizeof(shim_val_t*));
  shim_func_call_val(ctx, NULL, dtc->cb, 2, argv, rval);
  shim_value_release(rval);

	return (DTRACE_CONSUME_THIS);
}

int
consume(shim_ctx_t* ctx, shim_args_t *args)
{
  shim_val_t* arg = shim_args_get(args, 0);
	dtrace_hdl_t *dtp = (dtrace_hdl_t*)shim_external_value(ctx, arg);
	dtrace_workstatus_t status;

  agg_baton_t baton;
  baton.ctx = ctx;
	baton.cb = shim_args_get(args, 1);
  baton.handle = dtp;

	status = dtrace_work(dtp, NULL, NULL, _consume, &baton);

	if (status == -1 || shim_exception_pending(ctx))
    return FALSE;

  return TRUE;
}

/*
 * Caching the quantized ranges improves performance substantially if the
 * aggregations have many disjoing keys.  Note that we only cache a single
 * aggregation variable; programs that have more than one aggregation variable
 * may see significant degradations in performance.  (If this is a common
 * case, this cache should clearly be expanded.)
 */
/* TODO
Local<Array> *
DTraceConsumer::ranges_cached(dtrace_aggvarid_t varid)
{
	if (varid == dtc_ranges_varid)
		return (dtc_ranges);

	return (NULL);
}

Local<Array> *
DTraceConsumer::ranges_cache(dtrace_aggvarid_t varid, Local<Array> *ranges)
{
	if (dtc_ranges != NULL)
		delete [] dtc_ranges;

	dtc_ranges = ranges;
	dtc_ranges_varid = varid;

	return (ranges);
}
*/

shim_val_t**
ranges_quantize(shim_ctx_t* ctx, dtrace_aggvarid_t varid)
{
	int64_t min, max;
	shim_val_t **ranges;
	int i;

/* TODO
	if ((ranges = ranges_cached(varid)) != NULL)
		return (ranges);
*/

	ranges = malloc(sizeof(shim_val_t*) *DTRACE_QUANTIZE_NBUCKETS);

	for (i = 0; i < DTRACE_QUANTIZE_NBUCKETS; i++) {
		ranges[i] = shim_array_new(ctx, 2);

		if (i < DTRACE_QUANTIZE_ZEROBUCKET) {
			/*
			 * If we're less than the zero bucket, our range
			 * extends from negative infinity through to the
			 * beginning of our zeroth bucket.
			 */
			min = i > 0 ? DTRACE_QUANTIZE_BUCKETVAL(i - 1) + 1 :
			    INT64_MIN;
			max = DTRACE_QUANTIZE_BUCKETVAL(i);
		} else if (i == DTRACE_QUANTIZE_ZEROBUCKET) {
			min = max = 0;
		} else {
			min = DTRACE_QUANTIZE_BUCKETVAL(i);
			max = i < DTRACE_QUANTIZE_NBUCKETS - 1 ?
			    DTRACE_QUANTIZE_BUCKETVAL(i + 1) - 1 :
			    INT64_MAX;
		}

		shim_array_set(ctx, ranges[i], 0, shim_number_new(ctx, min));
		shim_array_set(ctx, ranges[i], 1, shim_number_new(ctx, max));
	}

/* TODO
	return (ranges_cache(varid, ranges));
*/
  return ranges;
}

shim_val_t**
ranges_lquantize(shim_ctx_t* ctx, dtrace_aggvarid_t varid,
    const uint64_t arg)
{
	int64_t min, max;
	shim_val_t** ranges;
	int32_t base;
	uint16_t step, levels;
	int i;

/* TODO
	if ((ranges = ranges_cached(varid)) != NULL)
		return (ranges);
*/

	base = DTRACE_LQUANTIZE_BASE(arg);
	step = DTRACE_LQUANTIZE_STEP(arg);
	levels = DTRACE_LQUANTIZE_LEVELS(arg);

	ranges = malloc(sizeof(shim_val_t*) * (levels + 2));

	for (i = 0; i <= levels + 1; i++) {
		ranges[i] = shim_array_new(ctx, 2);

		min = i == 0 ? INT64_MIN : base + ((i - 1) * step);
		max = i > levels ? INT64_MAX : base + (i * step) - 1;

		shim_array_set(ctx, ranges[i], 0, shim_number_new(ctx, min));
		shim_array_set(ctx, ranges[i], 1, shim_number_new(ctx, max));
	}

/* TODO
	return (ranges_cache(varid, ranges));
*/
  return ranges;
}

shim_val_t**
ranges_llquantize(shim_ctx_t* ctx, dtrace_aggvarid_t varid,
    const uint64_t arg, int nbuckets)
{
	int64_t value = 1, next, step;
	shim_val_t** ranges;
	int bucket = 0, order;
	uint16_t factor, low, high, nsteps;

/* TODO
	if ((ranges = ranges_cached(varid)) != NULL)
		return (ranges);
*/

	factor = DTRACE_LLQUANTIZE_FACTOR(arg);
	low = DTRACE_LLQUANTIZE_LOW(arg);
	high = DTRACE_LLQUANTIZE_HIGH(arg);
	nsteps = DTRACE_LLQUANTIZE_NSTEP(arg);

	ranges = malloc(sizeof(shim_val_t*) * nbuckets);

	for (order = 0; order < low; order++)
		value *= factor;

	ranges[bucket] = shim_array_new(ctx, 2);
	shim_array_set(ctx, ranges[bucket], 0, shim_number_new(ctx, 0));
	shim_array_set(ctx, ranges[bucket], 1, shim_number_new(ctx, value - 1));
	bucket++;

	next = value * factor;
	step = next > nsteps ? next / nsteps : 1;

	while (order <= high) {
		ranges[bucket] = shim_array_new(ctx, 2);
		shim_array_set(ctx, ranges[bucket], 0, shim_number_new(ctx, value));
		shim_array_set(ctx, ranges[bucket], 1, shim_number_new(ctx, value + step - 1));
		bucket++;

		if ((value += step) != next)
			continue;

		next = value * factor;
		step = next > nsteps ? next / nsteps : 1;
		order++;
	}

	ranges[bucket] = shim_array_new(ctx, 2);
	shim_array_set(ctx, ranges[bucket], 0, shim_number_new(ctx, value));
	shim_array_set(ctx, ranges[bucket], 1, shim_number_new(ctx, INT64_MAX));

	assert(bucket + 1 == nbuckets);

/* TODO
	return (ranges_cache(varid, ranges));
*/
  return ranges;
}

int
_aggwalk(const dtrace_aggdata_t *agg, void *arg)
{
	agg_baton_t *dtc = (agg_baton_t *)arg;
	const dtrace_aggdesc_t *aggdesc = agg->dtada_desc;
	const dtrace_recdesc_t *aggrec;
  shim_ctx_t* ctx = dtc->ctx;
  shim_val_t* id, *val, *key;
	char errbuf[256];
	int i;

	/*
	 * We expect to have both a variable ID and an aggregation value here;
	 * if we have fewer than two records, something is deeply wrong.
	 */
  id = shim_number_new(ctx, aggdesc->dtagd_varid);
	assert(aggdesc->dtagd_nrecs >= 2);
  key = shim_array_new(dtc->ctx, aggdesc->dtagd_nrecs - 2);

	for (i = 1; i < aggdesc->dtagd_nrecs - 1; i++) {
		const dtrace_recdesc_t *rec = &aggdesc->dtagd_rec[i];
		caddr_t addr = agg->dtada_data + rec->dtrd_offset;

		if (!_valid(rec)) {
			_error(ctx, "unsupported action %s "
			    "as key #%d in aggregation \"%s\"\n",
			    _action(rec, errbuf, sizeof (errbuf)), i,
			    aggdesc->dtagd_name);
			return (DTRACE_AGGWALK_ERROR);
		}

		shim_array_set(dtc->ctx, key, i - 1, _record(rec, addr, dtc, ctx));
	}

	aggrec = &aggdesc->dtagd_rec[aggdesc->dtagd_nrecs - 1];

	switch (aggrec->dtrd_action) {
	case DTRACEAGG_COUNT:
	case DTRACEAGG_MIN:
	case DTRACEAGG_MAX:
	case DTRACEAGG_SUM: {
		caddr_t addr = agg->dtada_data + aggrec->dtrd_offset;

		assert(aggrec->dtrd_size == sizeof (uint64_t));
		val = shim_number_new(ctx, *((int64_t *)addr));
		break;
	}

	case DTRACEAGG_AVG: {
		const int64_t *data = (int64_t *)(agg->dtada_data +
		    aggrec->dtrd_offset);

		assert(aggrec->dtrd_size == sizeof (uint64_t) * 2);
		val = shim_number_new(ctx, data[1] / (double)data[0]);
		break;
	}

	case DTRACEAGG_QUANTIZE: {
		shim_val_t* quantize = shim_array_new(ctx, 0);
		const int64_t *data = (int64_t *)(agg->dtada_data +
		    aggrec->dtrd_offset);
		shim_val_t **ranges, *datum;
		int i, j = 0;

		ranges = ranges_quantize(ctx, aggdesc->dtagd_varid); 

		for (i = 0; i < DTRACE_QUANTIZE_NBUCKETS; i++) {
			if (!data[i])
				continue;

			datum = shim_array_new(ctx, 2);
			shim_array_set(ctx, datum, 0, ranges[i]);
			shim_array_set(ctx, datum, 1, shim_number_new(ctx, data[i]));

      shim_array_set(ctx, quantize, j++, datum);
		}

		val = quantize;
		break;
	}

	case DTRACEAGG_LQUANTIZE:
	case DTRACEAGG_LLQUANTIZE: {
		shim_val_t* lquantize = shim_array_new(ctx, 0);
		const int64_t *data = (int64_t *)(agg->dtada_data +
		    aggrec->dtrd_offset);
		shim_val_t **ranges, *datum;
		int i, j = 0;

		uint64_t arg = *data++;
		int levels = (aggrec->dtrd_size / sizeof (uint64_t)) - 1;

		ranges = (aggrec->dtrd_action == DTRACEAGG_LQUANTIZE ?
		    ranges_lquantize(ctx, aggdesc->dtagd_varid, arg) :
		    ranges_llquantize(ctx, aggdesc->dtagd_varid, arg, levels));

		for (i = 0; i < levels; i++) {
			if (!data[i])
				continue;

			datum = shim_array_new(ctx, 2);
			shim_array_set(ctx, datum, 0, ranges[i]);
			shim_array_set(ctx, datum, 1, shim_number_new(ctx, data[i]));

      shim_array_set(ctx, lquantize, j++, datum);
		}

		val = lquantize;
		break;
	}

	default:
		_error(ctx, "unsupported aggregating action "
		    " %s in aggregation \"%s\"\n", _action(aggrec, errbuf,
		    sizeof (errbuf)), aggdesc->dtagd_name);
		return (DTRACE_AGGWALK_ERROR);
	}

	shim_val_t* argv[3] = { id, key, val };
  shim_val_t* rval = malloc(sizeof(shim_val_t*));
  shim_func_call_val(ctx, NULL, dtc->cb, 3, argv, rval);
  shim_value_release(rval);

	return (DTRACE_AGGWALK_REMOVE);
}

int
aggwalk(shim_ctx_t* ctx, shim_args_t *args)
{
  shim_val_t* arg = shim_args_get(args, 0);
	dtrace_hdl_t *dtp = (dtrace_hdl_t*)shim_external_value(ctx, arg);
	int rval;

  agg_baton_t baton;
  baton.ctx = ctx;
  baton.cb = shim_args_get(args, 1);
  baton.handle = dtp;

	if (dtrace_status(dtp) == -1) {
		_error(ctx, "couldn't get status: %s\n",
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
    return FALSE;
	}

	if (dtrace_aggregate_snap(dtp) == -1) {
		_error(ctx, "couldn't snap aggregate: %s\n",
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
    return FALSE;
	}

	rval = dtrace_aggregate_walk(dtp, _aggwalk, &baton);

	/*
	 * Flush the ranges cache; the ranges will go out of scope when the
	 * destructor for our HandleScope is called, and we cannot be left
	 * holding references.
	 */
  /*
	dtc->ranges_cache(DTRACE_AGGVARIDNONE, NULL);
  */

	if (rval == -1) {
		if (shim_exception_pending(ctx))
			return FALSE;

		_error(ctx, "couldn't walk aggregate: %s\n",
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
    return FALSE;
	}

  return TRUE;
}

int
aggmin(shim_ctx_t* ctx, shim_args_t *args)
{
  shim_args_set_rval(ctx, args, shim_number_new(ctx, INT64_MIN));
  return TRUE;
}

int
aggmax(shim_ctx_t* ctx, shim_args_t *args)
{
  shim_args_set_rval(ctx, args, shim_number_new(ctx, INT64_MAX));
  return TRUE;
}

int
version(shim_ctx_t* ctx, shim_args_t *args)
{
  shim_args_set_rval(ctx, args, shim_string_new_copy(ctx, _dtrace_version));
	return TRUE;
}

int
Initialize(shim_ctx_t* ctx, shim_val_t* exports, shim_val_t* module)
{
  shim_fspec_t funcs[] = {
    SHIM_FS(Consumer),
    SHIM_FS(strcompile),
    SHIM_FS(setopt),
    SHIM_FS(go),
    SHIM_FS(consume),
    SHIM_FS(aggwalk),
    SHIM_FS(aggmin),
    SHIM_FS(aggmax),
    SHIM_FS(stop),
    SHIM_FS(version),
    SHIM_FS_END,
  };

  shim_obj_set_funcs(ctx, exports, funcs);
  return TRUE;
}

SHIM_MODULE(dtrace, Initialize);
