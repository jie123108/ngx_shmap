//#line 2 "ngx_shmtest_mod.c"
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <math.h>
#include <openssl/md5.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "ngx_log_mod.h"
#include "ngx_shmap.h"

 
ngx_int_t  ngx_http_shmtest_init_process(ngx_cycle_t *cycle);

static char* ngx_http_shmtest_mod(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void* ngx_http_shmtest_create_main_conf(ngx_conf_t *cf);
static char* ngx_http_shmtest_init_main_conf(ngx_conf_t *cf, void *conf);

static void* ngx_http_shmtest_create_loc_conf(ngx_conf_t *cf);

static char* ngx_http_shmtest_merge_loc_conf(ngx_conf_t *cf,void *parent, void *child);

static void  ngx_http_shmtest_exit_master(ngx_cycle_t *cycle);
//static ngx_int_t RenameLogFile(const char* logfilename);

typedef struct {
	ngx_shm_zone_t* shmap;
	ngx_flag_t shm_open;
	size_t shm_size;
	ngx_str_t shm_name; 
}shmtest_main_conf_t;

typedef struct {
	ngx_flag_t enable;

	
} shmtest_loc_conf_t;

//static shmtest_loc_conf_t* g_loc_cfg = NULL;

static ngx_command_t  ngx_http_shmtest_commands[] = {
    { ngx_string("shmtest_mod"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_shmtest_mod,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },      
    { ngx_string("shm_size"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(shmtest_main_conf_t, shm_size),
      NULL },
      ngx_null_command
};
 
static ngx_http_module_t  ngx_http_shmtest_module_ctx = {
    NULL,                          /* preconfiguration */
    NULL,   				        /* postconfiguration */

    &ngx_http_shmtest_create_main_conf, /* create main configuration */
    &ngx_http_shmtest_init_main_conf,  /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_http_shmtest_create_loc_conf,  /* create location configuration */
    ngx_http_shmtest_merge_loc_conf /* merge location configuration */
};


ngx_module_t  ngx_http_shmtest_module = {
    NGX_MODULE_V1,
    &ngx_http_shmtest_module_ctx, /* module context */
    ngx_http_shmtest_commands,   /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    &ngx_http_shmtest_init_process,   /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,      /* exit process */
    ngx_http_shmtest_exit_master,      /* exit master */
    NGX_MODULE_V1_PADDING
};

ngx_int_t  ngx_http_shmtest_init_process(ngx_cycle_t *cycle)
{
	shmtest_main_conf_t* conf =  (shmtest_main_conf_t*)ngx_get_conf(cycle->conf_ctx, ngx_http_shmtest_module);
	if(conf == NULL){
		NLOG_INFO("conf is null!");
		return 0;
	}

	printf("process [%d] inited!\n", ngx_getpid());
	//多进程并发测试
	int i;
	int64_t ret=0;
	for(i=0;i<10000;i++){
		ngx_str_t key = ngx_string("test");
		ngx_shmap_inc_int(conf->shmap, &key, 1, 0, &ret);
	}
	printf("process [%d] init ok! ret=%lld\n", ngx_getpid(), (long long)ret);

	return 0;
}


ngx_chain_t* ngx_http_shmtest_resp(ngx_http_request_t *r, const char* output, int size){
	ngx_chain_t* chain = ngx_alloc_chain_link(r->pool);
	if(chain == NULL){
		NLOG_ERROR("Failed to allocate response chain");
		return NULL;
	}
	
    u_char* buf = (u_char*)ngx_pcalloc(r->pool, size);
	if(buf == NULL){
		NLOG_ERROR("Failed to allocate response buffer.");
        return NULL;
	}
	ngx_memcpy(buf, output, size);
	
    ngx_buf_t    *b;
    b = (ngx_buf_t*)ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
		NLOG_ERROR("Failed to allocate response buffer.");
        return NULL;
    }
    b->memory = 1;
    b->last_buf = 1;

    chain->buf = b;
    chain->next = NULL;
    b->pos = (u_char*)buf;
    b->last = (u_char*)(b->pos+size);

	return chain;

}

#define FUNC_ADD 1
#define FUNC_SET 2
#define FUNC_REPLACE 3

static char* funcs[5] = {
	NULL,
	"add",
	"set",
	"replace",
	NULL
};

static ngx_int_t ngx_http_shmtest_add_or_update(ngx_http_request_t *r,int func){
	ngx_int_t rc = NGX_HTTP_OK;
	ngx_str_t key = ngx_null_string;
	int32_t ikey = 0;
	ngx_str_t value = ngx_null_string;
 	char* szFunc = funcs[func];
	
	if(ngx_http_arg(r, (u_char*)"key", 3, &key)!=NGX_OK){
		NLOG_ERROR("get arg 'key' failed!");
		return NGX_HTTP_BAD_REQUEST;
	}

	if(ngx_http_arg(r, (u_char*)"value", 5, &value)!=NGX_OK){
		NLOG_ERROR("get arg 'value' failed!");
		return NGX_HTTP_BAD_REQUEST;
	}

	//如果key开始为0x 表示使用数字的KEY.
	if(key.len > 2 && key.data[0] == '0' &&	key.data[1] == 'x'){
		key.data += 2;
		key.len -= 2;
		ikey = ngx_hextoi(key.data, key.len);
		ngx_str_set_int32(&key, &ikey);
		NLOG_DEBUG("use int key ikey=%d", ikey);
	}
	
	uint64_t exptime = 0;
	ngx_str_t sexptime = ngx_null_string;
	if(ngx_http_arg(r, (u_char*)"exptime", 7, &sexptime)==NGX_OK){
		exptime = ngx_parse_time(&sexptime, 1);
	}

	if(ikey != 0){
		NLOG_DEBUG("%s(key=%d,value=%V,exptime=%d)", szFunc,ikey,&value,exptime);
	}else{
		NLOG_DEBUG("%s(key=%V,value=%V,exptime=%d)", szFunc,&key,&value,exptime);
	}
	shmtest_main_conf_t* smcf;
	smcf = ngx_http_get_module_main_conf(r, ngx_http_shmtest_module);
	if(smcf == NULL){
		NLOG_ERROR("get module ngx_http_shmtest_module's main conf failed!");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	ngx_shm_zone_t* zone = smcf->shmap;
	
	int ret = 0;
	switch(func){
	case FUNC_ADD:
		ret = ngx_shmap_add(zone, &key,&value,VT_STRING,exptime,0);
	break;
	case FUNC_SET:
		ret = ngx_shmap_set(zone, &key,&value,VT_STRING,exptime,0);
	break;
	case FUNC_REPLACE:
		ret = ngx_shmap_replace(zone, &key,&value,VT_STRING,exptime,0);
	break;
	default:
		NLOG_ERROR("un process type [%d]", func);
		return NGX_HTTP_BAD_REQUEST;
	}

	char* rsp = ngx_pcalloc(r->connection->pool, 256);
	int rsp_len = 0;
	if(ret == 0){
		rsp_len = sprintf(rsp, "%s success!\n", szFunc);
	}else{
		rsp_len = sprintf(rsp, "%s failed!\n", szFunc);
	}

	ngx_chain_t* chain = ngx_http_shmtest_resp(r, rsp, rsp_len);
	if(chain != NULL){
	    r->headers_out.content_length_n = rsp_len;
	}else{
		r->headers_out.content_length_n = 0;
	}

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        
    }else{
    	rc = ngx_http_output_filter(r, chain);
    }

	return rc;
}

static ngx_int_t ngx_http_shmtest_counter_inc_int(ngx_http_request_t *r)
{
	ngx_int_t rc = NGX_HTTP_OK;
	ngx_str_t key = ngx_null_string;
	ngx_str_t szn = ngx_null_string;
	ngx_int_t n = 1;
	int64_t cur = 0;
	
	if(ngx_http_arg(r, (u_char*)"key", 3, &key)!=NGX_OK){
		NLOG_ERROR("get arg 'key' failed!");
		return NGX_HTTP_BAD_REQUEST;
	}

	if(ngx_http_arg(r, (u_char*)"n", 1, &szn)==NGX_OK){
		n = ngx_atoi(szn.data, szn.len);
	}

	shmtest_main_conf_t* smcf;
	smcf = ngx_http_get_module_main_conf(r, ngx_http_shmtest_module);
	if(smcf == NULL){
		NLOG_ERROR("get module ngx_http_shmtest_module's main conf failed!");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	ngx_shm_zone_t* zone = smcf->shmap;
	u_char* rsp = ngx_pcalloc(r->connection->pool, 256);
	int rsp_len = 0;

	rc = ngx_shmap_inc_int(zone, &key, n,0, &cur);

	
	if(rc == 0){
		rsp_len = ngx_sprintf(rsp, "inc_int(key=%V,n=%l)=%l\n",
						&key,n, cur)-rsp;
	}else{
		rsp_len = ngx_sprintf(rsp, "inc_int(key=%V,n=%l) failed!\n", &key,n)-rsp;
	}

	ngx_chain_t* chain = ngx_http_shmtest_resp(r, (char*)rsp, rsp_len);
	if(chain != NULL){
	    r->headers_out.content_length_n = rsp_len;
	}else{
		r->headers_out.content_length_n = 0;
	}

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        
    }else{
    	rc = ngx_http_output_filter(r, chain);
    }

	return rc;	
}

static ngx_int_t ngx_http_shmtest_get(ngx_http_request_t *r){
	ngx_int_t rc = NGX_HTTP_OK;
	ngx_str_t key = ngx_null_string;
	ngx_str_t value = ngx_null_string;
	int32_t ikey = 0;
	uint8_t value_type = VT_BINARY;
	uint32_t exptime = 0;
	uint32_t user_flags = 0;
	
	if(ngx_http_arg(r, (u_char*)"key", 3, &key)!=NGX_OK){
		NLOG_ERROR("get arg 'key' failed!");
		return NGX_HTTP_BAD_REQUEST;
	}
	if(key.len > 2 && key.data[0] == '0' &&	key.data[1] == 'x'){
		key.data += 2;
		key.len -= 2;
		ikey = ngx_hextoi(key.data, key.len);
		ngx_str_set_int32(&key, &ikey);
		NLOG_DEBUG("use int key ikey=%d", ikey);
	} 

	shmtest_main_conf_t* smcf;
	smcf = ngx_http_get_module_main_conf(r, ngx_http_shmtest_module);
	if(smcf == NULL){
		NLOG_ERROR("get module ngx_http_shmtest_module's main conf failed!");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	ngx_shm_zone_t* zone = smcf->shmap;
	u_char* rsp = ngx_pcalloc(r->connection->pool, 256);
	int rsp_len = 0;

	rc = ngx_shmap_get(zone, &key, &value, &value_type,
				&exptime, &user_flags);

	if(ikey != 0){
		if(rc == 0){
			rsp_len = ngx_sprintf(rsp, "get(%d)={value=%V,exptime=%d,user_flags=%d}!\n",
							ikey,&value,exptime,user_flags)-rsp;
		}else{
			rsp_len = ngx_sprintf(rsp, "get(%d) failed!\n", ikey)-rsp;
		}
	}else{
		if(rc == 0){
			rsp_len = ngx_sprintf(rsp, "get(%V)={value=%V,exptime=%d,user_flags=%d}!\n",
							&key,&value,exptime,user_flags)-rsp;
		}else{
			rsp_len = ngx_sprintf(rsp, "get(%V) failed!\n", &key)-rsp;
		}
	}

	ngx_chain_t* chain = ngx_http_shmtest_resp(r, (char*)rsp, rsp_len);
	if(chain != NULL){
	    r->headers_out.content_length_n = rsp_len;
	}else{
		r->headers_out.content_length_n = 0;
	}

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        
    }else{
    	rc = ngx_http_output_filter(r, chain);
    }

	return rc;
}

static ngx_int_t ngx_http_shmtest_handler(ngx_http_request_t *r)
{
    //ngx_int_t     rc = NGX_DONE;

	//NLOG_DEBUG("### %.*s ###", r->request_line.len,r->request_line.data);

	if(r->uri.len == 2){
		char func = r->uri.data[1];
	    switch(func){
		case 'a': //add
			return ngx_http_shmtest_add_or_update(r, FUNC_ADD);
		case 's': //set
			return ngx_http_shmtest_add_or_update(r, FUNC_SET);
		case 'r': //replace
			return ngx_http_shmtest_add_or_update(r, FUNC_REPLACE);
		case 'd': //delete
			
		break;
		case 'g': //get
			return ngx_http_shmtest_get(r);
		case 'c': //counter
			return ngx_http_shmtest_counter_inc_int(r);
		default:
			NLOG_ERROR("Req [%.*s] Not Found! uri[%.*s]",
				r->request_line.len,r->request_line.data,
				r->uri.len,r->uri.data);
			return NGX_HTTP_NOT_FOUND;
	    }
		return NGX_HTTP_OK;
	}else{//未处理的请求。。
		NLOG_ERROR("Req [%.*s] Not Found! uri[%.*s]",
			r->request_line.len,r->request_line.data,
			r->uri.len,r->uri.data);
		return NGX_HTTP_NOT_FOUND;
	}
    return NGX_DONE;
}


static char * ngx_http_shmtest_mod(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;
    shmtest_loc_conf_t *vipcfg = (shmtest_loc_conf_t*)conf;

    clcf = (ngx_http_core_loc_conf_t*)ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_shmtest_handler;
	vipcfg->enable = 1;
	//CONF_INFO("######## shmtest enabled ############");
	return NGX_CONF_OK;
}

char* ngx_http_shmtest_init(ngx_conf_t *cf, shmtest_loc_conf_t *cscf)
{

	//CONF_INFO("nginx version [%s %s]", __DATE__, __TIME__);

	
   	return NGX_CONF_OK;
}

static void *
ngx_http_shmtest_create_loc_conf(ngx_conf_t *cf)
{
    shmtest_loc_conf_t  *conf;

    conf = (shmtest_loc_conf_t*)ngx_pcalloc(cf->pool, sizeof(shmtest_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
	conf->enable = NGX_CONF_UNSET;
		
    return conf;
}

static char *
ngx_http_shmtest_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    shmtest_loc_conf_t *prev = (shmtest_loc_conf_t*)parent;
    shmtest_loc_conf_t *conf = (shmtest_loc_conf_t*)child;

	ngx_conf_merge_value(conf->enable, prev->enable, 0);

	if(conf->enable){		
		return ngx_http_shmtest_init(cf, conf);
	}
   return NGX_CONF_OK;
}

static void* ngx_http_shmtest_create_main_conf(ngx_conf_t *cf)
{
	shmtest_main_conf_t* conf;
	conf = ngx_pcalloc(cf->pool, sizeof(shmtest_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }
	conf->shm_size = NGX_CONF_UNSET_SIZE;
	//conf->shm_name = test_shm_name;
	return conf;
}

static char* ngx_http_shmtest_init_main_conf(ngx_conf_t *cf, void *cnf)
{
    shmtest_main_conf_t *conf = (shmtest_main_conf_t*)cnf;
	if(conf->shm_size == NGX_CONF_UNSET_SIZE){
		conf->shm_size = 1024*1024*10; // default size:10m
	}
	if(conf->shm_name.len == 0){
		static ngx_str_t test_shm_name = ngx_string("shm_test_zone");
		conf->shm_name = test_shm_name;
	}
 	cf->cycle->conf_ctx[ngx_http_shmtest_module.index] = (void***)conf;

	printf("############ shmtest init ###########\n");
	printf("sizeof(ngx_shmap_node_t)=%d\n"
			"offsetof expires:%d\n"
			"offsetof value_len:%d\n"
			"offsetof user_flags:%d\n"
			"offsetof key_len:%d\n"
			"offsetof value_type:%d\n"
			"offsetof data:%d\n"
			,(int)sizeof(ngx_shmap_node_t),
				(int)offsetof(ngx_shmap_node_t,expires),
				(int)offsetof(ngx_shmap_node_t,value_len),
				(int)offsetof(ngx_shmap_node_t,user_flags),
				(int)offsetof(ngx_shmap_node_t,key_len),
				(int)offsetof(ngx_shmap_node_t,value_type),
				(int)offsetof(ngx_shmap_node_t,data)
				);  
	
	ngx_shm_zone_t* zone = ngx_shmap_init(cf, 
				&conf->shm_name, conf->shm_size,
				&ngx_http_shmtest_module);
	if(zone == NULL){
		u_char buf[256];
		ngx_sprintf(buf, "ngx_shmap_init(%V,%z) failed!\n",
			&conf->shm_name, conf->shm_size);
		printf((char*)buf);
		return NGX_CONF_ERROR;
	}
	conf->shmap = zone;
	printf("### ngx_http_shmtest_init_main_conf ###\n");
	return NGX_CONF_OK;
}

static void  ngx_http_shmtest_exit_master(ngx_cycle_t *cycle)
{
	NLOG_INFO("nginx master exit....");

	return ;
}

