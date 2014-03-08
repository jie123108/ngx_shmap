ngx_shmap nginx 共享字典模块。
===================================  
  nginx共享字典模块。当需要在多个进程间共享数据时，可以使用。(比如一个计数数，或者用作内存缓存)
 	该模块实际上是从ngx_lua中的ngx_http_lua_shdict模块移植而来。在此感谢原作者(@agentzh)为我们提供如此优秀的开源项目。

项目依赖项
-----------------------------------  
	ngx_log_mod 日志输出模块。由于nginx默认日志输出总是需要请求上下文，这里直接使用了自己写的一个模块。
	主页地址为：https://github.com/jie123108/ngx_log_mod

项目编译
----------------------------------- 
	cd nginx-1.x.x
	./configure --add-module=/u/GitHub/ngx_log_mod \
		--add-module=/path/to/ngx_shmap \
		--add-module=/path/to/ngx_shmap/testmod
	
	#其中第二行是ngx_shmap模块，后面是你自己的模块。上面示例中给出的是测试模块，代码在ngx_shmap目录下。
	
	make
	make install

函数说明(使用示例可参考testmod中的shmtest_mod.c)
-----------------------------------

初始化
=====
```
函数声明：
	ngx_shm_zone_t* ngx_shmap_init(ngx_conf_t *cf, ngx_str_t* name, size_t size, void* module)

```

获取值：
=====
```
/**
 * zone 共享字典对象
 * key 为字典的key.
 * data 为取得的数据(取得的数据是直接指向共享内存区的，
 *          所以如果你修改了该数据，共享内存中的数据也会被修改)
 * value_type 为数据的类型
 * exptime 为还有多久过期(秒)
 * user_flags 返回设置的user_flags值
 **/
int ngx_shmap_get(ngx_shm_zone_t* zone, ngx_str_t* key, 
		ngx_str_t* data, uint8_t* value_type,uint32_t* exptime,uint32_t* user_flags);
		
/**
 * 与ngx_shmap_get相同，取得一个key的值。
 * 与ngx_shmap_get不同之处在于user_flags返回的是设置的
 *    user_flags的指针，可以在获取后对user_flags进行修改。
 **/
int ngx_shmap_get_ex(ngx_shm_zone_t* zone, ngx_str_t* key, 
		ngx_str_t* data, uint8_t* value_type,uint32_t* exptime,uint32_t** user_flags);

//获取int32类型的值，对上面的函数的简单的包装。	
int ngx_shmap_get_int32(ngx_shm_zone_t* zone, ngx_str_t* key, int32_t* i);
//获取int64类型的值，对上面的函数的简单的包装。	
int ngx_shmap_get_int64(ngx_shm_zone_t* zone, ngx_str_t* key, int64_t* i);
//获取int64类型的值，并对值进行清0.
int ngx_shmap_get_int64_and_clear(ngx_shm_zone_t* zone, ngx_str_t* key, int64_t* i);

```

删除key
=====
```
int ngx_shmap_delete(ngx_shm_zone_t* zone, ngx_str_t* key);
```

循环处理整个共享字典
====
```
typedef void (*foreach_pt)(ngx_shmap_node_t* node, void* extarg);
#func为处理回调函数
int ngx_shmap_foreach(ngx_shm_zone_t* zone, foreach_pt func, void* args);

```

清理，删除所有
=====
```
//清空整个字典
int ngx_shmap_flush_all(ngx_shm_zone_t* zone);
//清空过期的key
int ngx_shmap_flush_expired(ngx_shm_zone_t* zone, int attempts);
```

添加，替换，设置值
=====
```
//添加一个key,value, 如果存在会报错(空间不够时，会删除最早过期的数据)
int ngx_shmap_add(ngx_shm_zone_t* zone, ngx_str_t* key, ngx_str_t* value, 
									uint8_t value_type, uint32_t exptime, uint32_t user_flags);
//添加一个key,value, 如果存在会报错(空间不够时，会返回失败)
int ngx_shmap_safe_add(ngx_shm_zone_t* zone, ngx_str_t* key, ngx_str_t* value, 
									uint8_t value_type, uint32_t exptime, uint32_t user_flags);
//替换一个key,value
int ngx_shmap_replace(ngx_shm_zone_t* zone, ngx_str_t* key, ngx_str_t* value, 
									uint8_t value_type, uint32_t exptime, uint32_t user_flags);
//设置一个key,value.
int ngx_shmap_set(ngx_shm_zone_t* zone, ngx_str_t* key, ngx_str_t* value, 
									uint8_t value_type, uint32_t exptime, uint32_t user_flags);

//给key增加i,并返回增加后的值。
int ngx_shmap_inc_int(ngx_shm_zone_t* zone, ngx_str_t* key,int64_t i,
															uint32_t exptime, int64_t* ret);
//给key增加d,并返回增加后的值。
int ngx_shmap_inc_double(ngx_shm_zone_t* zone, ngx_str_t* key,double d,
															uint32_t exptime,double* ret);
```

