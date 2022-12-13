#ifndef UNUSED_ARGUMENT_UTIL_H_
#define UNUSED_ARGUMENT_UTIL_H_

//the solution implemented here is taken from  https://jmmv.dev/2015/02/unused-parameters-in-c-and-c.html

#define UTILS_UNUSED __attribute__((unused))    //works for gcc, for othre compilers change this definition to a suitable one

#define UTILS_UNUSED_PARAM(name) unused_ ## name UTILS_UNUSED


#endif //UNUSED_ARGUMENT_UTIL_H_
