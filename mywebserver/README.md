# Unix_Net_Programming

题目：tcp课程的demo，实现迷你web服务器

环境：linux平台，c++语言，目前只支持Get方式

模型：主线程监听，线程池进行事务处理，one(event)loop per thread  + thread pool

资源目录：src-->源码；htdocs-->html,js,css等，web——conf配置默认首页和端口