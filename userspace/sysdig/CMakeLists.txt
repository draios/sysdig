include_directories(${PROJECT_SOURCE_DIR}/common)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libscap)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsinsp)
include_directories(.)

add_executable(sysdig
	chisel.cpp
	jsoncpp.cpp
	sysdig.cpp)

target_link_libraries(sysdig
	sinsp) 

install(TARGETS sysdig 
	DESTINATION bin)

install(DIRECTORY chisels
	DESTINATION share/sysdig)
